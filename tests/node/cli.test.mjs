import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  ROOT_DIR,
  STATUS,
  statusToExitCode,
  evaluatePhpVersion,
  evaluateNodeVersion,
  evaluateProductVersion,
  auditConfigContent,
  scanIndicatorsInText,
  scanBrotliExposureInProject,
  scanProjectFiles,
  verifyDatabase,
  generateUpgradePlan,
  getProductEffectiveRules,
  diffAuditReports,
  applyConfig,
  renderMarkdown,
  renderSarif,
  renderJunit,
  renderCsv
} from '../../bin/php2shell-guard.mjs';

test('PHP version boundary comparisons (Section 11 of plan.md)', () => {
  // 8.2 boundary
  assert.equal(evaluatePhpVersion('8.2.34').status, STATUS.VULNERABLE_PATCH_AVAILABLE);
  assert.equal(evaluatePhpVersion('8.2.35').status, STATUS.PATCHED);

  // 8.3 boundary
  assert.equal(evaluatePhpVersion('8.3.35').status, STATUS.VULNERABLE_PATCH_AVAILABLE);
  assert.equal(evaluatePhpVersion('8.3.36').status, STATUS.PATCHED);

  // 8.4 boundary
  assert.equal(evaluatePhpVersion('8.4.26').status, STATUS.VULNERABLE_PATCH_AVAILABLE);
  assert.equal(evaluatePhpVersion('8.4.27').status, STATUS.PATCHED);

  // 8.5 boundary
  assert.equal(evaluatePhpVersion('8.5.11').status, STATUS.VULNERABLE_PATCH_AVAILABLE);
  assert.equal(evaluatePhpVersion('8.5.12').status, STATUS.PATCHED);

  // Pre-release strings must not be treated as patched
  assert.equal(evaluatePhpVersion('8.3.36-dev').status, STATUS.VULNERABLE_PATCH_AVAILABLE);
  assert.equal(evaluatePhpVersion('8.3.36RC1').status, STATUS.VULNERABLE_PATCH_AVAILABLE);

  // EOL branches (7.4, 8.0, 8.1 have upstream source backports noted)
  const eol81 = evaluatePhpVersion('8.1.29');
  assert.equal(eol81.status, STATUS.EOL_NO_OFFICIAL_RELEASE);
  assert.match(eol81.notes, /source backports/);

  const eol56 = evaluatePhpVersion('5.6.40');
  assert.equal(eol56.status, STATUS.EOL_NO_OFFICIAL_RELEASE);
  assert.match(eol56.notes, /5\.4\.0/);

  // Distro suffixes
  assert.equal(evaluatePhpVersion('8.1.2-1ubuntu2.14').status, STATUS.UNKNOWN_BACKPORT_POSSIBLE);
  assert.equal(evaluatePhpVersion('8.2.26-1+deb12u1').status, STATUS.UNKNOWN_BACKPORT_POSSIBLE);
  assert.equal(evaluatePhpVersion('8.3.35-r0').status, STATUS.UNKNOWN_BACKPORT_POSSIBLE);

  // Distro changelog verified backport
  assert.equal(evaluatePhpVersion('8.2.26-1~deb12u2', { changelogPatched: true }).status, STATUS.PATCHED_BACKPORT);

  // Stale worker detection (A13)
  assert.equal(evaluatePhpVersion('8.3.36', { staleWorker: true }).status, STATUS.PATCHED_NOT_RESTARTED);
  assert.equal(statusToExitCode(STATUS.PATCHED_NOT_RESTARTED), 1);
});

test('Node.js version boundary comparisons (October 2026 release)', () => {
  assert.equal(evaluateNodeVersion('22.23.3').status, STATUS.VULNERABLE_PATCH_AVAILABLE);
  assert.equal(evaluateNodeVersion('22.23.4').status, STATUS.PATCHED);
  assert.equal(evaluateNodeVersion('24.22.0').status, STATUS.VULNERABLE_PATCH_AVAILABLE);
  assert.equal(evaluateNodeVersion('24.22.1').status, STATUS.PATCHED);
  assert.equal(evaluateNodeVersion('26.12.0').status, STATUS.VULNERABLE_PATCH_AVAILABLE);
  assert.equal(evaluateNodeVersion('26.12.1').status, STATUS.PATCHED);

  // EOL Node lines: 18, 20, 23, 25
  for (const v of ['18.20.4', '20.18.0', '23.9.0', '25.2.0']) {
    assert.equal(evaluateNodeVersion(v).status, STATUS.EOL_NO_OFFICIAL_RELEASE);
    assert.equal(statusToExitCode(evaluateNodeVersion(v).status), 2);
  }
});

test('Configuration audit checks M2, M3, M4, M5, M6, M7', () => {
  const vulnIni = fs.readFileSync(path.join(ROOT_DIR, 'tests/fixtures/php-vulnerable.ini'), 'utf8');
  const mitIni = fs.readFileSync(path.join(ROOT_DIR, 'tests/fixtures/php-mitigated.ini'), 'utf8');

  const vulnIssues = auditConfigContent(vulnIni, 'php-ini', '8.5');
  assert.equal(vulnIssues.length, 3);
  assert.ok(vulnIssues.some(i => i.id === 'B1_MEMORY_LIMIT'));
  assert.ok(vulnIssues.some(i => i.id === 'B1_UPLOAD_PROGRESS'));
  assert.ok(vulnIssues.some(i => i.id === 'B13_FATAL_BACKTRACES'));

  const mitIssues = auditConfigContent(mitIni, 'php-ini', '8.5');
  assert.equal(mitIssues.length, 0);

  // Nginx PHP_VALUE override check (B11)
  const nginxConf = fs.readFileSync(path.join(ROOT_DIR, 'tests/fixtures/nginx-vulnerable.conf'), 'utf8');
  const nginxIssues = auditConfigContent(nginxConf, 'nginx');
  assert.ok(nginxIssues.some(i => i.id === 'B11_NGINX_FASTCGI_PHP_VALUE'));

  // Systemd RLIMIT_AS check (B9)
  const systemdIssues = auditConfigContent('[Service]\nLimitAS=536870912\n', 'systemd');
  assert.equal(systemdIssues.length, 1);
  assert.equal(systemdIssues[0].id, 'B9_RLIMIT_AS_DATA');
});

test('Indicator checks IOC1, IOC2, IOC4, and IOC7 wording rule (never says clean or safe)', () => {
  const phpLog = fs.readFileSync(path.join(ROOT_DIR, 'tests/fixtures/php-error.log'), 'utf8');
  const apacheLog = fs.readFileSync(path.join(ROOT_DIR, 'tests/fixtures/apache-error.log'), 'utf8');
  const psTxt = fs.readFileSync(path.join(ROOT_DIR, 'tests/fixtures/ps-output.txt'), 'utf8');

  const r1 = scanIndicatorsInText(phpLog, 'php-error-log');
  assert.equal(r1.indicators_found, true);
  assert.equal(r1.hits[0].id, 'IOC1_UNKNOWN_LINE_0_OOM');

  const r2 = scanIndicatorsInText(apacheLog, 'apache-error-log');
  assert.equal(r2.indicators_found, true);
  assert.equal(r2.hits[0].id, 'IOC2_APACHE_SEGFAULT_AH00052');

  const r3 = scanIndicatorsInText(psTxt, 'ps');
  assert.equal(r3.indicators_found, true);
  assert.equal(r3.hits[0].id, 'IOC4_WORKER_CHILD_SHELL');

  const emptyRes = scanIndicatorsInText('Normal log line\n', 'php-error-log');
  assert.equal(emptyRes.indicators_found, false);
  assert.equal(emptyRes.status, 'no indicator found in the logs available (rotation and retention limits apply)');
  assert.ok(!/clean|safe|not compromised/i.test(emptyRes.status));
});

test('Project, Brotli exposure, and Upgrade Planner checks', () => {
  const fixturesDir = path.join(ROOT_DIR, 'tests/fixtures');
  const brotliHints = scanBrotliExposureInProject(fixturesDir);
  assert.ok(brotliHints.length >= 3);

  const projFindings = scanProjectFiles(fixturesDir);
  assert.ok(projFindings.some(f => f.file === 'Dockerfile.vulnerable' && f.digest_pinned === true));

  const upgradePlan = generateUpgradePlan(fixturesDir, '8.3');
  assert.equal(upgradePlan.recommended_release, '8.3.36');
  assert.ok(upgradePlan.blockers.some(b => b.package === 'laravel/framework'));
});

test('Advisory database schema, two-source rule, and freshness verification', () => {
  const res = verifyDatabase(ROOT_DIR);
  assert.equal(res.valid, true, `DB verification errors: ${res.errors.join(', ')}`);
});

test('Dynamic multi-vulnerability advisory engine detection (Section K5)', () => {
  const phpRules = getProductEffectiveRules('php', ROOT_DIR);
  assert.equal(phpRules.product, 'php');
  assert.ok(phpRules.cves.includes('CVE-2026-109618'));
  assert.ok(phpRules.cves.includes('CVE-2026-109619'));
  assert.equal(phpRules.branches['8.3'].fixed, '8.3.36');
  assert.equal(phpRules.branches['8.4'].fixed, '8.4.27');

  const nodeRules = getProductEffectiveRules('nodejs', ROOT_DIR);
  assert.equal(nodeRules.product, 'nodejs');
  assert.ok(nodeRules.cves.includes('CVE-2026-111497'));
  assert.equal(nodeRules.branches['22'].fixed, '22.23.4');
});

test('Report formatters: Markdown, SARIF, JUnit, CSV (Section 10)', () => {
  const samplePayload = {
    tool: 'php2shell-guard',
    version: '0.3.0',
    advisory_db_date: '2026-10-23',
    host: 'web-prod-01',
    runtimes: [
      {
        component: 'php-fpm',
        detected_version: '8.3.35',
        status: STATUS.VULNERABLE_PATCH_AVAILABLE,
        fixed_version: '8.3.36',
        notes: 'Vulnerable to CVE-2026-109618'
      },
      {
        component: 'nodejs',
        detected_version: '22.23.4',
        status: STATUS.PATCHED,
        fixed_version: '22.23.4',
        notes: 'Brotli patched'
      }
    ],
    indicators: {
      status: 'no indicator found in the logs available (rotation and retention limits apply)'
    }
  };

  // Markdown
  const md = renderMarkdown(samplePayload, { brandName: 'AcmeSec', brandContact: 'sec@acme.com' });
  assert.match(md, /# AcmeSec Security Audit Report/);
  assert.match(md, /\*\*Audited By:\*\* sec@acme\.com/);
  assert.match(md, /VULNERABLE_PATCH_AVAILABLE/);

  // SARIF
  const sarifStr = renderSarif(samplePayload);
  const sarif = JSON.parse(sarifStr);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].results[0].ruleId, 'PHP2SHELL-109618');

  // JUnit
  const junit = renderJunit(samplePayload);
  assert.match(junit, /<testsuites name="php2shell-guard"/);
  assert.match(junit, /<failure message=/);

  // CSV
  const csv = renderCsv(samplePayload);
  assert.match(csv, /"web-prod-01","php-fpm","8.3.35","VULNERABLE_PATCH_AVAILABLE"/);
});

test('Diff engine: calculates remediated, persistent, regressions (Section G12)', () => {
  const before = {
    runtimes: [
      { component: 'php-fpm', detected_version: '8.3.35', status: STATUS.VULNERABLE_PATCH_AVAILABLE },
      { component: 'nodejs', detected_version: '22.23.3', status: STATUS.VULNERABLE_PATCH_AVAILABLE }
    ]
  };
  const after = {
    runtimes: [
      { component: 'php-fpm', detected_version: '8.3.36', status: STATUS.PATCHED },
      { component: 'nodejs', detected_version: '22.23.3', status: STATUS.VULNERABLE_PATCH_AVAILABLE }
    ]
  };

  const diff = diffAuditReports(before, after);
  assert.equal(diff.summary.remediated_count, 1);
  assert.equal(diff.summary.persistent_count, 1);
  assert.equal(diff.summary.status, 'REMEDIATION_INCOMPLETE');
  assert.equal(diff.remediated[0].component, 'php-fpm');
  assert.equal(diff.persistent[0].component, 'nodejs');
});

test('Apply engine: dry-run, backup, syntax validation, and automatic rollback on failure (Section F7)', () => {
  const tmpDir = path.join(ROOT_DIR, 'tmp_apply_node_test');
  const backupDir = path.join(tmpDir, 'backups');
  const testDest = path.join(tmpDir, 'nginx-test.conf');

  if (fs.existsSync(tmpDir)) fs.rmSync(tmpDir, { recursive: true, force: true });
  fs.mkdirSync(tmpDir, { recursive: true });

  try {
    // 1. Dry run
    const dryRes = applyConfig('nginx', {
      rootDir: ROOT_DIR,
      backupRoot: backupDir,
      destinationPath: testDest,
      dryRun: true
    });
    assert.equal(dryRes.dry_run, true);
    assert.equal(dryRes.applied, false);
    assert.equal(fs.existsSync(testDest), false);

    // 2. Real apply with valid custom validator
    fs.writeFileSync(testDest, '# original config\n');
    const validValidator = process.platform === 'win32' ? 'cmd /c exit 0' : 'true';
    const applyRes = applyConfig('nginx', {
      rootDir: ROOT_DIR,
      backupRoot: backupDir,
      destinationPath: testDest,
      dryRun: false,
      customValidator: validValidator
    });
    assert.equal(applyRes.applied, true);
    assert.equal(applyRes.rolled_back, false);
    assert.ok(fs.existsSync(applyRes.backup_file));
    assert.equal(fs.readFileSync(applyRes.backup_file, 'utf8'), '# original config\n');
    assert.match(fs.readFileSync(testDest, 'utf8'), /client_max_body_size/);

    // 3. Apply with failing custom validator -> Automatic Rollback
    const invalidValidator = process.platform === 'win32' ? 'cmd /c exit 1' : 'false';
    const failRes = applyConfig('nginx', {
      rootDir: ROOT_DIR,
      backupRoot: backupDir,
      destinationPath: testDest,
      dryRun: false,
      customValidator: invalidValidator
    });
    assert.equal(failRes.applied, false);
    assert.equal(failRes.rolled_back, true);
    // Verified original content was restored by rollback
    assert.match(failRes.error, /validation failed/);
  } finally {
    if (fs.existsSync(tmpDir)) fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Future-proofing: dynamic detection of new runtime vulnerabilities and future branch advisories', () => {
  const tmpRoot = path.join(ROOT_DIR, 'tmp_dynamic_adv_test');
  const advDir = path.join(tmpRoot, 'data', 'advisories');
  if (fs.existsSync(tmpRoot)) fs.rmSync(tmpRoot, { recursive: true, force: true });
  fs.mkdirSync(advDir, { recursive: true });

  try {
    // 1. Simulate a newly discovered future advisory for Bun (product: "bun", CVE-2027-99999, fixed: "1.4.5")
    const bunAdvisory = {
      id: 'bun-2027-01',
      title: 'Bun Engine Security Advisory',
      product: 'bun',
      cves: ['CVE-2027-99999'],
      severity: { cvss_v4: 8.8, label: 'high' },
      published: '2027-01-15',
      branches: [
        { branch: '1.4', fixed: '1.4.5', eol: false }
      ],
      mitigations: [{ id: 'M1', title: 'Upgrade Bun', confidence: 'official' }],
      sources: ['https://bun.sh/blog', 'https://github.com/oven-sh/bun/security'],
      exploitation: 'unknown',
      last_verified: '2026-10-23'
    };
    fs.writeFileSync(path.join(advDir, 'bun-2027-01.json'), JSON.stringify(bunAdvisory, null, 2));

    // 2. Simulate a future PHP branch 8.6 (fixed: "8.6.2", eol: false)
    const phpFutureAdvisory = {
      id: 'php-2027-02',
      title: 'PHP 8.6 Security Advisory',
      product: 'php',
      cves: ['CVE-2027-88888'],
      severity: { cvss_v4: 9.0, label: 'critical' },
      published: '2027-02-01',
      branches: [
        { branch: '8.6', fixed: '8.6.2', eol: false }
      ],
      mitigations: [{ id: 'M1', title: 'Upgrade to 8.6.2', confidence: 'official' }],
      sources: ['https://www.php.net', 'https://github.com/php/php-src'],
      exploitation: 'unknown',
      last_verified: '2026-10-23'
    };
    fs.writeFileSync(path.join(advDir, 'php-2027-02.json'), JSON.stringify(phpFutureAdvisory, null, 2));

    // Test dynamic Bun evaluation: 1.4.3 (< 1.4.5) is VULNERABLE, 1.4.5 is PATCHED
    const bunVuln = evaluateProductVersion('bun', '1.4.3', { rootDir: tmpRoot });
    assert.equal(bunVuln.status, STATUS.VULNERABLE_PATCH_AVAILABLE);
    assert.equal(bunVuln.fixed, '1.4.5');

    const bunPatched = evaluateProductVersion('bun', '1.4.5', { rootDir: tmpRoot });
    assert.equal(bunPatched.status, STATUS.PATCHED);
    assert.equal(bunPatched.fixed, '1.4.5');

    // Test dynamic PHP 8.6 evaluation: 8.6.1 is VULNERABLE, 8.6.2 is PATCHED
    const phpVuln = evaluateProductVersion('php', '8.6.1', { rootDir: tmpRoot });
    assert.equal(phpVuln.status, STATUS.VULNERABLE_PATCH_AVAILABLE);
    assert.equal(phpVuln.fixed, '8.6.2');

    const phpPatched = evaluateProductVersion('php', '8.6.2', { rootDir: tmpRoot });
    assert.equal(phpPatched.status, STATUS.PATCHED);
    assert.equal(phpPatched.fixed, '8.6.2');

    // Test verification passes on new product schema
    const dbRes = verifyDatabase(tmpRoot);
    assert.equal(dbRes.valid, true, `Errors: ${dbRes.errors.join(', ')}`);
  } finally {
    if (fs.existsSync(tmpRoot)) fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});


