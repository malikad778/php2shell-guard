#!/usr/bin/env node
/*
 * php2shell-guard Node.js CLI & Audit Engine (bin/php2shell-guard.mjs)
 * Zero external dependencies. Supports Node 18+.
 * Read-only by default. Never outputs "safe", "clean", or "not compromised".
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const ROOT_DIR = path.resolve(__dirname, '..');
export const DB_DATE = '2026-10-23';
export const TOOL_VERSION = '0.3.0';

export const STATUS = {
  PATCHED: 'PATCHED',
  PATCHED_BACKPORT: 'PATCHED_BACKPORT',
  PATCHED_NOT_RESTARTED: 'PATCHED_NOT_RESTARTED',
  NOT_DETECTED: 'NOT_DETECTED',
  VULNERABLE_PATCH_AVAILABLE: 'VULNERABLE_PATCH_AVAILABLE',
  EOL_NO_OFFICIAL_RELEASE: 'EOL_NO_OFFICIAL_RELEASE',
  UNKNOWN_BACKPORT_POSSIBLE: 'UNKNOWN_BACKPORT_POSSIBLE',
  UNKNOWN: 'UNKNOWN'
};

export function statusToExitCode(status) {
  switch (status) {
    case STATUS.PATCHED:
    case STATUS.PATCHED_BACKPORT:
    case STATUS.NOT_DETECTED:
      return 0;
    case STATUS.VULNERABLE_PATCH_AVAILABLE:
    case STATUS.PATCHED_NOT_RESTARTED:
      return 1;
    case STATUS.EOL_NO_OFFICIAL_RELEASE:
      return 2;
    case STATUS.UNKNOWN_BACKPORT_POSSIBLE:
    case STATUS.UNKNOWN:
      return 3;
    default:
      return 4;
  }
}

export function extractSemver(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const match = raw.match(/([0-9]+)\.([0-9]+)\.([0-9]+)/);
  if (!match) return null;
  return {
    semver: `${match[1]}.${match[2]}.${match[3]}`,
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    branch: `${match[1]}.${match[2]}`
  };
}

export function compareSemver(a, b) {
  const pa = extractSemver(a);
  const pb = extractSemver(b);
  if (!pa || !pb) return 0;
  if (pa.major !== pb.major) return pa.major > pb.major ? 1 : -1;
  if (pa.minor !== pb.minor) return pa.minor > pb.minor ? 1 : -1;
  if (pa.patch !== pb.patch) return pa.patch > pb.patch ? 1 : -1;
  return 0;
}

export function isDistroVersionString(raw) {
  if (!raw || typeof raw !== 'string') return false;
  if (/(ondrej|sury|remi)/i.test(raw)) return false;
  return /(ubuntu|deb|el[0-9]|amzn|alpine|-r[0-9]+)/i.test(raw);
}

export function loadDynamicAdvisories(rootDir = ROOT_DIR) {
  const advDir = path.join(rootDir, 'data', 'advisories');
  if (!fs.existsSync(advDir)) return [];
  const files = fs.readdirSync(advDir).filter(f => f.endsWith('.json'));
  return files.map(f => {
    try {
      return JSON.parse(fs.readFileSync(path.join(advDir, f), 'utf8'));
    } catch (_) {
      return null;
    }
  }).filter(Boolean);
}

export function getProductEffectiveRules(product, rootDir = ROOT_DIR) {
  const advisories = loadDynamicAdvisories(rootDir).filter(a => a.product?.toLowerCase() === product.toLowerCase());
  const branches = {};
  const cves = [];
  for (const adv of advisories) {
    if (Array.isArray(adv.cves)) cves.push(...adv.cves);
    for (const b of (adv.branches || [])) {
      const br = String(b.branch);
      if (!branches[br]) branches[br] = { branch: br, fixed: null, eol: false };
      if (b.fixed) {
        if (!branches[br].fixed || compareSemver(b.fixed, branches[br].fixed) > 0) {
          branches[br].fixed = b.fixed;
        }
      }
      if (b.eol) branches[br].eol = true;
    }
  }
  return { product, cves: Array.from(new Set(cves)), branches };
}

export function evaluateProductVersion(product, rawVersion, options = {}) {
  const { staleWorker = false, changelogPatched = false, rootDir = ROOT_DIR } = options;
  const parsed = extractSemver(rawVersion);
  if (!parsed) {
    return {
      status: STATUS.UNKNOWN,
      fixed: 'unknown',
      branch: 'unknown',
      notes: `Could not parse ${product} version string`
    };
  }

  const dynamicRules = getProductEffectiveRules(product, rootDir);
  const branchKey = product.toLowerCase() === 'nodejs' ? String(parsed.major) : parsed.branch;
  const branchInfo = dynamicRules.branches[branchKey];
  const cveStr = dynamicRules.cves.length > 0 ? dynamicRules.cves.join(', ') : 'advisories';

  if (changelogPatched) {
    return {
      status: staleWorker ? STATUS.PATCHED_NOT_RESTARTED : STATUS.PATCHED_BACKPORT,
      fixed: 'distro-backport',
      branch: branchKey,
      notes: staleWorker
        ? `Distro changelog confirms CVE fix, but running worker process still uses old binary`
        : `Distro changelog confirms backported fixes for ${cveStr}`
    };
  }

  if (branchInfo) {
    if (branchInfo.eol) {
      if (isDistroVersionString(rawVersion)) {
        return {
          status: STATUS.UNKNOWN_BACKPORT_POSSIBLE,
          fixed: 'vendor-backport',
          branch: branchKey,
          notes: `EOL branch ${branchKey} on distro package; inspect package changelog for ${cveStr}`
        };
      }
      return {
        status: STATUS.EOL_NO_OFFICIAL_RELEASE,
        fixed: 'none (upgrade to 8.3.36 or 8.4.27)',
        branch: branchKey,
        notes: branchInfo.has_source_backport || ['7.4', '8.0', '8.1'].includes(branchKey)
          ? `No official php.net release for ${branchKey}; PHP published minimal source backports for vendor packaging`
          : `End-of-life PHP branch ${branchKey} with no official release (earliest affected path dates to PHP 5.4.0)`
      };
    }

    if (branchInfo.fixed) {
      const isPrerelease = /(-dev|alpha|beta|rc)/i.test(String(rawVersion));
      if (compareSemver(parsed.semver, branchInfo.fixed) >= 0 && !isPrerelease) {
        if (staleWorker) {
          return {
            status: STATUS.PATCHED_NOT_RESTARTED,
            fixed: branchInfo.fixed,
            branch: branchKey,
            notes: `Binary on disk is ${parsed.semver} (>= ${branchInfo.fixed}), but running workers have not been restarted`
          };
        }
        return {
          status: STATUS.PATCHED,
          fixed: branchInfo.fixed,
          branch: branchKey,
          notes: `Version ${parsed.semver} meets or exceeds fixed release ${branchInfo.fixed}`
        };
      }

      if (isDistroVersionString(rawVersion)) {
        return {
          status: STATUS.UNKNOWN_BACKPORT_POSSIBLE,
          fixed: branchInfo.fixed,
          branch: branchKey,
          notes: `Version ${parsed.semver} is below ${branchInfo.fixed}, but distro package may carry security backports`
        };
      }

      return {
        status: STATUS.VULNERABLE_PATCH_AVAILABLE,
        fixed: branchInfo.fixed,
        branch: branchKey,
        notes: `Version ${rawVersion} is below fixed release ${branchInfo.fixed} (${cveStr})`
      };
    }
  }

  // Fallbacks for legacy branches not explicitly present in JSON
  if (product === 'php') {
    if (parsed.major < 8 || parsed.branch === '8.0' || parsed.branch === '8.1') {
      if (isDistroVersionString(rawVersion)) {
        return {
          status: STATUS.UNKNOWN_BACKPORT_POSSIBLE,
          fixed: 'vendor-backport',
          branch: parsed.branch,
          notes: `EOL branch ${parsed.branch} from distro package; inspect package changelog for CVE-2026-109618 and CVE-2026-109619`
        };
      }
      const sourceBackportBranches = new Set(['7.4', '8.0', '8.1']);
      const notes = sourceBackportBranches.has(parsed.branch)
        ? `No official php.net release for ${parsed.branch}; PHP published minimal source backports that vendors must package and validate`
        : `End-of-life PHP branch ${parsed.branch} with no official release (earliest affected path dates to PHP 5.4.0)`;
      return {
        status: STATUS.EOL_NO_OFFICIAL_RELEASE,
        fixed: 'none (upgrade to 8.3.36 or 8.4.27)',
        branch: parsed.branch,
        notes
      };
    }
  } else if (product === 'nodejs') {
    const eolMajors = new Set([18, 20, 23, 25]);
    if (eolMajors.has(parsed.major) || parsed.major < 22) {
      return {
        status: STATUS.EOL_NO_OFFICIAL_RELEASE,
        fixed: 'none (upgrade to 22.23.4 or 24.22.1)',
        branch: String(parsed.major),
        notes: `Node.js ${parsed.major}.x is End-of-Life and receives no fix for CVE-2026-111497 and October 2026 High CVEs`
      };
    }
  }

  return {
    status: STATUS.UNKNOWN,
    fixed: 'unknown',
    branch: branchKey,
    notes: `Branch ${branchKey} is newer than advisory database (${DB_DATE})`
  };
}

export function evaluatePhpVersion(rawVersion, options = {}) {
  return evaluateProductVersion('php', rawVersion, options);
}

export function evaluateNodeVersion(rawVersion, options = {}) {
  return evaluateProductVersion('nodejs', rawVersion, options);
}

export function auditConfigContent(content, type = 'php-ini', phpBranch = '8.3') {
  const findings = [];
  if (type === 'php-ini') {
    const memMatch = content.match(/^\s*memory_limit\s*=\s*([^\s;#]+)/m);
    if (!memMatch || memMatch[1] !== '-1') {
      findings.push({
        id: 'B1_MEMORY_LIMIT',
        mitigation: 'M2',
        cve: 'CVE-2026-109618',
        confidence: 'official-partial',
        severity: 'high',
        message: 'memory_limit is not set to -1. Official PHP guidance for CVE-2026-109618 recommends enforcing php_admin_value[memory_limit] = -1 paired with cgroup/container memory limits (reduces exposure; does not replace patching).'
      });
    }
    const uploadProg = content.match(/^\s*session\.upload_progress\.enabled\s*=\s*([^\s;#]+)/mi);
    if (!uploadProg || !/^(0|off|false)$/i.test(uploadProg[1])) {
      findings.push({
        id: 'B1_UPLOAD_PROGRESS',
        mitigation: 'M5',
        cve: 'CVE-2026-109619',
        confidence: 'official-partial',
        severity: 'high',
        message: 'session.upload_progress.enabled is not disabled (0/Off) before request parsing (covers one confirmed path of CVE-2026-109619; reduces exposure, does not replace patching).'
      });
    }
    if (phpBranch === '8.5') {
      const bt = content.match(/^\s*fatal_error_backtraces\s*=\s*([^\s;#]+)/mi);
      if (!bt || !/^(0|off|false)$/i.test(bt[1])) {
        findings.push({
          id: 'B13_FATAL_BACKTRACES',
          mitigation: 'M6',
          cve: 'CVE-2026-109619',
          confidence: 'official-partial',
          severity: 'medium',
          message: 'On PHP 8.5, set fatal_error_backtraces = 0 before request parsing.'
        });
      }
    }
  } else if (type === 'fpm') {
    if (!/php_admin_value\[memory_limit\]\s*=\s*-1/.test(content)) {
      findings.push({
        id: 'B10_FPM_ADMIN_MEMORY_LIMIT',
        mitigation: 'M2',
        cve: 'CVE-2026-109618',
        confidence: 'official-partial',
        severity: 'high',
        message: 'FPM pool does not enforce php_admin_value[memory_limit] = -1 administratively.'
      });
    }
    if (/php_value\[memory_limit\]\s*=\s*[0-9]+/.test(content)) {
      findings.push({
        id: 'B10_FINITE_POOL_MEMORY',
        mitigation: 'M2',
        cve: 'CVE-2026-109618',
        confidence: 'official-partial',
        severity: 'high',
        message: 'FPM pool sets a finite memory_limit via php_value, allowing controllable OOM failure.'
      });
    }
  } else if (type === 'nginx') {
    if (/fastcgi_param\s+PHP_(ADMIN_)?VALUE/i.test(content)) {
      findings.push({
        id: 'B11_NGINX_FASTCGI_PHP_VALUE',
        mitigation: 'M7',
        cve: 'CVE-2026-109619',
        confidence: 'official',
        severity: 'high',
        message: 'Nginx configuration passes per-request fastcgi_param PHP_VALUE/PHP_ADMIN_VALUE, which can trigger early diagnostics (M7).'
      });
    }
    if (!/client_max_body_size\s+[0-9]+[km]/i.test(content)) {
      findings.push({
        id: 'B12_NGINX_BODY_LIMIT',
        mitigation: 'M4',
        cve: 'CVE-2026-109618',
        confidence: 'official-partial',
        severity: 'medium',
        message: 'Nginx configuration does not explicitly set a bounded client_max_body_size (M4).'
      });
    }
  } else if (type === 'apache' || type === 'htaccess') {
    if (/^\s*php_(value|flag)\s+/mi.test(content)) {
      findings.push({
        id: 'B11_HTACCESS_PHP_VALUE',
        mitigation: 'M7',
        cve: 'CVE-2026-109619',
        confidence: 'official',
        severity: 'high',
        message: 'Per-request php_value or php_flag directive detected; under mod_php this can emit early diagnostics (M7).'
      });
    }
  } else if (type === 'systemd') {
    if (/Limit(AS|DATA)\s*=\s*[0-9]+/i.test(content)) {
      findings.push({
        id: 'B9_RLIMIT_AS_DATA',
        mitigation: 'M3',
        cve: 'CVE-2026-109618',
        confidence: 'official',
        severity: 'critical',
        message: 'Systemd unit sets finite LimitAS or LimitDATA (RLIMIT_AS/RLIMIT_DATA), which triggers allocation failures exploited by CVE-2026-109618. Use cgroup MemoryMax instead (M3).'
      });
    }
  }
  return findings;
}

export function scanIndicatorsInText(logText, sourceType = 'php-error-log') {
  const hits = [];
  const lines = String(logText).split(/\r?\n/);

  // First pass for process tree PID/PPID tracking when sourceType === 'ps'
  const workerPids = new Set();
  if (sourceType === 'ps') {
    for (const line of lines) {
      const m = line.trim().match(/^([0-9]+)\s+([0-9]+)\s+([^\s]+)\s+(.*)$/);
      if (m && /(php-fpm|apache2|httpd|frankenphp|lsphp|php-cgi)/i.test(m[3] + ' ' + m[4])) {
        workerPids.add(m[1]);
      }
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/Allowed memory size of [0-9]+ bytes exhausted \(tried to allocate [0-9]+ bytes\) in Unknown on line 0/i.test(line)) {
      hits.push({
        id: 'IOC1_UNKNOWN_LINE_0_OOM',
        source: sourceType,
        line: i + 1,
        evidence: line.trim(),
        note: 'Memory exhaustion during PHP request startup (in Unknown on line 0) matches CVE-2026-109618 indicator.'
      });
    }
    if (/AH00052:.*child pid [0-9]+ exit signal Segmentation fault \(11\)/i.test(line)) {
      hits.push({
        id: 'IOC2_APACHE_SEGFAULT_AH00052',
        source: sourceType,
        line: i + 1,
        evidence: line.trim(),
        note: 'Apache worker segmentation fault (AH00052) can occur after failed address guesses (indicator only).'
      });
    }
    if (sourceType === 'ps') {
      const pm = line.trim().match(/^([0-9]+)\s+([0-9]+)\s+([^\s]+)\s+(.*)$/);
      if (pm && workerPids.has(pm[2]) && /^(sh|bash|dash|nc|ncat|curl|wget|python[23]?)$/i.test(pm[3])) {
        hits.push({
          id: 'IOC4_WORKER_CHILD_SHELL',
          source: 'process-tree',
          line: i + 1,
          evidence: line.trim(),
          note: `Shell or network utility (PID ${pm[1]}) spawned under web worker parent (PPID ${pm[2]}).`
        });
      } else if (/(php-fpm|apache2|httpd|frankenphp|lsphp|php-cgi).*(?:\s|\/)(sh|bash|dash|nc|ncat|curl|wget|python[23]?)\b/i.test(line)) {
        hits.push({
          id: 'IOC4_WORKER_CHILD_SHELL',
          source: 'process-tree',
          line: i + 1,
          evidence: line.trim(),
          note: 'Shell or network utility spawned under web worker process.'
        });
      }
    }
  }
  return {
    indicators_found: hits.length > 0,
    count: hits.length,
    status: hits.length > 0
      ? `indicator found (${hits.length} indicator(s); preserve volatile evidence with --collect-evidence before restarting workers)`
      : 'no indicator found in the logs available (rotation and retention limits apply)',
    hits
  };
}

export function scanBrotliExposureInProject(targetDir) {
  const hints = [];
  const pkgPath = path.join(targetDir, 'package.json');
  const brotliPackages = ['undici', 'node-fetch', 'axios', 'got', 'superagent', 'iltorb', 'brotli', 'compression'];

  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      for (const dep of brotliPackages) {
        if (allDeps[dep]) {
          hints.push({
            id: 'D2_BROTLI_DEPENDENCY',
            file: 'package.json',
            package: dep,
            version: allDeps[dep],
            note: `Dependency '${dep}' may auto-decompress Brotli streams or handle Content-Encoding/Accept-Encoding: br (CVE-2026-111497 exposure hint).`
          });
        }
      }
    } catch (_) {
      // ignore invalid json
    }
  }

  const walk = (dir, depth = 0) => {
    if (depth > 4 || !fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (['node_modules', '.git', 'vendor', '.php2shell-guard'].includes(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full, depth + 1);
      } else if (/\.(mjs|cjs|js|ts|tsx|jsx)$/.test(entry.name)) {
        const text = fs.readFileSync(full, 'utf8');
        if (/\b(brotliDecompress|brotliDecompressSync|createBrotliDecompress)\b/.test(text)) {
          hints.push({
            id: 'D1_DIRECT_ZLIB_BROTLI',
            file: path.relative(targetDir, full),
            note: 'Direct call to Node zlib Brotli decompression API detected (CVE-2026-111497 exposure hint).'
          });
        }
        if (/\bdns\.resolve\b/.test(text)) {
          hints.push({
            id: 'D6_DNS_RESOLVE',
            file: path.relative(targetDir, full),
            note: 'Call to dns.resolve detected; ensure untrusted input does not contain NUL bytes (CVE-2026-105482).'
          });
        }
      }
    }
  };

  if (fs.existsSync(targetDir) && fs.statSync(targetDir).isDirectory()) {
    walk(targetDir);
  }
  return hints;
}

export function scanProjectFiles(targetDir) {
  const findings = [];
  if (!fs.existsSync(targetDir)) return findings;

  // 1. composer.json
  const composerFile = path.join(targetDir, 'composer.json');
  if (fs.existsSync(composerFile)) {
    try {
      const comp = JSON.parse(fs.readFileSync(composerFile, 'utf8'));
      const reqPhp = comp?.require?.php;
      const platPhp = comp?.config?.platform?.php;
      if (reqPhp) {
        findings.push({
          file: 'composer.json',
          field: 'require.php',
          value: reqPhp,
          note: /(7\.|8\.0|8\.1)/.test(reqPhp)
            ? 'Allows EOL PHP branches (7.x / 8.0 / 8.1) which have no official php.net release for PHP2Shell'
            : 'PHP version constraint declared'
        });
      }
      if (platPhp) {
        const ev = evaluatePhpVersion(platPhp.split('.').length === 2 ? `${platPhp}.0` : platPhp);
        findings.push({
          file: 'composer.json',
          field: 'config.platform.php',
          value: platPhp,
          status: ev.status,
          fixed: ev.fixed,
          note: ev.notes
        });
      }
    } catch (_) {}
  }

  // 2. Dockerfile*
  for (const name of fs.readdirSync(targetDir)) {
    if (/^Dockerfile/i.test(name)) {
      const dfPath = path.join(targetDir, name);
      if (!fs.statSync(dfPath).isFile()) continue;
      const lines = fs.readFileSync(dfPath, 'utf8').split(/\r?\n/);
      lines.forEach((line, idx) => {
        const phpMatch = line.match(/^\s*FROM\s+php:([^\s]+)/i);
        if (phpMatch) {
          const tag = phpMatch[1];
          const isDigestPinned = tag.includes('@sha256:');
          const sem = extractSemver(tag);
          let evalRes;
          if (sem) {
            evalRes = evaluatePhpVersion(sem.semver);
          } else {
            const brMatch = tag.match(/^([0-9]+\.[0-9]+)/);
            evalRes = brMatch
              ? evaluatePhpVersion(`${brMatch[1]}.0`)
              : { status: STATUS.UNKNOWN, fixed: '8.3.36 / 8.4.27', notes: 'Floating Docker tag; pin to >= 8.3.36 or 8.4.27 and rebuild with --pull' };
          }
          findings.push({
            file: name,
            line: idx + 1,
            image: `php:${tag}`,
            digest_pinned: isDigestPinned,
            status: evalRes.status,
            fixed: evalRes.fixed,
            note: isDigestPinned
              ? `${evalRes.notes} (Digest-pinned image will not auto-update until SHA256 digest is bumped)`
              : evalRes.notes
          });
        }
        const nodeMatch = line.match(/^\s*FROM\s+node:([^\s]+)/i);
        if (nodeMatch) {
          const tag = nodeMatch[1];
          const sem = extractSemver(tag);
          const evalRes = sem
            ? evaluateNodeVersion(sem.semver)
            : { status: STATUS.UNKNOWN, fixed: '22.23.4 / 24.22.1', notes: 'Floating Node Docker tag; pin to >= 22.23.4 or 24.22.1' };
          findings.push({
            file: name,
            line: idx + 1,
            image: `node:${tag}`,
            status: evalRes.status,
            fixed: evalRes.fixed,
            note: evalRes.notes
          });
        }
      });
    }
  }

  // 3. Coolify version check if coolify config or compose present
  const composeFile = path.join(targetDir, 'docker-compose.yml');
  if (fs.existsSync(composeFile)) {
    const content = fs.readFileSync(composeFile, 'utf8');
    const coolifyMatch = content.match(/coollabsio\/coolify:v?([0-9]+\.[0-9]+\.[0-9]+)/i);
    if (coolifyMatch) {
      const cVer = coolifyMatch[1];
      findings.push({
        file: 'docker-compose.yml',
        component: 'coolify',
        value: cVer,
        note: 'CRITICAL (H9): Ensure Coolify is >= 4.0.1 / 4.1.3 / 4.2.1 / 4.3.24 / 4.4.7. Updating or isolating Coolify itself does NOT rebuild or isolate the PHP/Laravel/WordPress/Node application containers it deployed.'
      });
    }
  }

  return findings;
}

export function verifyDatabase(rootDir = ROOT_DIR) {
  const advDir = path.join(rootDir, 'data', 'advisories');
  const files = fs.readdirSync(advDir).filter(f => f.endsWith('.json'));
  const errors = [];
  const now = new Date('2026-10-23T00:00:00Z');

  for (const file of files) {
    const full = path.join(advDir, file);
    const data = JSON.parse(fs.readFileSync(full, 'utf8'));
    const required = ['id', 'title', 'product', 'cves', 'severity', 'published', 'branches', 'mitigations', 'sources', 'exploitation', 'last_verified'];
    for (const req of required) {
      if (!(req in data)) {
        errors.push(`${file}: missing required property '${req}'`);
      }
    }
    if (!Array.isArray(data.sources) || data.sources.length < 2) {
      errors.push(`${file}: violates two-source rule (found ${data.sources?.length || 0} sources, minimum 2 required)`);
    }
    for (const m of data.mitigations || []) {
      if (!['official', 'official-partial', 'vendor-reported', 'reasoning-based'].includes(m.confidence)) {
        errors.push(`${file}: mitigation ${m.id} has invalid confidence label '${m.confidence}'`);
      }
    }
    if (data.last_verified) {
      const verifiedDate = new Date(`${data.last_verified}T00:00:00Z`);
      const ageDays = Math.floor((now - verifiedDate) / (1000 * 60 * 60 * 24));
      if (ageDays > 30) {
        errors.push(`${file}: last_verified (${data.last_verified}) is older than 30 days (${ageDays} days)`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    checked_files: files,
    errors
  };
}

export function generateUpgradePlan(targetDir, targetPhp = '8.3') {
  const blockers = [];
  let laravelVersion = null;
  const compPath = path.join(targetDir, 'composer.json');
  if (fs.existsSync(compPath)) {
    try {
      const comp = JSON.parse(fs.readFileSync(compPath, 'utf8'));
      const req = { ...(comp.require || {}), ...(comp['require-dev'] || {}) };
      if (req['laravel/framework']) {
        laravelVersion = req['laravel/framework'];
        if (/^\^?(6|7|8|9)\./.test(laravelVersion) && (targetPhp === '8.3' || targetPhp === '8.4')) {
          blockers.push({
            package: 'laravel/framework',
            constraint: laravelVersion,
            reason: `Laravel ${laravelVersion} must be upgraded to Laravel 10.x (PHP 8.1-8.3) or Laravel 11.x/12.x (PHP 8.2-8.4) to run on PHP ${targetPhp}.`
          });
        }
      }
      for (const [pkg, ver] of Object.entries(req)) {
        if (pkg === 'php' && !ver.includes(targetPhp) && !ver.includes('^8') && !ver.includes('>=8')) {
          blockers.push({
            package: 'php',
            constraint: ver,
            reason: `composer.json require.php (${ver}) does not currently allow PHP ${targetPhp}`
          });
        }
      }
    } catch (_) {}
  }

  const sizeTier = blockers.length === 0 ? 'S' : blockers.length <= 2 ? 'M' : blockers.length <= 5 ? 'L' : 'XL';
  const hoursMap = { S: '4-8 hours', M: '12-24 hours', L: '24-48 hours', XL: '48-80+ hours' };
  const targetFixed = targetPhp === '8.4' ? '8.4.27' : targetPhp === '8.5' ? '8.5.12' : targetPhp === '8.2' ? '8.2.35' : '8.3.36';

  return {
    target_php_branch: targetPhp,
    recommended_release: targetFixed,
    laravel_detected: laravelVersion,
    blockers,
    effort_estimate: {
      t_shirt_size: sizeTier,
      estimated_engineering_range: hoursMap[sizeTier],
      assumptions: 'Assumes automated Rector/PHPStan pass, staging smoke test suite, and FPM/container rollout.'
    }
  };
}

export function diffAuditReports(beforeReport, afterReport) {
  const indexRuntimes = (rep) => {
    const map = {};
    for (const rt of (rep?.runtimes || [])) {
      map[rt.component || 'unknown'] = rt;
    }
    return map;
  };

  const beforeMap = indexRuntimes(beforeReport);
  const afterMap = indexRuntimes(afterReport);
  const allKeys = Array.from(new Set([...Object.keys(beforeMap), ...Object.keys(afterMap)]));

  const isVuln = (s) => ['VULNERABLE_PATCH_AVAILABLE', 'EOL_NO_OFFICIAL_RELEASE', 'PATCHED_NOT_RESTARTED'].includes(s);

  const remediated = [];
  const persistent = [];
  const regressions = [];
  const unchanged = [];

  for (const k of allKeys) {
    const b = beforeMap[k];
    const a = afterMap[k];
    if (b && a) {
      const bV = isVuln(b.status);
      const aV = isVuln(a.status);
      if (bV && !aV) {
        remediated.push({
          component: k,
          before_version: b.detected_version,
          before_status: b.status,
          after_version: a.detected_version,
          after_status: a.status
        });
      } else if (bV && aV) {
        persistent.push({
          component: k,
          before_version: b.detected_version,
          after_version: a.detected_version,
          status: a.status
        });
      } else if (!bV && aV) {
        regressions.push({
          component: k,
          before_status: b.status,
          after_status: a.status
        });
      } else {
        unchanged.push({ component: k, status: a.status });
      }
    }
  }

  return {
    summary: {
      remediated_count: remediated.length,
      persistent_count: persistent.length,
      regressions_count: regressions.length,
      status: persistent.length === 0 ? 'ALL_REMEDIATED' : 'REMEDIATION_INCOMPLETE'
    },
    remediated,
    persistent,
    regressions,
    unchanged
  };
}

export function applyConfig(target = 'php-ini', options = {}) {
  const {
    rootDir = ROOT_DIR,
    backupRoot = '.php2shell-guard/backups',
    destinationPath = null,
    dryRun = true,
    reload = false,
    customValidator = null
  } = options;

  const targetMap = {
    'php-ini': {
      template: 'templates/php-ini/99-php2shell-mitigation.ini',
      destination: '/etc/php/8.3/fpm/conf.d/99-php2shell-mitigation.ini',
      validator: 'php -v',
      reload: 'systemctl restart php8.3-fpm 2>&1'
    },
    fpm: {
      template: 'templates/fpm/zz-php2shell-pool.conf',
      destination: '/etc/php/8.3/fpm/pool.d/zz-php2shell-pool.conf',
      validator: 'php-fpm8.3 -t 2>&1 || php-fpm -t 2>&1',
      reload: 'systemctl reload php8.3-fpm 2>&1'
    },
    nginx: {
      template: 'templates/nginx/php2shell-mitigation.conf',
      destination: '/etc/nginx/conf.d/php2shell-mitigation.conf',
      validator: 'nginx -t 2>&1',
      reload: 'systemctl reload nginx 2>&1'
    },
    apache: {
      template: 'templates/apache/php2shell-mitigation.conf',
      destination: '/etc/apache2/conf-available/php2shell-mitigation.conf',
      validator: 'apache2ctl -t 2>&1 || httpd -t 2>&1',
      reload: 'systemctl reload apache2 2>&1'
    }
  };

  const defaults = targetMap[target];
  if (!defaults) {
    throw new Error(`Unknown mitigation target '${target}'. Supported: php-ini, fpm, nginx, apache.`);
  }

  const templateFile = path.resolve(rootDir, defaults.template);
  if (!fs.existsSync(templateFile)) {
    throw new Error(`Template file not found: ${templateFile}`);
  }

  const snippetContent = fs.readFileSync(templateFile, 'utf8');
  const dest = destinationPath || defaults.destination;
  const validator = customValidator !== undefined ? customValidator : defaults.validator;
  const reloadCmd = defaults.reload;

  const timestamp = new Date().toISOString().replace(/[-:T.]/g, '').slice(0, 15);
  const backupDir = path.resolve(backupRoot, timestamp);
  const backupFile = path.join(backupDir, `${path.basename(dest)}.bak`);

  if (dryRun) {
    return {
      applied: false,
      dry_run: true,
      destination: dest,
      planned_backup: backupFile,
      validator,
      message: 'Dry run only. To apply changes with backup and validation, specify --yes.'
    };
  }

  const hadExisting = fs.existsSync(dest);
  if (hadExisting) {
    fs.mkdirSync(backupDir, { recursive: true });
    fs.copyFileSync(dest, backupFile);
  }

  const destDir = path.dirname(dest);
  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }

  fs.writeFileSync(dest, snippetContent, 'utf8');

  // Pre-validation
  if (validator) {
    let valid = true;
    let valOut = '';
    try {
      valOut = execSync(validator, { stdio: 'pipe' }).toString();
    } catch (err) {
      valid = false;
      valOut = err.stderr ? err.stderr.toString() : err.message;
    }

    if (!valid) {
      // Automatic rollback
      if (hadExisting && fs.existsSync(backupFile)) {
        fs.copyFileSync(backupFile, dest);
      } else {
        try { fs.unlinkSync(dest); } catch (_) {}
      }
      return {
        applied: false,
        rolled_back: true,
        dry_run: false,
        destination: dest,
        backup_file: hadExisting ? backupFile : null,
        error: `Configuration validation failed! Automatically rolled back. Details: ${valOut}`
      };
    }
  }

  let reloaded = false;
  if (reload && reloadCmd) {
    try {
      execSync(reloadCmd, { stdio: 'pipe' });
      reloaded = true;
    } catch (_) {
      reloaded = false;
    }
  }

  return {
    applied: true,
    rolled_back: false,
    dry_run: false,
    destination: dest,
    backup_file: hadExisting ? backupFile : null,
    reloaded,
    message: 'Configuration validated and applied successfully.'
  };
}

export function renderMarkdown(payload, options = {}) {
  const brandName = options.brandName || 'php2shell-guard';
  const brandContact = options.brandContact || null;
  const noCta = Boolean(options.noCta);

  const lines = [
    `# ${brandName} Security Audit Report`,
    '',
    `**Target:** \`${payload.host || 'localhost'}\` | **Advisory Database:** \`${payload.advisory_db_date || DB_DATE}\` | **Mode:** Read-only`
  ];
  if (brandContact) {
    lines.push(`**Audited By:** ${brandContact}`);
  }
  lines.push('');

  lines.push('## Runtime Findings');
  lines.push('');
  lines.push('| Component | Detected Version | Status | Fixed Version |');
  lines.push('|---|---|---|---|');
  for (const rt of (payload.runtimes || [])) {
    lines.push(`| \`${rt.component}\` | \`${rt.detected_version}\` | **${rt.status}** | \`${rt.fixed_version}\` |`);
  }
  lines.push('');
  lines.push('## Compromise Indicators (Logs & Processes)');
  lines.push('');
  lines.push(`> ${payload.indicators?.status || 'no indicator found in the logs available (rotation and retention limits apply)'}`);
  lines.push('');
  lines.push('_Note: Absence of indicators does not prove absence of compromise. Log rotation, retention limits, and stealthy in-memory attacks apply._');
  lines.push('');
  lines.push('## Remediation Guidance');
  lines.push('');
  lines.push('1. **Patching is mandatory:** Upgrading to >= 8.2.35, 8.3.36, 8.4.27, or 8.5.12 (and >= 22.23.4 / 24.22.1 for Node) is the only permanent defense.');
  lines.push('2. **Restart every worker:** A patched binary on disk has no effect until all worker processes and containers are restarted.');
  lines.push('');
  if (!noCta) {
    lines.push('---');
    lines.push('Need emergency patching assistance or a controlled PHP 8.3/8.4 upgrade plan? https://github.com/malikad778/php2shell-guard');
  }
  return lines.join('\n') + '\n';
}

export function renderSarif(payload) {
  const results = [];
  const rules = [
    {
      id: 'PHP2SHELL-109618',
      name: 'PhpOutOfMemoryCorruptionRce',
      shortDescription: { text: 'CVE-2026-109618: PHP Out-of-Memory Corruption Remote Code Execution' },
      defaultConfiguration: { level: 'error' }
    },
    {
      id: 'NODE2SHELL-111497',
      name: 'NodeBrotliDecoderOobWrite',
      shortDescription: { text: 'CVE-2026-111497: Node.js Brotli Decoder Out-of-Bounds Write RCE' },
      defaultConfiguration: { level: 'error' }
    }
  ];

  for (const rt of (payload.runtimes || [])) {
    if (['PATCHED', 'PATCHED_BACKPORT', 'NOT_DETECTED'].includes(rt.status)) continue;
    const isNode = rt.component === 'nodejs';
    const ruleId = isNode ? 'NODE2SHELL-111497' : 'PHP2SHELL-109618';
    results.push({
      ruleId,
      level: ['VULNERABLE_PATCH_AVAILABLE', 'EOL_NO_OFFICIAL_RELEASE'].includes(rt.status) ? 'error' : 'warning',
      message: { text: `${rt.component} (${rt.detected_version}) is ${rt.status}: ${rt.notes || ''} (Fix: ${rt.fixed_version})` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: 'server-runtime', uriBaseId: '%SRCROOT%' },
            region: { startLine: 1, startColumn: 1 }
          }
        }
      ]
    });
  }

  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'php2shell-guard',
            version: payload.version || TOOL_VERSION,
            informationUri: 'https://github.com/malikad778/php2shell-guard',
            rules
          }
        },
        results
      }
    ]
  }, null, 2);
}

export function renderJunit(payload) {
  const runtimes = payload.runtimes || [];
  const failures = runtimes.filter(r => ['VULNERABLE_PATCH_AVAILABLE', 'EOL_NO_OFFICIAL_RELEASE', 'PATCHED_NOT_RESTARTED'].includes(r.status)).length;
  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="php2shell-guard" tests="${runtimes.length}" failures="${failures}" errors="0" time="0.0">`,
    `  <testsuite name="runtime-advisory-audit" tests="${runtimes.length}" failures="${failures}" errors="0" time="0.0">`
  ];
  for (const rt of runtimes) {
    xml.push(`    <testcase classname="runtime" name="${rt.component}" time="0.0">`);
    if (['VULNERABLE_PATCH_AVAILABLE', 'EOL_NO_OFFICIAL_RELEASE', 'PATCHED_NOT_RESTARTED'].includes(rt.status)) {
      xml.push(`      <failure message="Status: ${rt.status} (Detected: ${rt.detected_version}, Fixed: ${rt.fixed_version})" type="${rt.status}">${rt.notes || ''}</failure>`);
    }
    xml.push('    </testcase>');
  }
  xml.push('  </testsuite>', '</testsuites>');
  return xml.join('\n') + '\n';
}

export function renderCsv(payload) {
  const lines = ['host,component,detected_version,status,fixed_version,notes'];
  const host = payload.host || 'localhost';
  for (const rt of (payload.runtimes || [])) {
    const esc = (s) => `"${String(s || '').replace(/"/g, '""')}"`;
    lines.push([host, rt.component, rt.detected_version, rt.status, rt.fixed_version, rt.notes].map(esc).join(','));
  }
  return lines.join('\n') + '\n';
}

function getCliArg(args, name, fallback = null) {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name && args[i + 1] && !args[i + 1].startsWith('-')) {
      return args[i + 1];
    }
    if (args[i].startsWith(name + '=')) {
      return args[i].slice(name.length + 1);
    }
  }
  return fallback;
}

// CLI execution when invoked directly
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const args = process.argv.slice(2);
  const cmd = args.find(a => !a.startsWith('-')) || 'scan';
  const format = getCliArg(args, '--format', 'table');
  const noCta = args.includes('--no-cta');
  const includeWeak = args.includes('--include-weak');

  const brandName = getCliArg(args, '--brand-name', 'php2shell-guard');
  const brandContact = getCliArg(args, '--brand-contact', null);

  if (args.includes('--print-commands')) {
    console.log([
      'php -v',
      'php-fpm -v',
      'node -v',
      'node -p "JSON.stringify({versions:process.versions,variables:process.config.variables})"',
      'bun --version'
    ].join('\n'));
    process.exit(0);
  }

  if (cmd === 'db:verify') {
    const res = verifyDatabase(ROOT_DIR);
    if (format === 'json') {
      console.log(JSON.stringify(res, null, 2));
    } else {
      console.log(`php2shell-guard db:verify | checked ${res.checked_files.length} advisory files | valid=${res.valid}`);
      if (!res.valid) {
        res.errors.forEach(e => console.error(`  ERROR: ${e}`));
      }
    }
    process.exit(res.valid ? 0 : 4);
  }

  if (cmd === 'explain') {
    const cve = args.find(a => /^CVE-/i.test(a)) || 'CVE-2026-109618';
    const phpAdv = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, 'data/advisories/php2shell-2026-10.json'), 'utf8'));
    const nodeAdv = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, 'data/advisories/nodejs-2026-10.json'), 'utf8'));
    const detail = phpAdv.cve_details?.[cve.toUpperCase()] || nodeAdv.cve_details?.[cve.toUpperCase()];
    if (!detail) {
      console.error(`Unknown CVE: ${cve}`);
      process.exit(4);
    }
    console.log(JSON.stringify({ cve: cve.toUpperCase(), ...detail, sources: cve.includes('10961') ? phpAdv.sources : nodeAdv.sources }, null, 2));
    process.exit(0);
  }

  if (cmd === 'mitigate') {
    const target = getCliArg(args, '--target', 'php-ini');
    const map = {
      'php-ini': 'templates/php-ini/99-php2shell-mitigation.ini',
      fpm: 'templates/fpm/zz-php2shell-pool.conf',
      nginx: 'templates/nginx/php2shell-mitigation.conf',
      apache: 'templates/apache/php2shell-mitigation.conf',
      modsecurity: 'templates/apache/modsecurity-php2shell.conf',
      docker: 'templates/docker/Dockerfile.patched',
      compose: 'templates/docker/docker-compose.override.yml',
      k8s: 'templates/k8s/kustomize-patch.yaml',
      cloudflare: 'templates/cloudflare/waf-custom-rule.txt',
      systemd: 'templates/systemd/php-fpm-mitigation.conf',
      ansible: 'templates/ansible/remediate-php2shell.yml'
    };
    if (!map[target]) {
      console.error(`Unknown mitigation target: ${target}`);
      process.exit(4);
    }
    process.stdout.write(fs.readFileSync(path.join(ROOT_DIR, map[target]), 'utf8'));
    if (includeWeak && target === 'nginx') {
      console.log('\n# [N3 - Weak/Last Resort] Reject inbound Content-Encoding: br for CVE-2026-111497 (reduces exposure only)\nif ($http_content_encoding ~* "br") { return 415; }');
    }
    process.exit(0);
  }

  if (cmd === 'apply') {
    const target = getCliArg(args, '--target', 'php-ini');
    const dryRun = !args.includes('--yes') && !args.includes('-y');
    const reload = args.includes('--reload');
    const dest = getCliArg(args, '--dest', null);

    try {
      const res = applyConfig(target, { rootDir: ROOT_DIR, destinationPath: dest, dryRun, reload });
      if (format === 'json') {
        console.log(JSON.stringify(res, null, 2));
      } else {
        console.log(`php2shell-guard apply (${dryRun ? 'DRY-RUN' : 'LIVE'})`);
        console.log(`  Target:      ${target}`);
        console.log(`  Destination: ${res.destination}`);
        console.log(`  Backup:      ${res.backup_file || res.planned_backup}`);
        console.log(`  Status:      ${res.applied ? 'APPLIED' : (res.dry_run ? 'PREVIEW_ONLY' : 'ROLLED_BACK')}`);
        console.log(`  Message:     ${res.message || res.error}`);
      }
      process.exit(res.applied || res.dry_run ? 0 : 1);
    } catch (err) {
      console.error(`Apply error: ${err.message}`);
      process.exit(1);
    }
  }

  if (cmd === 'diff') {
    const files = args.filter(a => !a.startsWith('-') && a !== 'diff');
    if (files.length < 2) {
      console.error('Usage: php2shell-guard diff <before.json> <after.json>');
      process.exit(4);
    }
    try {
      const before = JSON.parse(fs.readFileSync(files[0], 'utf8'));
      const after = JSON.parse(fs.readFileSync(files[1], 'utf8'));
      const diffRes = diffAuditReports(before, after);
      if (format === 'json') {
        console.log(JSON.stringify(diffRes, null, 2));
      } else {
        console.log('php2shell-guard Scan Difference Report');
        console.log('======================================');
        console.log(`Overall Result:      ${diffRes.summary.status}`);
        console.log(`Remediated Findings: ${diffRes.summary.remediated_count}`);
        console.log(`Persistent Findings: ${diffRes.summary.persistent_count}`);
        console.log(`Regressions:         ${diffRes.summary.regressions_count}`);
        if (diffRes.remediated.length > 0) {
          console.log('\n[+] REMEDIATED:');
          diffRes.remediated.forEach(r => console.log(`  - ${r.component}: ${r.before_version} (${r.before_status}) -> ${r.after_version} (${r.after_status})`));
        }
        if (diffRes.persistent.length > 0) {
          console.log('\n[!] PERSISTENT VULNERABILITIES:');
          diffRes.persistent.forEach(r => console.log(`  - ${r.component}: ${r.after_version} (Status: ${r.status})`));
        }
      }
      process.exit(0);
    } catch (err) {
      console.error(`Diff error: ${err.message}`);
      process.exit(4);
    }
  }

  if (cmd === 'upgrade:plan') {
    const toVer = getCliArg(args, '--to', '8.3');
    const targetDir = args.filter(a => !a.startsWith('-') && a !== 'upgrade:plan' && a !== toVer)[0] || '.';
    const plan = generateUpgradePlan(targetDir, toVer);
    console.log(JSON.stringify(plan, null, 2));
    process.exit(0);
  }

  if (cmd === 'project:scan') {
    const targetDir = args.filter(a => !a.startsWith('-') && a !== 'project:scan' && a !== format)[0] || '.';
    const findings = scanProjectFiles(targetDir);
    console.log(JSON.stringify({ command: 'project:scan', target: targetDir, findings }, null, 2));
    const hasVuln = findings.some(f => f.status === STATUS.VULNERABLE_PATCH_AVAILABLE || f.status === STATUS.EOL_NO_OFFICIAL_RELEASE);
    process.exit(hasVuln ? 1 : 0);
  }

  if (cmd === 'node:scan') {
    const targetDir = args.filter(a => !a.startsWith('-') && a !== 'node:scan' && a !== format)[0] || '.';
    const nodeEval = evaluateNodeVersion(process.versions.node);
    const brotliHints = scanBrotliExposureInProject(targetDir);
    const sharedBrotli = Boolean(process.config?.variables?.node_shared_brotli);
    const report = {
      command: 'node:scan',
      node_version: process.versions.node,
      brotli_version: process.versions.brotli || 'unknown',
      shared_brotli_build: sharedBrotli,
      status: nodeEval.status,
      fixed_version: nodeEval.fixed,
      notes: nodeEval.notes,
      exposure_hints: brotliHints
    };
    console.log(JSON.stringify(report, null, 2));
    process.exit(statusToExitCode(nodeEval.status));
  }

  // Default: scan
  const mockNode = process.env.PHP2SHELL_MOCK_NODE_VERSION || process.versions.node;
  const mockPhp = process.env.PHP2SHELL_MOCK_PHP_FPM_VERSION || null;
  const stale = process.env.PHP2SHELL_MOCK_STALE_WORKER === '1';

  const nodeRes = evaluateNodeVersion(mockNode, { staleWorker: stale });
  const phpRes = mockPhp
    ? evaluatePhpVersion(mockPhp, { staleWorker: stale })
    : { status: STATUS.NOT_DETECTED, fixed: 'none', notes: 'No PHP web SAPI detected' };

  const exitCode = Math.max(statusToExitCode(nodeRes.status), statusToExitCode(phpRes.status));
  const payload = {
    tool: 'php2shell-guard',
    version: TOOL_VERSION,
    advisory_db_date: DB_DATE,
    mode: 'read-only',
    host: os.hostname(),
    runtimes: [
      {
        component: 'php-fpm',
        detected_version: mockPhp || 'not_detected',
        status: phpRes.status,
        fixed_version: phpRes.fixed,
        notes: phpRes.notes
      },
      {
        component: 'nodejs',
        detected_version: mockNode,
        brotli_version: process.versions.brotli || 'unknown',
        status: nodeRes.status,
        fixed_version: nodeRes.fixed,
        notes: nodeRes.notes
      }
    ],
    indicators: {
      status: 'no indicator found in the logs available (rotation and retention limits apply)'
    },
    exit_code: exitCode
  };

  if (format === 'json') {
    console.log(JSON.stringify(payload, null, 2));
  } else if (format === 'markdown') {
    process.stdout.write(renderMarkdown(payload, { brandName, brandContact, noCta }));
  } else if (format === 'sarif') {
    console.log(renderSarif(payload));
  } else if (format === 'junit') {
    process.stdout.write(renderJunit(payload));
  } else if (format === 'csv') {
    process.stdout.write(renderCsv(payload));
  } else {
    console.log(`php2shell-guard v${TOOL_VERSION}  |  advisory db ${DB_DATE}  |  read-only scan`);
    console.log(`  php-fpm   ${mockPhp || 'not detected'}   ${phpRes.status} (fix: ${phpRes.fixed})`);
    console.log(`  nodejs    ${mockNode} (brotli ${process.versions.brotli || 'n/a'})   ${nodeRes.status} (fix: ${nodeRes.fixed})`);
    console.log(`Indicators: ${payload.indicators.status}`);
    if (!noCta) {
      console.log('Need emergency patching or PHP/Node migration? https://github.com/malikad778/php2shell-guard?utm_source=node_cli');
    }
  }
  process.exit(exitCode);
}
