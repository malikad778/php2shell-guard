# Hacker News: Show HN Submission

**Title:** Show HN: php2shell-guard – Read-only auditor for PHP2Shell (CVE-2026-109618) and Node.js CVEs

**URL / Link:** https://github.com/malikad778/php2shell-guard

**Text / First Comment:**

Hi HN,

I built php2shell-guard, an open-source, read-only defensive security auditor for PHP2Shell (CVE-2026-109618 & CVE-2026-109619) and Node.js October 2026 advisories (CVE-2026-111497).

When a high-severity bug like PHP2Shell drops, the immediate guidance is "upgrade your PHP packages." But across production fleets, real-world reality is messy:

1. **Stale Workers in RAM:** OS package managers replace the PHP binary on disk, but running PHP-FPM or Apache worker pools keep executing the unpatched binary from memory. The disk shows 8.3.36, but active processes in RAM are still vulnerable.
2. **Distro Backports:** Debian, Ubuntu, Alpine, and RHEL regularly backport security patches without bumping the upstream semver. Generic scanners trigger false positives that waste engineering cycles.
3. **Legacy EOL Runtimes:** Thousands of production systems run PHP 7.4, 8.0, or 8.1 where upstream fixes will never exist.

Key design choices in php2shell-guard:
- **Zero runtime dependencies:** Available as a POSIX shell script (runs via curl on dash, bash, busybox), a standalone compiled PHAR archive (PHP 5.4 - 8.4+), an npm CLI (`npx php2shell-guard scan`), and a Composer package (`composer require --dev malikad/php2shell-guard`).
- **Strictly read-only:** Contains no exploit code or PoC payloads.
- **Defensive IOC7 wording:** Never emits "safe" or "clean" verdicts because log retention and rotation limits cannot prove the absence of historical exploitation.
- **Automated configuration rollback:** Stopgap apply mode creates timestamped backups and executes `php -v`, `php-fpm -t`, and `nginx -t` before activating configuration changes, rolling back automatically if validation fails.
- **Dynamic advisory feed:** Advisory definitions live in validated JSON schemas, allowing zero-day detection updates without redeploying code.

One-liner verification:
```bash
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan
```

Live documentation & version calculator: https://codebyadnan.tech/php2shell-guard/
Packagist: https://packagist.org/packages/malikad/php2shell-guard
NPM: https://www.npmjs.com/package/php2shell-guard

I would love feedback on the detection heuristics and distro backport parsers.
