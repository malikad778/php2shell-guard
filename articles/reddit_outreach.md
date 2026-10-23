# Reddit Outreach Threads for php2shell-guard

---

## 1. r/PHP

**Title:** Technical Breakdown: Auditing PHP2Shell (CVE-2026-109618), Stale Workers, and EOL Branches

**Body:**

Hey r/PHP,

With the disclosure of PHP2Shell (CVE-2026-109618 and CVE-2026-109619), unauthenticated remote code execution via file upload progress tracking is actively being scanned across the web.

While the fix itself is straightforward (update to PHP 8.2.35, 8.3.36, 8.4.27, or 8.5.12), real-world production fleets encounter distinct operational snags:
1. Long-running FPM pools frequently do not restart after `apt upgrade` or `dnf update`, so running processes continue executing unpatched binary code in memory.
2. Distro packages (Debian, Ubuntu, Alpine, RHEL) often backport security fixes without changing upstream semver, which trips generic version checks.
3. Unsupported EOL branches (PHP 5.4 through 8.1) have no upstream fix.

I built `php2shell-guard`, an open-source, read-only defensive auditor with zero runtime dependencies and no exploit code or PoC:

```bash
# Instant POSIX one-liner (works via dash, bash, busybox sh):
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan

# Or via standalone executable PHAR:
php -r "copy('https://raw.githubusercontent.com/malikad778/php2shell-guard/main/php2shell-guard.phar', 'php2shell-guard.phar');"
php php2shell-guard.phar scan --format=table

# Or via Composer for Laravel / Symfony / WordPress:
composer require --dev malikad/php2shell-guard
php artisan php2shell:audit
```

Key technical features:
- **Separates Web SAPI from CLI:** Evaluates Apache mod_php, PHP-FPM, LiteSpeed lsphp, and FrankenPHP with appropriate risk models.
- **Catches Stale Workers:** Detects `/proc/<pid>/exe (deleted)` and compares process launch timestamps against binary modification dates.
- **Log Indicators (IOC1, IOC2):** Scans for signature error strings like `"Allowed memory size of ... exhausted in Unknown on line 0"` and `"AH00052: child pid ... exit signal Segmentation fault (11)"`.
- **Defensive IOC7 Reporting:** Never claims a server is "safe" or "clean" because log rotation or truncation cannot prove the absence of exploitation.
- **Automated Stopgap Rollback:** If you cannot patch an EOL host today, it generates `memory_limit = -1` configurations, validates syntax with `php -v` and `php-fpm -t`, and rolls back automatically if validation fails.

GitHub: https://github.com/malikad778/php2shell-guard
Docs & Live Version Calculator: https://codebyadnan.tech/php2shell-guard/
Packagist: https://packagist.org/packages/malikad/php2shell-guard
NPM: https://www.npmjs.com/package/php2shell-guard

Feedback and pull requests welcome!

---

## 2. r/sysadmin

**Title:** Free Read-Only Auditor for PHP2Shell (CVE-2026-109618): Catches Stale FPM Workers and Distro Backports

**Body:**

Sysadmins,

If you are managing Linux servers, Docker containers, or Kubernetes clusters running PHP, there is a common pitfall happening right now with PHP2Shell (CVE-2026-109618):

Package managers (`apt`, `dnf`, `apk`) replace the PHP binary on disk, but long-running systemd worker pools (`php-fpm.service`, `httpd.service`) do not restart automatically in many environments. The binary on disk is patched, but the process executing in RAM is still vulnerable.

To audit active worker states across fleets without installing new dependencies, I open-sourced `php2shell-guard`:

```bash
# Audit running workers and host config in under 30 seconds:
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan
```

What it checks:
1. **In-Memory Worker Inodes:** Flags running workers holding deleted file handles (`/proc/<pid>/exe (deleted)`) with exit code 1 (`PATCHED_NOT_RESTARTED`).
2. **Distro Backport Awareness:** Understands Debian, Ubuntu, Alpine, and RHEL package release naming so you do not chase false positives on backported patches.
3. **Log Compromise Scanner:** Checks `/var/log` for memory exhaustion signatures (`Unknown on line 0`) and worker segfaults (`AH00052`).
4. **Fleet Scanning:** Supports `--hosts=servers.txt` (SSH batch), `--docker` (containers and images), and `--k8s` (cluster pods).
5. **Safe Mitigation:** If you have legacy EOL boxes (PHP 7.4/8.0/8.1) that cannot be upgraded immediately, `apply` mode creates timestamped backups, runs `nginx -t` and `php-fpm -t`, and rolls back automatically on failure.

Read-only by design, zero external dependencies, no exploit code.

Repo: https://github.com/malikad778/php2shell-guard
Live Documentation: https://codebyadnan.tech/php2shell-guard/

---

## 3. r/netsec

**Title:** php2shell-guard: Open-Source Read-Only Auditor for PHP2Shell (CVE-2026-109618) and Node.js Brotli RCE

**Body:**

Hi r/netsec,

Following the public disclosure and observed pre-disclosure in-the-wild exploitation of PHP2Shell (CVE-2026-109618 & CVE-2026-109619), we released `php2shell-guard`, an open-source defensive auditor for SecOps and incident response teams.

Key design principles:
- **Strictly Read-Only:** Zero exploit code, no proof-of-concept payloads, zero external runtime dependencies.
- **Defensive Reporting (IOC7):** Adheres to forensic standards by never claiming a host is "safe" or "clean". Output is structured by evidence and confidence ratings, explicitly noting log retention and rotation limits.
- **Enterprise CI/CD Integration:** Produces SARIF 2.1.0 (for GitHub Code Scanning), JUnit XML, Markdown, CSV, and responsive HTML dashboards.
- **Dynamic Multi-Advisory Feed:** Advisory rules are decoupled into JSON definitions, allowing immediate detection updates without code changes. Covers PHP2Shell and the recent Node.js Brotli integer overflow (CVE-2026-111497).

Quick verification:
```bash
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan
```

Source and documentation:
- GitHub: https://github.com/malikad778/php2shell-guard
- Documentation: https://codebyadnan.tech/php2shell-guard/
- NPM: https://www.npmjs.com/package/php2shell-guard
- Packagist: https://packagist.org/packages/malikad/php2shell-guard

---

## 4. r/laravel

**Title:** How to Audit Your Laravel Apps and Forge/Coolify Servers for PHP2Shell (CVE-2026-109618)

**Body:**

Hey Laravel devs,

If your applications handle file uploads or use standard web SAPI setups (PHP-FPM, Octane, FrankenPHP), you should check your servers for the PHP2Shell vulnerability (CVE-2026-109618).

We created a zero-dependency package and CLI tool that integrates directly with Laravel Artisan:

```bash
# 1. Install as a dev dependency:
composer require --dev malikad/php2shell-guard

# 2. Run the audit via Artisan:
php artisan php2shell:audit
```

Or run the standalone POSIX shell script across your Laravel Forge, Coolify, or DigitalOcean droplets:
```bash
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan
```

What it does:
- Validates active PHP-FPM and web worker processes in memory.
- Warns if you updated PHP on disk but forgot to reload the worker pool (`PATCHED_NOT_RESTARTED`).
- Checks if you are running on an unpatched EOL PHP version (PHP 8.0, 8.1).
- Discovers error logs for exploitation attempts (`Allowed memory size ... exhausted in Unknown on line 0`).
- Provides Spatie Health check integration (`Malikad\Php2ShellGuard\Laravel\HealthCheck`).

GitHub: https://github.com/malikad778/php2shell-guard
Documentation: https://codebyadnan.tech/php2shell-guard/
