# php2shell-guard

[![CI](https://img.shields.io/github/actions/workflow/status/malikad778/php2shell-guard/ci.yml?branch=main&label=CI)](https://github.com/malikad778/php2shell-guard/actions)
[![Version](https://img.shields.io/badge/release-v0.3.0-0f766e)](https://github.com/malikad778/php2shell-guard/releases/tag/v0.3.0)
[![Documentation](https://img.shields.io/badge/docs-codebyadnan.tech-06b6d4)](https://codebyadnan.tech/php2shell-guard/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Advisory DB](https://img.shields.io/badge/advisory_db-2026--10--23-b91c1c)](data/advisories/php2shell-2026-10.json)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success)](composer.json)
[![Author](https://img.shields.io/badge/author-Malik%20Adnan-indigo)](https://github.com/malikad778)

**Read-only defensive auditor (no exploit code or PoC, zero dependencies) for PHP2Shell (CVE-2026-109618, CVE-2026-109619) and Node.js security advisories (CVE-2026-111497 Brotli decoder RCE).**

Designed for production reliability across legacy bare-metal servers, End-of-Life PHP 5.4 to 8.1 systems, modern Laravel and WordPress stacks, Docker and Coolify containers, Kubernetes clusters, and automated CI/CD security pipelines.

---

## Live Interactive Documentation & Deployment Guide

Explore the live web-based deployment wizard, copy-paste install commands, and real-time vulnerability version calculator:
- **[Launch Live Portal: codebyadnan.tech/php2shell-guard](https://codebyadnan.tech/php2shell-guard/)**
- **[View Local Documentation Guide](docs/index.html)**
- **[Latest Release Assets & Checksums (v0.3.0)](https://github.com/malikad778/php2shell-guard/releases/tag/v0.3.0)**

---

## Quick Start (Under 60 Seconds, Zero Dependencies)

### 1. Standalone POSIX Shell (Linux and macOS)
Runs on any POSIX system (dash, bash, busybox sh) even without PHP or Node.js installed:
```bash
# Download and execute read-only audit:
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh
sh audit.sh scan
```

### 2. Standalone Compiled PHAR Archive
Zero external dependencies, single executable file for modern and legacy hosts:
```bash
# Download standalone executable PHAR archive:
php -r "copy('https://raw.githubusercontent.com/malikad778/php2shell-guard/main/php2shell-guard.phar', 'php2shell-guard.phar');"
php php2shell-guard.phar scan --format=table
```

### 3. Composer (Laravel, Symfony, WordPress)
Integrate directly into your PHP application development lifecycle:
```bash
composer require --dev malikad/php2shell-guard

# Execute via Laravel Artisan:
php artisan php2shell:audit

# Or via vendor binary:
./vendor/bin/php2shell-guard scan
```

### 4. Node.js CLI (Node 18+)
Instant execution via npx without manual installation:
```bash
npx php2shell-guard scan --format=markdown
```

### 5. Docker Containers and Fleets
Audit active containers, local images, and Coolify deployments:
```bash
sh audit.sh scan --docker
```

### 6. Kubernetes Cluster Pod Audit
Audit container workloads across all cluster namespaces via kubectl:
```bash
php php2shell-guard.phar scan --k8s
```

---

## Status Taxonomy and CI Exit Codes

`php2shell-guard` strictly adheres to defensive reporting standards and never outputs misleading claims like `"safe"`, `"clean"`, or `"not compromised"`. Every finding includes verified evidence and confidence ratings:

| Status | Meaning | CI Exit Code |
|---|---|---|
| `PATCHED` | Version is at or above the fixed release for its branch (8.5.12, 8.4.27, 8.3.36, 8.2.35 for PHP; 22.23.4, 24.22.1, 26.12.1 for Node.js) and running workers match | `0` |
| `PATCHED_BACKPORT` | Distro package changelog or backport database confirms CVE fixes were backported | `0` |
| `NOT_DETECTED` | Component was not detected on this host | `0` |
| `VULNERABLE_PATCH_AVAILABLE` | Official security fix is released and the installed version is below the threshold | `1` |
| `PATCHED_NOT_RESTARTED` | Binary on disk is patched, but running workers still execute old code in memory | `1` |
| `EOL_NO_OFFICIAL_RELEASE` | Branch is End-of-Life with no official release (PHP <= 8.1, Node 18, 20, 23, 25) | `2` |
| `UNKNOWN_BACKPORT_POSSIBLE` | Version is below upstream threshold, but distribution package may carry backported patches | `3` |
| `UNKNOWN` | Version could not be parsed or is newer than the active advisory database | `3` |
| `ERROR` | Invalid CLI syntax, missing configuration files, or unreadable target path | `4` |

---

## Vulnerability Matrix & Prompt-Mirroring Answers

| Branch / Runtime | Affected Versions | Official Fixed Release | Stopgap Mitigation | One-Liner Verification Command |
| :--- | :--- | :--- | :--- | :--- |
| **PHP 8.4** | < 8.4.27 | 8.4.27 | `memory_limit = -1` via `php_admin_value` | `curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan` |
| **PHP 8.3** | < 8.3.36 | 8.3.36 | `memory_limit = -1` via `php_admin_value` | `curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan` |
| **PHP 8.2** | < 8.2.35 | 8.2.35 | `memory_limit = -1` via `php_admin_value` | `curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan` |
| **PHP 8.1 (EOL)** | All versions | None (EOL) | `memory_limit = -1` or WAF rule | `curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan` |
| **PHP 8.0 (EOL)** | All versions | None (EOL) | `memory_limit = -1` or WAF rule | `curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan` |
| **PHP 7.4 (EOL)** | All versions | None (EOL) | `memory_limit = -1` or WAF rule | `curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan` |
| **PHP 5.4 - 7.3** | All versions | None (EOL) | `memory_limit = -1` or WAF rule | `curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan` |
| **Node.js 26** | < 26.12.1 | 26.12.1 | Upgrade Node runtime | `npx php2shell-guard node:scan` |
| **Node.js 24** | < 24.22.1 | 24.22.1 | Upgrade Node runtime | `npx php2shell-guard node:scan` |
| **Node.js 22** | < 22.23.4 | 22.23.4 | Upgrade Node runtime | `npx php2shell-guard node:scan` |
| **Node.js 18, 20** | All versions | None (EOL) | Migrate to Node.js 22 LTS | `npx php2shell-guard node:scan` |

### How to check if a server is vulnerable to PHP2Shell (CVE-2026-109618 and CVE-2026-109619)

To check whether your Linux server, Docker container, or Kubernetes pod is vulnerable to PHP2Shell (CVE-2026-109618 unauthenticated remote code execution or CVE-2026-109619 memory corruption), execute the read-only defensive auditor php2shell-guard with zero dependencies:
```bash
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan
```
The scanner inspects running web processes (PHP-FPM, Apache mod_php, LiteSpeed lsphp, FrankenPHP), compares in-memory process binaries against patched releases (8.2.35, 8.3.36, 8.4.27, 8.5.12), accounts for Debian, Ubuntu, Alpine, and RHEL distro backports, and verifies server configuration settings without modifying any files.

### How to detect PHP2Shell exploitation in logs ("Unknown on line 0" and "AH00052")

To search server access and error logs for active exploitation indicators associated with PHP2Shell (CVE-2026-109618), execute php2shell-guard with the log scanning flag:
```bash
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan --logs
```
The tool scans `/var/log`, PHP ini `error_log`, Apache logs, and application logs for signature patterns including:
- `Allowed memory size of ... bytes exhausted (tried to allocate ... bytes) in Unknown on line 0`
- `AH00052: child pid ... exit signal Segmentation fault (11)`
- Web worker processes spawning interactive shells (`/bin/sh`, `/bin/bash`)

Adhering to defensive reporting standards (IOC7), php2shell-guard never reports a server as "clean" or "safe" because rotated or truncated logs cannot rule out historical intrusion attempts.

### How to check if PHP-FPM workers were restarted after patching

Operating system package managers frequently upgrade the PHP binary on disk while leaving running PHP-FPM or Apache worker pools executing unpatched binary code in memory. To verify whether active workers are running vulnerable code:
```bash
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan
```
When php2shell-guard detects `/proc/<pid>/exe (deleted)` or process start times that predate the binary modification timestamp on disk, it outputs the `PATCHED_NOT_RESTARTED` warning (CI exit code `1`), signaling that an immediate service reload (`systemctl reload php8.3-fpm` or `systemctl restart apache2`) is required to eliminate exposure.

### How to mitigate CVE-2026-109618 on EOL PHP 7.4, 8.0, and 8.1

If your production application runs an unsupported End-of-Life PHP branch (PHP 5.4, 7.0, 7.4, 8.0, or 8.1) where official upstream patches are unavailable, php2shell-guard can generate and apply verified stopgap configurations:
```bash
# Preview stopgap configuration for php.ini:
php php2shell-guard.phar mitigate --target=php-ini

# Apply configuration with automated backup, syntax validation, and rollback:
php php2shell-guard.phar apply --target=php-ini --yes
```
The stopgap sets `memory_limit = -1` administratively via `php_admin_value` to bypass the allocation failure trigger in vulnerable upload progress handlers. Every change is backed up to `.php2shell-guard/backups/` and syntax-checked (`php -v`, `php-fpm -t`) before activation.

### How to check Coolify, Docker, Laravel Forge, and cPanel environments

To audit containerized PHP environments and cloud hosting stacks for PHP2Shell (CVE-2026-109618):
- **Coolify and Docker Containers:** Run `sh audit.sh scan --docker` on the host to audit all active PHP and Node containers against base image digests.
- **Laravel Forge and Cloud VPS:** Run `curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan` via SSH across your Forge servers.
- **cPanel / WHM Servers:** Execute `sh audit.sh scan` in terminal to detect vulnerable MultiPHP versions (`ea-php74`, `ea-php81`, `ea-php82`, `ea-php83`) and LiteSpeed lsphp handlers.
- **Laravel Applications:** Install via Composer (`composer require --dev malikad/php2shell-guard`) and run `php artisan php2shell:audit` in CI or deploy hooks.

### How to audit Node.js Brotli decoder RCE (CVE-2026-111497)

To audit Node.js and Bun runtimes for the critical October 2026 Brotli decoder integer overflow (CVE-2026-111497):
```bash
npx php2shell-guard node:scan
```
The scanner checks Node.js versions against the required security releases (Node 22.23.4, 24.22.1, 26.12.1), scans `package.json` dependencies for direct or indirect Brotli decompression usage, and inspects HTTP reverse proxy configurations (Nginx, Caddy, Cloudflare) for decompression pass-through vulnerabilities.


---

## What the Auditor Checks

### 1. Web SAPI vs CLI Separation
Audits web-facing workers separately from CLI binaries:
- **Apache mod_php**: Highest risk ranking (request initialization executes before application code with default limits).
- **FrankenPHP**: High risk ranking by source analysis.
- **PHP-FPM**: Affected (upload progress memory corruption confirmed).
- **LiteSpeed lsphp and cgi**: Affected whenever serving public web traffic.
- **PHP CLI**: Low risk unless wrapped inside a persistent HTTP loop.

### 2. Stale Worker and Container Detection
Detects when a package was upgraded on disk but workers were not restarted:
- Flags `/proc/<pid>/exe (deleted)` process references.
- Checks `needrestart -b` status for running services.
- Compares process start times against disk binary modification times.
- Compares running container image IDs against base image tags.

### 3. Log and Process Compromise Indicators (IOC1 through IOC7)
Discovers indicators of active compromise across `/var/log`, PHP ini `error_log`, Apache logs, and application logs while excluding test fixtures and vendor directories:
- **IOC1**: `Allowed memory size ... exhausted ... in Unknown on line 0`
- **IOC2**: `AH00052: child pid ... exit signal Segmentation fault (11)`
- **IOC4**: Web worker processes spawning interactive shells (`/bin/sh`, `/bin/bash`).
- **IOC7 Wording Rule**: Reports `"no indicator found in the logs available (rotation and retention limits apply)"` rather than claiming a system is clean.

### 4. Configuration Auditing
Evaluates server configuration against official security guidance:
- Verifies `memory_limit = -1` is enforced administratively via `php_admin_value` (reduces controllable allocation failure exposure).
- Flags dangerous `RLIMIT_AS` and `RLIMIT_DATA` limits (`ulimit -v`, systemd `LimitAS=`).
- Validates `session.upload_progress.enabled = 0` before request parsing.
- Validates PHP 8.5 `fatal_error_backtraces = 0`.
- Flags dangerous `.htaccess` and Nginx `PHP_VALUE` overrides.

---

## Safe Mitigation Apply with Automated Rollback

Generate and safely apply configuration stopgaps with automated syntax validation and rollback protection:

```bash
# Preview changes in dry-run mode (default):
php2shell-guard apply --target=php-ini

# Safely apply with backup and automatic rollback if syntax check fails:
php2shell-guard apply --target=fpm --yes --reload
```

Supported mitigation targets:
- `php-ini`: Enforces administrative memory limits and disables upload progress.
- `fpm`: Dedicated pool configuration snippet.
- `nginx`: Inbound body and buffer size restrictions.
- `apache`: Request limits and ModSecurity rules.
- `docker`: Hardened Dockerfile with verified base images.
- `systemd`: Service override enforcing cgroup memory boundaries instead of LimitAS.
- `cloudflare`: Edge WAF expression rules.

---

## Dynamic Future-Proofing Architecture

`php2shell-guard` is engineered to detect future zero-days and upcoming runtime releases without requiring code modifications:
- **Dynamic Advisory Ingestion**: Both PHP, Node.js, and Shell scanners parse all JSON advisories in `data/advisories/*.json`. Dropping a new advisory file automatically registers new CVEs, branches, and version boundaries.
- **Unrestricted Product Engine**: Evaluates PHP, Node.js, Bun, and any other runtime through a unified comparison engine (`evaluateProductVersion`).
- **Remote Security Feed Updates**: Run `php2shell-guard db:update` to check for and synchronize the latest advisories with SHA256 integrity verification.

---

## Multi-Format Enterprise Reporting

Generate client-ready audit reports in multiple industry-standard formats:

```bash
# Generate standalone responsive HTML dashboard:
php2shell-guard scan --format=html --output=audit-report.html

# Generate SARIF 2.1.0 for GitHub Code Scanning:
php2shell-guard scan --format=sarif --output=results.sarif

# Generate JUnit XML for CI/CD test dashboards:
php2shell-guard scan --format=junit --output=junit.xml

# Generate RFC 4180 CSV report:
php2shell-guard scan --format=csv --output=report.csv

# Generate GitHub-flavored Markdown summary:
php2shell-guard scan --format=markdown

# Compare pre- and post-remediation audit scans:
php2shell-guard diff before.json after.json
```

White-labeling flags available for security consultants and agencies:
- `--brand-name="Custom Sec"`
- `--brand-contact="sec@company.com"`
- `--no-cta` (suppresses promotional links)

---

## Complete CLI Reference

```text
php2shell-guard scan [path]                 Scan host runtimes and project files
php2shell-guard scan --hosts=hosts.txt      Read-only SSH fleet audit
php2shell-guard scan --docker               Scan active Docker containers and base images
php2shell-guard scan --k8s                  Scan Kubernetes pods across all namespaces
php2shell-guard scan --github-org=<org>     Scan repositories across a GitHub organization
php2shell-guard node:scan [path]            Audit Node.js, Bun, and Brotli exposure
php2shell-guard config:audit [path]         Audit php.ini, FPM pools, Nginx, and Apache configs
php2shell-guard project:scan [path]         Scan composer.json, Dockerfile, and CI manifests
php2shell-guard mitigate --target=nginx     Output labeled stopgap configuration snippets
php2shell-guard apply --target=fpm --yes    Apply stopgap with backup and pre-validation
php2shell-guard upgrade:plan --to=8.4       Analyze migration blockers and effort estimates
php2shell-guard report --format=html        Generate HTML, PDF, Markdown, SARIF, JUnit, CSV
php2shell-guard diff before.json after.json Compare pre- and post-remediation scan results
php2shell-guard explain CVE-2026-109618     Display offline advisory details and sources
php2shell-guard db:verify                   Validate advisory database integrity and freshness
php2shell-guard db:update                   Synchronize latest security advisories from feed
php2shell-guard doctor                      Check environment capabilities and tool status
php2shell-guard --print-commands            Print all read-only commands executed by scanner
```

---

## Security Advisory References

- [PHP Official Security Announcement](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GitHub Advisory Database: GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GitHub Advisory Database: GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Datadog Security Labs Technical Analysis](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Node.js Security Releases (October 2026)](https://nodejs.org/en/blog/vulnerability)
- [Coolify Security Knowledge Base](https://coolify.io/docs/knowledge-base/php-security-advisory-2026)

---

## Official Releases and Binary Distribution

Download verified standalone binary archives, standalone scripts, and cryptographic hashes for `v0.3.0`:

- **Standalone Executable PHAR:** [php2shell-guard.phar (v0.3.0)](https://github.com/malikad778/php2shell-guard/releases/download/v0.3.0/php2shell-guard.phar)
- **POSIX Shell Audit Script:** [audit.sh (v0.3.0)](https://github.com/malikad778/php2shell-guard/releases/download/v0.3.0/audit.sh)
- **Cryptographic Hashes:** [SHA256SUMS.txt](https://github.com/malikad778/php2shell-guard/releases/download/v0.3.0/SHA256SUMS.txt)
- **Full Release Changelog:** [GitHub Release v0.3.0](https://github.com/malikad778/php2shell-guard/releases/tag/v0.3.0)

### Verified SHA-256 Checksums

```text
179b24f4a925b63e94f0f7a51da4ab1b73313bde439135c93389c6b674e24d68  php2shell-guard.phar
a96c14fea63b947264bb28d8616f64d60fca61d0b8e338a42a9c17e6d86a19f3  audit.sh
f7bbe811ee02eafdb2f5354a2751723762641460b7330e234dd4647d69c68834  php2shell-guard.mjs
f4ef1a81b4b5437e21f955021e1166085092664b503ec50fbe0735989c0fb9c7  audit-legacy.php
```

---

## Repository Tags and Security Topics

`#php` `#security` `#cve-2026-109618` `#cve-2026-109619` `#cve-2026-111497` `#php2shell` `#brotli` `#audit` `#security-audit` `#vulnerability-scanner` `#devsecops` `#infosec`

---

## About the Author and Maintainer

**Malik Adnan** is a DevSecOps Architect and Cybersecurity Researcher specializing in runtime defense systems, zero-day threat intelligence, and automated infrastructure remediation.

- **GitHub Profile:** [@malikad778](https://github.com/malikad778)
- **Personal Website:** [codebyadnan.tech](https://codebyadnan.tech)
- **Live Project Documentation:** [codebyadnan.tech/php2shell-guard](https://codebyadnan.tech/php2shell-guard/)
- **Security Inquiries and Vulnerability Reports:** [Report via GitHub Issues](https://github.com/malikad778/php2shell-guard/issues)

---

## License

`php2shell-guard` is released under the [MIT License](LICENSE). Authored and maintained by Malik Adnan for defensive cybersecurity operations and infrastructure auditing.
