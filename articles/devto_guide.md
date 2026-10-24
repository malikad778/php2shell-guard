---
title: "How to Check and Mitigate PHP2Shell (CVE-2026-109618 & CVE-2026-109619) on Linux, Docker, and EOL PHP"
published: true
tags: php, security, devsecops, webdev
canonical_url: https://codebyadnan.tech/php2shell-guard/
---

PHP2Shell (CVE-2026-109618 and CVE-2026-109619) is an unauthenticated remote code execution vulnerability in PHP core file upload progress tracking. It affects major server implementations including PHP-FPM, Apache mod_php, LiteSpeed lsphp, and FrankenPHP.

In the wild, exploitation was observed prior to disclosure. While official security updates are available for active branches, real-world fleet remediation presents complex challenges:
1. Long-running worker processes often remain un-restarted after package updates, executing vulnerable binaries in memory.
2. Distribution packages (Debian, Ubuntu, Alpine, RHEL) frequently backport patches without changing upstream version numbers, producing false positive alerts.
3. Unsupported End-of-Life branches (PHP 5.4, 7.0, 7.4, 8.0, 8.1) receive no upstream patches.

To provide infrastructure and security teams with an instant, verified assessment, we authored `php2shell-guard`, a read-only defensive auditor with zero dependencies and no exploit code or PoC.

Here is the exact guide to auditing and mitigating your infrastructure.

---

## Instant Read-Only Verification (Under 60 Seconds)

To verify whether your server, container, or fleet is vulnerable, run the POSIX one-liner:

```bash
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan
```

The script runs on any POSIX system (Linux, macOS, WSL) using standard core utilities (dash, bash, busybox sh) even if PHP or Node.js is not installed.

### Alternative Installation Channels
- **Standalone PHAR (PHP 5.4 - 8.4+):**
  ```bash
  php -r "copy('https://raw.githubusercontent.com/malikad778/php2shell-guard/main/php2shell-guard.phar', 'php2shell-guard.phar');"
  php php2shell-guard.phar scan --format=table
  ```
- **NPM Package (Node.js 18+):**
  ```bash
  npx php2shell-guard scan
  ```
- **Packagist / Composer (Laravel, WordPress, Symfony):**
  ```bash
  composer require --dev malikad/php2shell-guard
  php artisan php2shell:audit
  ```

---

## Vulnerability Matrix by PHP Branch

| Runtime Branch | Affected Versions | Official Fixed Release | Mitigation Action |
| :--- | :--- | :--- | :--- |
| **PHP 8.4** | < 8.4.27 | **8.4.27** | Upgrade packages and restart FPM / Apache workers |
| **PHP 8.3** | < 8.3.36 | **8.3.36** | Upgrade packages and restart FPM / Apache workers |
| **PHP 8.2** | < 8.2.35 | **8.2.35** | Upgrade packages and restart FPM / Apache workers |
| **PHP 8.1** | All versions | None (EOL) | Apply stopgap: `memory_limit = -1` via `php_admin_value` |
| **PHP 8.0** | All versions | None (EOL) | Apply stopgap: `memory_limit = -1` via `php_admin_value` |
| **PHP 7.4** | All versions | None (EOL) | Apply stopgap: `memory_limit = -1` via `php_admin_value` |
| **PHP 5.4 - 7.3** | All versions | None (EOL) | Apply stopgap: `memory_limit = -1` via `php_admin_value` |

---

## How to Detect PHP2Shell Exploitation in Server Logs

To check server access and error logs for active exploitation attempts:

```bash
curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan --logs
```

The auditor discovers log files across `/var/log`, PHP ini `error_log`, Apache logs, and application logs while excluding test fixtures and vendor directories. It matches signature indicators:

- `Allowed memory size of ... bytes exhausted (tried to allocate ... bytes) in Unknown on line 0`
- `AH00052: child pid ... exit signal Segmentation fault (11)`
- Web worker processes spawning interactive shells (`/bin/sh`, `/bin/bash`)

In compliance with defensive reporting standards (IOC7), `php2shell-guard` never reports a system as "clean" or "safe" because rotated or truncated logs cannot prove the absence of prior exploitation.

---

## How to Check If Workers Were Restarted After Patching

When an apt, dnf, or apk update completes, the on-disk binary is replaced, but running daemon processes continue executing the old binary from RAM.

`php2shell-guard` checks active `/proc/<pid>/exe` references and compares process launch timestamps against disk binaries:
- If running processes execute deleted inode pointers, it outputs status `PATCHED_NOT_RESTARTED` with exit code `1`.
- Remediation:
  ```bash
  systemctl reload php8.3-fpm
  # or
  systemctl restart apache2
  ```

---

## How to Mitigate CVE-2026-109618 on EOL PHP

If upgrading to an officially patched release is not possible today, you can generate and apply verified stopgap configurations:

```bash
# Preview changes in dry-run mode:
php php2shell-guard.phar mitigate --target=php-ini

# Apply configuration with automated backup and syntax pre-validation:
php php2shell-guard.phar apply --target=php-ini --yes
```

The mitigation sets `memory_limit = -1` administratively via `php_admin_value` to bypass the memory allocation failure condition in upload progress tracking.

Every modification is saved to `.php2shell-guard/backups/<timestamp>/`. Syntax tests (`php -v`, `php-fpm -t`, `nginx -t`, `apache2ctl -t`) execute prior to activation, triggering an immediate automated rollback if syntax fails.

---

## Cloud Ecosystems: Coolify, Docker, Forge, and cPanel

- **Docker & Coolify:** Run `sh audit.sh scan --docker` to scan container base images and inspect active worker states.
- **Laravel Forge & Cloud VPS:** Run `curl -fsSLO https://raw.githubusercontent.com/malikad778/php2shell-guard/main/bin/audit.sh && sh audit.sh scan` via SSH.
- **cPanel / WHM:** Run `sh audit.sh scan` in terminal to detect vulnerable MultiPHP versions (`ea-php74`, `ea-php81`, `ea-php82`, `ea-php83`) and LiteSpeed lsphp handlers.

---

## Resources & Links

- **GitHub Repository:** https://github.com/malikad778/php2shell-guard
- **Live Documentation Portal:** https://codebyadnan.tech/php2shell-guard/
- **NPM Package:** https://www.npmjs.com/package/php2shell-guard
- **Packagist:** https://packagist.org/packages/malikad/php2shell-guard
- **Release Assets:** https://github.com/malikad778/php2shell-guard/releases/tag/v0.3.1
