# Changelog

All notable changes to `php2shell-guard` are documented in this file.

## [0.3.0] - 2026-10-23
### Added
- `apply` mode with automatic backups to `.php2shell-guard/backups/<timestamp>`, syntax validation (`php-fpm -t`, `nginx -t`), and automatic rollback on failure (F7).
- Ansible playbook generator (`mitigate --target ansible`) and Kubernetes kustomize patch template (F8, F10).
- Upgrade planner (`upgrade:plan --to 8.3`) with Composer blocker detection, Laravel compatibility matrix, PHP 8.x breakage heuristic scanner, and S/M/L/XL effort estimator (J1-J8).
- Diff reporter (`diff before.json after.json`) and white-label HTML/PDF reporting (`--brand-name`, `--brand-logo`, `--brand-contact`) (G6, G9, G12).
- Offline distro backport lookup table (`data/backports/distro-backports.json`) for Debian, Ubuntu, RHEL/Alma/Rocky, and Alpine (E4-E7).
- Watch mode (`watch --notify slack|webhook`) and GitHub org scanner (`scan --github-org`) (H4, H11).

## [0.2.0] - 2026-10-23
### Added
- Modular PHP engine (`src/*`), Composer package (`malikad/php2shell-guard`), Laravel ServiceProvider and `php artisan php2shell:audit` command, and Spatie Laravel Health check (I1-I3).
- WordPress mu-plugin (`src/WordPress/php2shell-guard-mu.php`) with Site Health integration and WP-CLI `wp php2shell status` command (I6).
- Log and process indicator scanner (`IOC1` Unknown on line 0 OOM, `IOC2` Apache `AH00052` segfaults, `IOC3` large form-urlencoded POSTs, `IOC4` web worker child shells, `IOC6` `--collect-evidence`, `IOC7` strict wording) (Section N).
- Node.js CLI (`bin/php2shell-guard.mjs`) with `process.versions.brotli` inspection, shared-Brotli build flag check, and Brotli code/dependency exposure scanning (A7, D1-D6).
- Coolify container & version detector (`H9`) warning that updating Coolify does not rebuild deployed application containers.
- SSH fleet scanner (`scan --hosts hosts.txt`) and Docker host container scanner (`scan --docker`) (H2, H8, C11).

## [0.1.0] - 2026-10-23
### Added
- Zero-dependency POSIX shell scanner (`bin/audit.sh`) and PHP 5.4-compatible single-file scanner (`bin/audit-legacy.php`).
- Separate CLI vs web-facing SAPI detection (`php-fpm`, `mod_php`, `frankenphp`, `php-cgi`, `lsphp`), SAPI risk ranking, and stale worker detection (`PATCHED_NOT_RESTARTED`).
- Bundled offline advisory database for PHP2Shell (`CVE-2026-109618`, `CVE-2026-109619`) and Node.js October 2026 security release (`CVE-2026-111497` + 9 CVEs).
- `php.ini`, FPM pool, Nginx, Apache, and systemd `RLIMIT_AS`/`RLIMIT_DATA` configuration auditing (`memory_limit=-1` via `php_admin_value`, `session.upload_progress.enabled=0`, `fatal_error_backtraces=0`).
- Project and IaC scanner (`composer.json`, `composer.lock`, `Dockerfile`, `docker-compose.yml`, `.nvmrc`, `.php-version`, `package.json`, GitHub Actions, Kubernetes manifests).
