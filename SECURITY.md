# Security Policy

## Scope and Principles

`php2shell-guard` is a read-only runtime, configuration, and infrastructure-as-code auditor for PHP (CVE-2026-109618, CVE-2026-109619) and Node.js (October 2026 security release including CVE-2026-111497).

- **Zero runtime dependencies**: The core shell, PHP, and Node.js scanners require zero third-party packages.
- **No network calls by default**: The scanner runs 100% offline using its bundled `data/advisories/*.json` database. Network requests occur only when you explicitly invoke `db:update` or `--github-org`.
- **Read-only by default**: No system file is modified unless you explicitly run `apply --apply --yes`, which creates timestamped backups in `.php2shell-guard/backups/` and validates configurations (`php-fpm -t`, `nginx -t`) before reloading.
- **No exploit payloads**: This repository contains zero exploit code, zero PoCs, and never sends crafted packets.

## Reporting a Vulnerability

If you discover a security issue in `php2shell-guard` itself or an inaccuracy in `data/advisories/*.json`, please report it privately:

- **Contact**: `security@webwhizy.com` or via GitHub Private Vulnerability Reporting at `https://github.com/malikad778/php2shell-guard/security/advisories/new`.
- **Response target**: Acknowledgment within 24 hours; verified database or code fixes released within 48 hours.
