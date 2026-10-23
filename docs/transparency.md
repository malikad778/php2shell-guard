# Scanner Transparency & Read-Only Command Whitelist

`php2shell-guard` is designed for high-trust production environments. You can inspect every command the tool would run on your machine without executing anything by passing `--print-commands`.

## Commands Executed in Read-Only Scan Mode

| Category | Command / File Read | Purpose |
|---|---|---|
| PHP CLI detection | `php -v`, `php --ini`, `php -i` | Determine CLI version, loaded `php.ini`, and effective INI values |
| PHP-FPM detection | `php-fpm -v`, `php-fpm8.x -v`, `php-fpm -tt` | Determine web-facing FPM version and pool `php_admin_value` settings |
| Apache / SAPI detection | `apache2ctl -M`, `httpd -M`, `lsphp -v`, `frankenphp version` | Detect `mod_php`, MPM mode, LiteSpeed, or FrankenPHP |
| Stale worker detection | `ps -eo pid,ppid,lstart,comm,args`, `/proc/<pid>/exe`, `/proc/<pid>/limits` | Check if running workers still use a deleted/pre-patch binary or finite `Max address space` (`RLIMIT_AS`) |
| Distro & backports | `/etc/os-release`, `dpkg-query -W`, `rpm -q --changelog`, `apk info`, `/usr/share/doc/*/changelog.Debian.gz` | Check whether a distribution package backported fixes for `CVE-2026-109618` and `CVE-2026-109619` |
| Node / Bun detection | `node -v`, `node -p 'JSON.stringify({versions:process.versions,variables:process.config.variables})'`, `bun --version` | Detect Node.js version, bundled vs shared Brotli (`node_shared_brotli`), and Brotli version |
| Docker / Coolify | `docker ps`, `docker inspect` (opt-in via `--docker`) | Check running container images, image IDs vs tags, `MemLimit`, and Coolify version |
| Indicator checks | Read-only grep on configured PHP `error_log`, Apache `ErrorLog`, and `ps` tree | Look for `Unknown on line 0` memory exhaustion, `AH00052` segfaults, and shells under web workers |

## Network Calls Policy

- Default scan (`scan`, `config:audit`, `project:scan`, `node:scan`, `mitigate`, `explain`, `report`, `upgrade:plan`): **Zero network calls**.
- `db:update`: Connects only to `https://raw.githubusercontent.com/malikad778/php2shell-guard/main/data/` to fetch updated advisory JSON and verify SHA-256 checksums.
