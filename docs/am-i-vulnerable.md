# Am I Vulnerable to PHP2Shell (CVE-2026-109618 & CVE-2026-109619) or Node2Shell (CVE-2026-111497)?

## 60-Second Decision Tree

### Step 1: Check the Web-Facing PHP SAPI (Not Just `php -v`)

Many servers run a different PHP binary for web traffic (`php-fpm`, Apache `mod_php`, FrankenPHP, `lsphp`, `php-cgi`) than what `php -v` prints on the CLI.

| Installed Web PHP Version | Branch Status | Fixed Version | Your Status |
|---|---|---|---|
| `>= 8.5.12` | Active | `8.5.12` | `PATCHED` (only after all workers/containers are restarted) |
| `8.5.0` to `8.5.11` | Active | `8.5.12` | `VULNERABLE_PATCH_AVAILABLE` |
| `>= 8.4.27` | Active | `8.4.27` | `PATCHED` (only after all workers/containers are restarted) |
| `8.4.0` to `8.4.26` | Active | `8.4.27` | `VULNERABLE_PATCH_AVAILABLE` |
| `>= 8.3.36` | Active | `8.3.36` | `PATCHED` (only after all workers/containers are restarted) |
| `8.3.0` to `8.3.35` | Active | `8.3.36` | `VULNERABLE_PATCH_AVAILABLE` |
| `>= 8.2.35` | Security Support | `8.2.35` | `PATCHED` (only after all workers/containers are restarted) |
| `8.2.0` to `8.2.34` | Security Support | `8.2.35` | `VULNERABLE_PATCH_AVAILABLE` |
| `8.1.x`, `8.0.x`, `7.4.x` | End of Life (EOL) | No official release | `EOL_NO_OFFICIAL_RELEASE` (Upstream published minimal source backports; check distro/vendor build) |
| `<= 7.3.x` (back to `5.4.0`) | End of Life (EOL) | None | `EOL_NO_OFFICIAL_RELEASE` |

### Step 2: Did You Restart Workers and Rebuild Containers After Patching?

Updating a package on disk or pulling a new Docker image tag does **not** replace the code already loaded in running `php-fpm`, Apache, or container processes. If `/proc/<pid>/exe` points to a `(deleted)` binary or the process started before the package upgrade, your host is `PATCHED_NOT_RESTARTED` and remains exposed until every worker is restarted or replaced.

### Step 3: What SAPI Serves Requests?

- **Apache `mod_php` & FrankenPHP**: Rated highest risk by PHP's advisory because the vulnerable code path executes during request startup before any application script runs, and was demonstrated under default memory and input limits.
- **PHP-FPM, `php-cgi`, LiteSpeed (`lsphp`)**: Also affected (the `session.upload_progress` path for CVE-2026-109619 is confirmed on PHP-FPM).

### Step 4: Check Node.js Runtimes (October 2026 Release)

| Node.js Branch | Fixed Version | Status Below Fixed Version |
|---|---|---|
| `26.x` | `26.12.1` | `VULNERABLE_PATCH_AVAILABLE` |
| `24.x` | `24.22.1` | `VULNERABLE_PATCH_AVAILABLE` |
| `22.x` | `22.23.4` | `VULNERABLE_PATCH_AVAILABLE` |
| `18.x`, `20.x`, `23.x`, `25.x` | None (EOL) | `EOL_NO_OFFICIAL_RELEASE` |

## What If I Cannot Upgrade Today?

No configuration change fully blocks attacks. While you prepare a runtime upgrade or migration:

1. **M2 (Official, partial - covers CVE-2026-109618)**: Enforce `memory_limit = -1` administratively (`php_admin_value[memory_limit] = -1` in every FPM pool or `php_admin_value memory_limit -1` in Apache vhost config) so scripts cannot restore a finite limit.
2. **M3 (Official - companion to M2)**: Bound memory via container `mem_limit` or systemd cgroup `MemoryMax`. Never use `RLIMIT_AS` (`ulimit -v`, `LimitAS=`) or `RLIMIT_DATA` (`LimitDATA=`), which cause the exact in-process allocation failures the bug depends on.
3. **M4 (Official guidance)**: Enforce strict frontend request body size limits (`client_max_body_size 8m`, `LimitRequestBody 8388608`, `post_max_size = 8M`).
4. **M5 & M6 (Official, partial - covers CVE-2026-109619)**: Set `session.upload_progress.enabled = 0` (and `fatal_error_backtraces = 0` on PHP 8.5) in startup configuration loaded before request parsing, and restart all workers.
5. **M7 (Official)**: Remove `.htaccess` `php_value`/`php_flag` directives and Nginx `fastcgi_param PHP_VALUE`/`PHP_ADMIN_VALUE` overrides that can emit early startup diagnostics.
