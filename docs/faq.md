# Frequently Asked Questions (FAQ)

## Why does `php -v` show 8.3.36 (Patched), while `php2shell-guard` reports `EOL_NO_OFFICIAL_RELEASE` or `VULNERABLE_PATCH_AVAILABLE`?

On multi-PHP servers (Ubuntu Ondrej PPA, Debian Sury, RHEL Remi, cPanel EasyApache, Laravel Forge, Plesk), `/usr/bin/php` (CLI) is often updated or switched via `update-alternatives`, while Nginx or Apache continues forwarding web traffic to `/run/php/php8.1-fpm.sock` or loading `libphp8.1.so`. Web traffic is what exposes CVE-2026-109618 and CVE-2026-109619, so `php2shell-guard` audits the web-facing SAPI separately from CLI.

## Why does the tool return `UNKNOWN_BACKPORT_POSSIBLE` on Debian, Ubuntu, or RHEL?

Linux distributions backport security patches into the version of PHP or Node.js shipped with that OS release (for example, Ubuntu 22.04 ships `8.1.2-1ubuntu2.xx`). Comparing `8.1.2` against `8.2.35` without checking the distro changelog would trigger a false alarm. When changelog inspection cannot confirm the CVE IDs locally, `php2shell-guard` reports `UNKNOWN_BACKPORT_POSSIBLE` (exit code 3) and prints the command to verify your package changelog.

## Why does `php2shell-guard` never say a server is "safe" or "clean"?

1. **Runtime patches require restarts**: Even with a patched binary on disk, un-restarted workers or un-rebuilt containers keep vulnerable code in memory.
2. **Stopgaps are partial**: `memory_limit=-1` and `session.upload_progress.enabled=0` close specific paths described in the PHP advisory, not every way an out-of-memory or stale-state condition can be reached.
3. **Exploitation can be silent**: As documented by Datadog Security Labs, a successful exploit does not have to crash a worker, write to `error_log`, or alter the HTTP status code. Finding no log indicators means `"no indicator found in the logs available (rotation and retention limits apply)"`, never `"not compromised"`.
