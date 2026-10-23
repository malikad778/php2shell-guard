# Fixing PHP2Shell on Ubuntu & Debian

1. **Identify Package Origin (`apt-cache policy`)**:
   - Official Ubuntu/Debian archive packages backport fixes into stable version numbers (check via `apt changelog php8.2-fpm | grep -E 'CVE-2026-109618|CVE-2026-109619'`).
   - Systems using Ondrej Sury PPA (`ppa:ondrej/php` / `packages.sury.org`) track upstream versions (`8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`).
2. **Upgrade and Restart**:
   ```bash
   sudo apt-get update
   sudo apt-get install --only-upgrade 'php*'
   sudo systemctl restart php8.3-fpm apache2
   ```
3. **Verify Workers Restarted**:
   - Run `php2shell-guard scan` to confirm no worker reports `PATCHED_NOT_RESTARTED`.
