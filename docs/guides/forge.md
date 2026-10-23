# Fixing PHP2Shell on Laravel Forge Servers

1. **Upgrade PHP via Forge UI or CLI**:
   - Ensure each site is assigned to PHP 8.2 (`>= 8.2.35`), 8.3 (`>= 8.3.36`), or 8.4 (`>= 8.4.27`).
   - Run `sudo apt-get update && sudo apt-get install --only-upgrade 'php8.*'` on the host.
2. **Restart Every PHP-FPM Service & Horizon / Octane Workers**:
   - `sudo systemctl restart php8.3-fpm php8.4-fpm`
   - `php artisan horizon:terminate` and `php artisan octane:reload`
3. **Audit Multi-Version Remnants**:
   - Forge servers frequently retain older `php8.0-fpm` or `php8.1-fpm` daemons listening on sockets. Run `php2shell-guard scan` to spot any active EOL FPM pools.
