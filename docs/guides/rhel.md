# Fixing PHP2Shell on RHEL, AlmaLinux, Rocky Linux & Amazon Linux

1. **Check Package Source (AppStream vs Remi)**:
   - For distro packages, inspect the RPM changelog: `rpm -q --changelog php-fpm | grep -E 'CVE-2026-109618|CVE-2026-109619'`.
   - For Remi repository packages (`php82-php-fpm`, `php83-php-fpm`, `php84-php-fpm`), upgrade to `>= 8.2.35`, `>= 8.3.36`, or `>= 8.4.27`.
2. **Upgrade and Restart**:
   ```bash
   sudo dnf upgrade -y 'php*'
   sudo systemctl restart php-fpm httpd
   ```
