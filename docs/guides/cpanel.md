# Fixing PHP2Shell on cPanel / WHM (EasyApache 4)

1. **Audit All `ea-php*` Packages**:
   - EasyApache installs multiple PHP versions under `/opt/cpanel/ea-php*/root/usr/bin/php`.
   - Run `php2shell-guard scan` to enumerate all installed `ea-php` binaries and FPM pools.
2. **Update EasyApache Packages**:
   - Run `yum update 'ea-php*'` or `dnf upgrade 'ea-php*'`, then restart Apache (`httpd`) and `ea-php*-php-fpm`.
3. **Check `.htaccess` Overrides (`M7`)**:
   - Under `mod_php`, customer `.htaccess` files with `php_value` or `php_flag` can trigger early request startup diagnostics. Prefer PHP-FPM with `php_admin_value[memory_limit] = -1`.
