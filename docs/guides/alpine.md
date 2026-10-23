# Fixing PHP2Shell on Alpine Linux

1. **Upgrade APK Packages**:
   ```sh
   apk update
   apk upgrade 'php82*' 'php83*' 'php84*' 'nodejs*'
   ```
2. **Restart Services or Rebuild Container**:
   - On bare Alpine hosts: `rc-service php-fpm83 restart`
   - In Docker containers: rebuild the image from `php:8.3.36-fpm-alpine` or `alpine:3.21` and redeploy.
