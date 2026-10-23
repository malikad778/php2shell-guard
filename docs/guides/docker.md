# Fixing PHP2Shell & Node2Shell in Docker Environments

1. **Update Base Image Tags**:
   - PHP: Use `php:8.5.12-*`, `php:8.4.27-*`, `php:8.3.36-*`, or `php:8.2.35-*`.
   - Node.js: Use `node:26.12.1-*`, `node:24.22.1-*`, or `node:22.23.4-*`.
2. **Beware Digest-Pinned and Floating Tags**:
   - If your `Dockerfile` uses `FROM php:8.3-fpm@sha256:...`, you must update the digest.
   - If you use floating tags (`FROM php:8.3-fpm`), run `docker build --pull --no-cache` so cached layers are not reused.
3. **Recreate Running Containers**:
   - Run `docker compose up -d --force-recreate` and verify with `php2shell-guard scan --docker` that no container reports `PATCHED_NOT_RESTARTED`.
4. **Enforce Container Memory Limits (`M3`)**:
   - Set `mem_limit: 512m` on the container combined with `php_admin_value[memory_limit] = -1` inside PHP-FPM (`M2`). Do not set `ulimits.as` or `ulimits.data`.
