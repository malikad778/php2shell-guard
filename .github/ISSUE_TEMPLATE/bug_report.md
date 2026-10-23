---
name: Bug Report / False Positive
about: Report a false positive, distro backport edge case, or parser bug
title: "[BUG] "
labels: bug
---

## Environment
- OS / Distro (`/etc/os-release`):
- PHP / Node version string (`php -v`, `php-fpm -v`, `node -v`):
- Package origin (`apt-cache policy`, `rpm -qi`, Docker image tag):

## Expected vs Actual Output
Paste the sanitized output of `php2shell-guard scan --format json`:
