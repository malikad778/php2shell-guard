# Contributing to php2shell-guard

Thank you for helping keep `php2shell-guard` accurate, transparent, and dependency-free.

## Rules for Contributions

1. **Two-Source Rule for Advisory Data**: Every version threshold or backport entry in `data/advisories/*.json` and `data/backports/*.json` must cite at least two independent primary or vendor sources, include a `last_verified` date (`YYYY-MM-DD`), and validate against `data/schema/advisory.schema.json`.
2. **Confidence Labels on Mitigations**: Every mitigation must carry one of the four confidence labels (`official`, `official-partial`, `vendor-reported`, `reasoning-based`) and state `"This does not replace patching."`
3. **Strict Wording**: Never output `"safe"`, `"clean"`, or `"not compromised"` in any scanner, report template, or test fixture. Indicator scans must report `"indicator found"` or `"no indicator found in the logs available (rotation and retention limits apply)"`.
4. **Zero Runtime Dependencies**: Do not add runtime packages to `composer.json` or `package.json`.
5. **PHP 5.4 Compatibility for `bin/audit-legacy.php`**: Changes to `bin/audit-legacy.php` must pass `php -l` on PHP 5.4 through 8.5.
6. **ASCII Punctuation in Code Comments**: Avoid em dashes and en dashes in code comments across all shell, PHP, and JavaScript files.

## Running Tests

```bash
# Run POSIX shell test suite (bash and dash)
sh tests/shell/test_audit_sh.sh

# Run Node.js built-in test runner
node --test tests/node/cli.test.mjs

# Validate advisory JSON files and schema
node bin/php2shell-guard.mjs db:verify
```
