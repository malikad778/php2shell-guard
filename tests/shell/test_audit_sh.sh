#!/bin/sh
# POSIX shell test suite for bin/audit.sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
AUDIT_SH="$ROOT_DIR/bin/audit.sh"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# 1. Test PATCHED PHP and PATCHED Node (exit code 0)
set +e
OUT=$(PHP2SHELL_MOCK_PHP_FPM_VERSION="8.3.36" PHP2SHELL_MOCK_PHP_CLI_VERSION="8.3.36" PHP2SHELL_MOCK_NODE_VERSION="22.23.4" sh "$AUDIT_SH" scan --format json --no-cta)
CODE=$?
set -e
[ "$CODE" -eq 0 ] || fail "Expected exit code 0 for patched versions, got $CODE"
echo "$OUT" | grep -q '"status": "PATCHED"' || fail "Expected PATCHED status in JSON output"

# 2. Test VULNERABLE_PATCH_AVAILABLE (exit code 1)
set +e
OUT=$(PHP2SHELL_MOCK_PHP_FPM_VERSION="8.3.35" PHP2SHELL_MOCK_PHP_CLI_VERSION="8.3.36" PHP2SHELL_MOCK_NODE_VERSION="22.23.4" sh "$AUDIT_SH" scan --format json --no-cta)
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "Expected exit code 1 for vulnerable 8.3.35, got $CODE"
echo "$OUT" | grep -q '"status": "VULNERABLE_PATCH_AVAILABLE"' || fail "Expected VULNERABLE_PATCH_AVAILABLE"

# 3. Test PATCHED_NOT_RESTARTED (exit code 1)
set +e
OUT=$(PHP2SHELL_MOCK_PHP_FPM_VERSION="8.4.27" PHP2SHELL_MOCK_STALE_WORKER="1" PHP2SHELL_MOCK_NODE_VERSION="24.22.1" sh "$AUDIT_SH" scan --format json --no-cta)
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "Expected exit code 1 for PATCHED_NOT_RESTARTED, got $CODE"
echo "$OUT" | grep -q '"status": "PATCHED_NOT_RESTARTED"' || fail "Expected PATCHED_NOT_RESTARTED"

# 4. Test EOL_NO_OFFICIAL_RELEASE (exit code 2)
set +e
OUT=$(PHP2SHELL_MOCK_PHP_FPM_VERSION="8.1.29" PHP2SHELL_MOCK_PHP_CLI_VERSION="8.3.36" PHP2SHELL_MOCK_NODE_VERSION="22.23.4" sh "$AUDIT_SH" scan --format json --no-cta)
CODE=$?
set -e
[ "$CODE" -eq 2 ] || fail "Expected exit code 2 for EOL PHP 8.1.29, got $CODE"
echo "$OUT" | grep -q '"status": "EOL_NO_OFFICIAL_RELEASE"' || fail "Expected EOL_NO_OFFICIAL_RELEASE"

# 5. Test UNKNOWN_BACKPORT_POSSIBLE (exit code 3)
set +e
OUT=$(PHP2SHELL_MOCK_PHP_FPM_VERSION="8.1.2-1ubuntu2.14" PHP2SHELL_MOCK_PHP_CLI_VERSION="8.3.36" PHP2SHELL_MOCK_NODE_VERSION="22.23.4" sh "$AUDIT_SH" scan --format json --no-cta)
CODE=$?
set -e
[ "$CODE" -eq 3 ] || fail "Expected exit code 3 for distro package 8.1.2-1ubuntu2.14, got $CODE"
echo "$OUT" | grep -q '"status": "UNKNOWN_BACKPORT_POSSIBLE"' || fail "Expected UNKNOWN_BACKPORT_POSSIBLE"

# 6. Test mitigate snippet output and confidence header
MIT_OUT=$(sh "$AUDIT_SH" mitigate --target fpm)
echo "$MIT_OUT" | grep -q "This does not replace patching." || fail "Mitigation snippet missing mandatory disclaimer"
echo "$MIT_OUT" | grep -q "php_admin_value\[memory_limit\] = -1" || fail "FPM snippet missing memory_limit=-1"

# 7. Test explain command
EXP_OUT=$(sh "$AUDIT_SH" explain CVE-2026-109618)
echo "$EXP_OUT" | grep -q "CVSS v4.0 9.2" || fail "explain output missing CVSS"

# 8. Assert output never uses forbidden words ("safe", "clean", "not compromised")
set +e
TABLE_OUT=$(PHP2SHELL_MOCK_PHP_FPM_VERSION="8.3.36" PHP2SHELL_MOCK_PHP_CLI_VERSION="8.3.36" PHP2SHELL_MOCK_NODE_VERSION="22.23.4" sh "$AUDIT_SH" scan "$ROOT_DIR/tests/fixtures/php-mitigated.ini" --no-cta)
set -e
if echo "$TABLE_OUT" | grep -Eqi '\b(safe|clean|not compromised)\b'; then
    fail "Output contained forbidden wording (safe/clean/not compromised)"
fi

# 9. Test clean box indicator scan on repo root does not trigger false positive
set +e
CLEAN_OUT=$(PHP2SHELL_MOCK_PHP_FPM_VERSION="8.3.36" PHP2SHELL_MOCK_PHP_CLI_VERSION="8.3.36" PHP2SHELL_MOCK_NODE_VERSION="22.23.4" sh "$AUDIT_SH" scan "$ROOT_DIR" --format json --no-cta)
set -e
if echo "$CLEAN_OUT" | grep -q '"count": [1-9]'; then
    fail "Clean repo scan triggered false positive log indicators"
fi

# 10. Test indicator scan on explicit log fixture
set +e
IOC_OUT=$(PHP2SHELL_MOCK_PHP_FPM_VERSION="8.3.36" PHP2SHELL_MOCK_PHP_CLI_VERSION="8.3.36" PHP2SHELL_MOCK_NODE_VERSION="22.23.4" sh "$AUDIT_SH" scan "$ROOT_DIR/tests/fixtures/php-error.log" --format json --no-cta)
set -e
echo "$IOC_OUT" | grep -q '"status": "indicator found' || fail "Expected indicator found on php-error.log fixture"

echo "All POSIX shell tests (audit.sh) passed."
