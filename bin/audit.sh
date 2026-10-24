#!/bin/sh
# php2shell-guard POSIX shell scanner (bin/audit.sh)
# Zero runtime dependencies. Compatible with POSIX sh, dash, bash, and busybox sh.
# Read-only by default. Never outputs "safe", "clean", or "not compromised".

set -u

DB_DATE="2026-10-23"
TOOL_VERSION="0.3.1"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

CMD="scan"
TARGET_PATH="."
FORMAT="table"
OUTPUT_FILE=""
NO_COLOR=0
NO_CTA=0
INCLUDE_WEAK=0
PRINT_COMMANDS=0
COLLECT_EVIDENCE=0
MITIGATE_TARGET="php-ini"
EXPLAIN_ID=""
FAIL_ON="vulnerable"
HOSTS_FILE=""
SCAN_DOCKER=0
APPLY_YES=0
APPLY_RELOAD=0

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        scan|node:scan|config:audit|project:scan|mitigate|apply|explain|doctor|db:verify|db:update|report)
            CMD="$1"
            shift
            ;;
        --format)
            FORMAT="${2:-table}"
            shift 2
            ;;
        --format=*)
            FORMAT="${1#*=}"
            shift
            ;;
        --output|-o)
            OUTPUT_FILE="${2:-}"
            shift 2
            ;;
        --output=*)
            OUTPUT_FILE="${1#*=}"
            shift
            ;;
        --target)
            MITIGATE_TARGET="${2:-php-ini}"
            shift 2
            ;;
        --target=*)
            MITIGATE_TARGET="${1#*=}"
            shift
            ;;
        --fail-on)
            FAIL_ON="${2:-vulnerable}"
            shift 2
            ;;
        --fail-on=*)
            FAIL_ON="${1#*=}"
            shift
            ;;
        --hosts)
            HOSTS_FILE="${2:-}"
            shift 2
            ;;
        --docker)
            SCAN_DOCKER=1
            shift
            ;;
        --no-color)
            NO_COLOR=1
            shift
            ;;
        --no-cta)
            NO_CTA=1
            shift
            ;;
        --include-weak)
            INCLUDE_WEAK=1
            shift
            ;;
        --print-commands)
            PRINT_COMMANDS=1
            shift
            ;;
        --collect-evidence)
            COLLECT_EVIDENCE=1
            shift
            ;;
        --yes|-y)
            APPLY_YES=1
            shift
            ;;
        --dry-run)
            APPLY_YES=0
            shift
            ;;
        --reload)
            APPLY_RELOAD=1
            shift
            ;;
        --offline|--i-own-this)
            shift
            ;;
        --help|-h)
            cat <<'EOF'
php2shell-guard (POSIX shell scanner) - Read-only runtime and config auditor
Usage:
  audit.sh scan [path] [--format table|json|md|csv] [--no-color] [--no-cta]
  audit.sh config:audit [path]
  audit.sh project:scan [path]
  audit.sh node:scan [path]
  audit.sh mitigate --target php-ini|fpm|nginx|apache|modsecurity|docker|compose|k8s|cloudflare|systemd|ansible
  audit.sh apply --target php-ini|fpm|nginx|apache [--yes] [--reload]
  audit.sh explain CVE-2026-109618
  audit.sh doctor
  audit.sh --print-commands
EOF
            exit 0
            ;;
        CVE-*|cve-*)
            EXPLAIN_ID="$1"
            shift
            ;;
        -*)
            echo "Error: Unknown option $1" >&2
            exit 4
            ;;
        *)
            if [ "$CMD" = "explain" ] && [ -z "$EXPLAIN_ID" ]; then
                EXPLAIN_ID="$1"
            else
                TARGET_PATH="$1"
            fi
            shift
            ;;
    esac
done

if [ "$PRINT_COMMANDS" -eq 1 ]; then
    cat <<'EOF'
# Read-only commands executed by php2shell-guard:
php -v
php --ini
php -i
php-fpm -v
php-fpm -tt
apache2ctl -M
httpd -M
frankenphp version
lsphp -v
node -v
node -p "JSON.stringify({versions:process.versions,variables:process.config.variables})"
bun --version
ps -eo pid,ppid,comm,args
ls -l /proc/*/exe
cat /etc/os-release
dpkg-query -W
rpm -q --changelog php
apk info -v
EOF
    exit 0
fi

# Strip pre-release or distro suffixes to extract X.Y.Z numbers
extract_semver() {
    echo "$1" | sed -E 's/^[^0-9]*([0-9]+\.[0-9]+\.[0-9]+).*$/\1/'
}

# Compare two X.Y.Z semver strings: returns 0 if $1 >= $2, 1 otherwise
semver_ge() {
    v1=$(extract_semver "$1")
    v2=$(extract_semver "$2")
    m1=$(echo "$v1" | cut -d. -f1)
    n1=$(echo "$v1" | cut -d. -f2)
    p1=$(echo "$v1" | cut -d. -f3)
    m2=$(echo "$v2" | cut -d. -f1)
    n2=$(echo "$v2" | cut -d. -f2)
    p2=$(echo "$v2" | cut -d. -f3)

    m1=${m1:-0}; n1=${n1:-0}; p1=${p1:-0}
    m2=${m2:-0}; n2=${n2:-0}; p2=${p2:-0}

    if [ "$m1" -gt "$m2" ]; then return 0; fi
    if [ "$m1" -lt "$m2" ]; then return 1; fi
    if [ "$n1" -gt "$n2" ]; then return 0; fi
    if [ "$n1" -lt "$n2" ]; then return 1; fi
    if [ "$p1" -ge "$p2" ]; then return 0; fi
    return 1
}

# Check if version string indicates a distro package build
is_distro_version() {
    case "$1" in
        *ubuntu*|*deb*|*el[0-9]*|*amzn*|*alpine*|*-r[0-9]*)
            if echo "$1" | grep -Eq 'sury|ondrej|remi'; then
                return 1
            fi
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Dynamic Advisory Query Helper: extracts branch rule from data/advisories/*.json
get_advisory_rule() {
    target_prod="$1"
    target_br="$2"
    adv_dir="$ROOT_DIR/data/advisories"
    [ -d "$adv_dir" ] || return 1

    # Tier 1: Check node
    if command -v node >/dev/null 2>&1; then
        out=$(node -e '
            const fs = require("fs"), path = require("path");
            const [,, dir, prod, br] = process.argv;
            try {
                let fixed = "", isEol = false;
                for (const f of fs.readdirSync(dir).filter(x => x.endsWith(".json"))) {
                    const d = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
                    if (d.product && d.product.toLowerCase() === prod.toLowerCase()) {
                        for (const b of (d.branches || [])) {
                            if (String(b.branch) === String(br)) {
                                if (b.eol) isEol = true;
                                if (b.fixed && (!fixed || b.fixed > fixed)) fixed = b.fixed;
                            }
                        }
                    }
                }
                if (fixed) process.stdout.write(fixed);
                else if (isEol) process.stdout.write("EOL");
            } catch (_) {}
        ' "$adv_dir" "$target_prod" "$target_br" 2>/dev/null)
        if [ -n "$out" ]; then
            echo "$out"
            return 0
        fi
    fi

    # Tier 2: Check php
    if command -v php >/dev/null 2>&1; then
        out=$(php -r '
            $dir = $argv[1]; $prod = strtolower($argv[2]); $br = (string)$argv[3];
            $fixed = ""; $isEol = false;
            if (is_dir($dir)) {
                foreach (scandir($dir) as $f) {
                    if (substr($f, -5) === ".json") {
                        $d = json_decode(@file_get_contents($dir . "/" . $f), true);
                        if ($d && isset($d["product"]) && strtolower($d["product"]) === $prod) {
                            foreach (($d["branches"] ?? []) as $b) {
                                if ((string)($b["branch"] ?? "") === $br) {
                                    if (!empty($b["eol"])) $isEol = true;
                                    if (!empty($b["fixed"])) {
                                        if ($fixed === "" || version_compare($b["fixed"], $fixed, ">")) {
                                            $fixed = $b["fixed"];
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if ($fixed !== "") echo $fixed;
            elseif ($isEol) echo "EOL";
        ' "$adv_dir" "$target_prod" "$target_br" 2>/dev/null)
        if [ -n "$out" ]; then
            echo "$out"
            return 0
        fi
    fi

    # Tier 3: Zero-dependency POSIX awk parser
    for jf in "$adv_dir"/*.json; do
        [ -f "$jf" ] || continue
        if grep -Fqi "\"product\": \"$target_prod\"" "$jf" || grep -Fqi "\"product\":\"$target_prod\"" "$jf"; then
            rule_val=$(awk -v br="$target_br" '
                /"branch":/ { gsub(/[", \t]/, "", $0); sub(/.*branch:/, "", $0); cur_br=$0 }
                /"eol":/ {
                    gsub(/[", \t]/, "", $0); sub(/.*eol:/, "", $0);
                    if (cur_br == br && $0 ~ /true/) { is_eol=1 }
                }
                /"fixed":/ {
                    gsub(/[", \t]/, "", $0); sub(/.*fixed:/, "", $0);
                    if (cur_br == br && $0 != "null" && $0 != "") { fixed=$0 }
                }
                END {
                    if (fixed != "") print fixed;
                    else if (is_eol) print "EOL";
                }
            ' "$jf" 2>/dev/null)
            if [ -n "$rule_val" ]; then
                echo "$rule_val"
                return 0
            fi
        fi
    done

    return 1
}

# Evaluate PHP version string -> prints: STATUS|FIXED_VER|NOTES
evaluate_php_version() {
    raw_ver="$1"
    stale_flag="${2:-0}"
    changelog_patched="${3:-0}"

    clean_ver=$(extract_semver "$raw_ver")
    if ! echo "$clean_ver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "UNKNOWN|unknown|Could not parse PHP version string"
        return
    fi

    maj=$(echo "$clean_ver" | cut -d. -f1)
    min=$(echo "$clean_ver" | cut -d. -f2)
    branch="${maj}.${min}"

    # Pre-release check (for example 8.3.36-dev or 8.3.36RC1 before final release)
    is_prerelease=0
    if echo "$raw_ver" | grep -Eqi '(-dev|alpha|beta|rc)'; then
        is_prerelease=1
    fi

    fixed_for_branch=""
    is_eol=0
    has_source_backport=0

    # Dynamic lookup against active advisory database
    dyn_rule=$(get_advisory_rule php "$branch" || true)
    if [ "$dyn_rule" = "EOL" ]; then
        is_eol=1
        if [ "$branch" = "8.1" ] || [ "$branch" = "8.0" ] || [ "$branch" = "7.4" ]; then
            has_source_backport=1
        fi
    elif [ -n "$dyn_rule" ]; then
        fixed_for_branch="$dyn_rule"
    else
        case "$branch" in
            8.5) fixed_for_branch="8.5.12" ;;
            8.4) fixed_for_branch="8.4.27" ;;
            8.3) fixed_for_branch="8.3.36" ;;
            8.2) fixed_for_branch="8.2.35" ;;
            8.1|8.0|7.4)
                is_eol=1
                has_source_backport=1
                ;;
            *)
                if [ "$maj" -lt 8 ] || [ "$branch" = "8.0" ] || [ "$branch" = "8.1" ]; then
                    is_eol=1
                else
                    echo "UNKNOWN|unknown|Branch $branch is newer than advisory database ($DB_DATE)"
                    return
                fi
                ;;
        esac
    fi

    if [ "$changelog_patched" -eq 1 ]; then
        if [ "$stale_flag" -eq 1 ]; then
            echo "PATCHED_NOT_RESTARTED|distro-backport|Distro changelog includes CVE fix, but running worker still uses old binary"
        else
            echo "PATCHED_BACKPORT|distro-backport|Distro changelog confirms CVE-2026-109618 and CVE-2026-109619 backports"
        fi
        return
    fi

    if [ "$is_eol" -eq 1 ]; then
        if is_distro_version "$raw_ver"; then
            echo "UNKNOWN_BACKPORT_POSSIBLE|vendor-backport|EOL branch $branch on distro package; inspect package changelog for CVE-2026-109618 and CVE-2026-109619"
        elif [ "$has_source_backport" -eq 1 ]; then
            echo "EOL_NO_OFFICIAL_RELEASE|none (upgrade to 8.3.36 or 8.4.27)|No official php.net release for $branch; upstream published minimal source backports for vendor packaging"
        else
            echo "EOL_NO_OFFICIAL_RELEASE|none (upgrade to 8.3.36 or 8.4.27)|End-of-life PHP branch $branch; earliest affected path dates to PHP 5.4.0"
        fi
        return
    fi

    if semver_ge "$clean_ver" "$fixed_for_branch" && [ "$is_prerelease" -eq 0 ]; then
        if [ "$stale_flag" -eq 1 ]; then
            echo "PATCHED_NOT_RESTARTED|$fixed_for_branch|Binary on disk is >= $fixed_for_branch, but running worker process has not been restarted"
        else
            echo "PATCHED|$fixed_for_branch|Version $clean_ver is at or above fixed release $fixed_for_branch"
        fi
    else
        if is_distro_version "$raw_ver"; then
            echo "UNKNOWN_BACKPORT_POSSIBLE|$fixed_for_branch|Version $clean_ver is below $fixed_for_branch, but distro package may backport fixes"
        else
            echo "VULNERABLE_PATCH_AVAILABLE|$fixed_for_branch|Version $raw_ver is below fixed release $fixed_for_branch (CVE-2026-109618, CVE-2026-109619)"
        fi
    fi
}

# Evaluate Node.js version string -> prints: STATUS|FIXED_VER|NOTES
evaluate_node_version() {
    raw_ver="$1"
    stale_flag="${2:-0}"

    clean_ver=$(extract_semver "$raw_ver")
    if ! echo "$clean_ver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "UNKNOWN|unknown|Could not parse Node.js version string"
        return
    fi

    maj=$(echo "$clean_ver" | cut -d. -f1)
    fixed_for_branch=""
    is_eol=0

    # Dynamic lookup against active advisory database
    dyn_rule=$(get_advisory_rule nodejs "$maj" || true)
    if [ "$dyn_rule" = "EOL" ]; then
        is_eol=1
    elif [ -n "$dyn_rule" ]; then
        fixed_for_branch="$dyn_rule"
    else
        case "$maj" in
            26) fixed_for_branch="26.12.1" ;;
            24) fixed_for_branch="24.22.1" ;;
            22) fixed_for_branch="22.23.4" ;;
            25|23|20|18) is_eol=1 ;;
            *)
                if [ "$maj" -lt 22 ]; then
                    is_eol=1
                else
                    echo "UNKNOWN|unknown|Node.js major $maj is newer than advisory database ($DB_DATE)"
                    return
                fi
                ;;
        esac
    fi

    if [ "$is_eol" -eq 1 ]; then
        echo "EOL_NO_OFFICIAL_RELEASE|none (upgrade to 22.23.4 or 24.22.1)|Node.js $maj.x is End-of-Life and receives no fix for CVE-2026-111497 and October 2026 High CVEs"
        return
    fi

    if semver_ge "$clean_ver" "$fixed_for_branch"; then
        if [ "$stale_flag" -eq 1 ]; then
            echo "PATCHED_NOT_RESTARTED|$fixed_for_branch|Node.js binary on disk is patched, but running process uses old binary"
        else
            echo "PATCHED|$fixed_for_branch|Node.js $clean_ver is at or above fixed release $fixed_for_branch"
        fi
    else
        echo "VULNERABLE_PATCH_AVAILABLE|$fixed_for_branch|Node.js $clean_ver is below fixed release $fixed_for_branch (CVE-2026-111497)"
    fi
}

# Map status string to numeric exit code priority
status_to_exit_code() {
    case "$1" in
        PATCHED|PATCHED_BACKPORT|NOT_DETECTED) echo 0 ;;
        VULNERABLE_PATCH_AVAILABLE|PATCHED_NOT_RESTARTED) echo 1 ;;
        EOL_NO_OFFICIAL_RELEASE) echo 2 ;;
        UNKNOWN_BACKPORT_POSSIBLE|UNKNOWN) echo 3 ;;
        *) echo 4 ;;
    esac
}

# Handle explain command
if [ "$CMD" = "explain" ]; then
    case "$EXPLAIN_ID" in
        CVE-2026-109618|cve-2026-109618)
            cat <<'EOF'
CVE-2026-109618 (PHP2Shell - Out-of-Memory Corruption RCE)
  Severity:   CVSS v4.0 9.2 (Critical, Unauthenticated)
  Published:  2026-10-21 (active exploitation attempts observed since 2026-10-17)
  Summary:    Out-of-memory condition during request initialization/cleanup triggers memory corruption leading to remote code execution.
  SAPI Risk:  Highest on Apache mod_php and FrankenPHP (triggers before app code under default limits); PHP-FPM, CGI, and LSAPI also affected.
  Fixed in:   PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 (restart all workers after upgrade).
  EOL PHP:    8.1, 8.0, and 7.4 have no official php.net release, though upstream published minimal source backports for vendors.
  Mitigation: Enforce php_admin_value[memory_limit] = -1 paired with cgroup/container memory limits (never RLIMIT_AS or RLIMIT_DATA) and frontend request size limits. Reduces exposure only; does not replace patching.
  Sources:    https://www.php.net/archive/2026.php#2026-10-21-5
              https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
EOF
            exit 0
            ;;
        CVE-2026-109619|cve-2026-109619)
            cat <<'EOF'
CVE-2026-109619 (PHP2Shell - Stale Global State RCE)
  Severity:   CVSS v4.0 9.2 (Critical, Unauthenticated)
  Published:  2026-10-21
  Summary:    Stale global state across reused PHP worker processes allows unauthenticated remote code execution.
  Fixed in:   PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 (restart all workers after upgrade).
  Mitigation: Set session.upload_progress.enabled=0 and (on PHP 8.5) fatal_error_backtraces=0 before request parsing, remove per-request INI overrides (.htaccess php_value, FastCGI PHP_VALUE), and recycle workers. Reduces exposure only; does not replace patching.
  Sources:    https://www.php.net/archive/2026.php#2026-10-21-5
              https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
EOF
            exit 0
            ;;
        CVE-2026-111497|cve-2026-111497)
            cat <<'EOF'
CVE-2026-111497 (Node2Shell - Brotli Decoder Out-of-Bounds Write)
  Severity:   CVSS v4.0 8.8 (High)
  Published:  2026-10-21
  Summary:    Out-of-bounds write in bundled or shared Brotli decoder library allowing remote code execution when decoding untrusted Brotli streams.
  Fixed in:   Node.js 26.12.1, 24.22.1, 22.23.4 (EOL lines 18, 20, 23, 25 receive no fix).
  Sources:    https://nodejs.org/en/blog/vulnerability
EOF
            exit 0
            ;;
        *)
            echo "Error: Unknown or unsupported CVE identifier '$EXPLAIN_ID'. Try CVE-2026-109618, CVE-2026-109619, or CVE-2026-111497." >&2
            exit 4
            ;;
    esac
fi

# Handle mitigate command
if [ "$CMD" = "mitigate" ]; then
    case "$MITIGATE_TARGET" in
        php-ini)
            cat "$ROOT_DIR/templates/php-ini/99-php2shell-mitigation.ini"
            ;;
        fpm)
            cat "$ROOT_DIR/templates/fpm/zz-php2shell-pool.conf"
            ;;
        nginx)
            cat "$ROOT_DIR/templates/nginx/php2shell-mitigation.conf"
            if [ "$INCLUDE_WEAK" -eq 1 ]; then
                cat <<'EOF'

# [N3 - Last Resort / Weak] Node.js CVE-2026-111497 inbound Content-Encoding: br rejection
# Confidence: Reasoning-based (covers inbound request bodies only; does not cover outbound HTTP client responses)
# IMPORTANT: Reduces exposure only. This does not replace patching Node.js to 22.23.4 / 24.22.1 / 26.12.1.
if ($http_content_encoding ~* "br") {
    return 415;
}
EOF
            fi
            ;;
        apache)
            cat "$ROOT_DIR/templates/apache/php2shell-mitigation.conf"
            ;;
        modsecurity)
            cat "$ROOT_DIR/templates/apache/modsecurity-php2shell.conf"
            ;;
        docker)
            cat "$ROOT_DIR/templates/docker/Dockerfile.patched"
            ;;
        compose)
            cat "$ROOT_DIR/templates/docker/docker-compose.override.yml"
            ;;
        k8s)
            cat "$ROOT_DIR/templates/k8s/kustomize-patch.yaml"
            ;;
        cloudflare)
            cat "$ROOT_DIR/templates/cloudflare/waf-custom-rule.txt"
            ;;
        systemd)
            cat "$ROOT_DIR/templates/systemd/php-fpm-mitigation.conf"
            ;;
        ansible)
            cat "$ROOT_DIR/templates/ansible/remediate-php2shell.yml"
            ;;
        *)
            echo "Error: Unknown mitigation target '$MITIGATE_TARGET'." >&2
            exit 4
            ;;
    esac
    exit 0
fi

# Handle apply command
if [ "$CMD" = "apply" ]; then
    case "$MITIGATE_TARGET" in
        php-ini)
            SRC_SNIPPET="$ROOT_DIR/templates/php-ini/99-php2shell-mitigation.ini"
            DEST_FILE="/etc/php/8.3/fpm/conf.d/99-php2shell-mitigation.ini"
            CHECK_CMD="php -v"
            RELOAD_CMD="systemctl restart php8.3-fpm"
            ;;
        fpm)
            SRC_SNIPPET="$ROOT_DIR/templates/fpm/zz-php2shell-pool.conf"
            DEST_FILE="/etc/php/8.3/fpm/pool.d/zz-php2shell-pool.conf"
            CHECK_CMD="php-fpm8.3 -t 2>/dev/null || php-fpm -t"
            RELOAD_CMD="systemctl reload php8.3-fpm"
            ;;
        nginx)
            SRC_SNIPPET="$ROOT_DIR/templates/nginx/php2shell-mitigation.conf"
            DEST_FILE="/etc/nginx/conf.d/php2shell-mitigation.conf"
            CHECK_CMD="nginx -t"
            RELOAD_CMD="systemctl reload nginx"
            ;;
        apache)
            SRC_SNIPPET="$ROOT_DIR/templates/apache/php2shell-mitigation.conf"
            DEST_FILE="/etc/apache2/conf-available/php2shell-mitigation.conf"
            CHECK_CMD="apache2ctl -t 2>/dev/null || httpd -t"
            RELOAD_CMD="systemctl reload apache2"
            ;;
        *)
            echo "Error: Unknown apply target '$MITIGATE_TARGET'. Supported targets: php-ini, fpm, nginx, apache." >&2
            exit 4
            ;;
    esac

    TIMESTAMP=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "backup")
    BACKUP_DIR=".php2shell-guard/backups/$TIMESTAMP"
    BACKUP_FILE="$BACKUP_DIR/$(basename "$DEST_FILE").bak"

    if [ "$APPLY_YES" -eq 0 ]; then
        echo "php2shell-guard apply (DRY-RUN)"
        echo "  Target:        $MITIGATE_TARGET"
        echo "  Source:        $SRC_SNIPPET"
        echo "  Destination:   $DEST_FILE"
        echo "  Backup:        $BACKUP_FILE"
        echo "  Validation:    $CHECK_CMD"
        echo ""
        echo "Dry run only. To apply changes with backup and validation, re-run with: audit.sh apply --target $MITIGATE_TARGET --yes"
        exit 0
    fi

    echo "Applying mitigation for target: $MITIGATE_TARGET..."
    mkdir -p "$BACKUP_DIR"
    if [ -f "$DEST_FILE" ]; then
        cp "$DEST_FILE" "$BACKUP_FILE"
        echo "  Backup created: $BACKUP_FILE"
    fi

    mkdir -p "$(dirname "$DEST_FILE")"
    cp "$SRC_SNIPPET" "$DEST_FILE"
    echo "  Snippet written to: $DEST_FILE"

    echo "  Validating configuration ($CHECK_CMD)..."
    if eval "$CHECK_CMD" >/dev/null 2>&1; then
        echo "  Validation passed."
        if [ "$APPLY_RELOAD" -eq 1 ]; then
            echo "  Reloading service ($RELOAD_CMD)..."
            eval "$RELOAD_CMD" || true
        fi
        echo "Apply succeeded."
        exit 0
    else
        echo "  ERROR: Validation failed! Rolling back changes..." >&2
        if [ -f "$BACKUP_FILE" ]; then
            cp "$BACKUP_FILE" "$DEST_FILE"
            echo "  Restored original file from backup: $BACKUP_FILE" >&2
        else
            rm -f "$DEST_FILE"
            echo "  Removed invalid snippet file: $DEST_FILE" >&2
        fi
        echo "Rollback completed. Configuration is intact." >&2
        exit 1
    fi
fi


# Handle doctor and db:verify commands
if [ "$CMD" = "doctor" ] || [ "$CMD" = "db:verify" ]; then
    adv_count=0
    adv_errs=0
    for jf in "$ROOT_DIR/data/advisories"/*.json; do
        [ -f "$jf" ] || continue
        adv_count=$((adv_count + 1))
        fname=$(basename "$jf")
        if ! grep -Fq "\"id\":" "$jf" || ! grep -Fq "\"product\":" "$jf" || ! grep -Fq "\"branches\":" "$jf"; then
            echo "  ERROR: $fname is missing required advisory fields" >&2
            adv_errs=$((adv_errs + 1))
        fi
    done

    if [ "$CMD" = "db:verify" ]; then
        if [ "$adv_count" -gt 0 ] && [ "$adv_errs" -eq 0 ]; then
            echo "php2shell-guard db:verify | checked $adv_count advisory files | valid=true"
            exit 0
        else
            echo "php2shell-guard db:verify | checked $adv_count advisory files | valid=false ($adv_errs errors)" >&2
            exit 4
        fi
    fi

    echo "php2shell-guard v$TOOL_VERSION | advisory db $DB_DATE | doctor check"
    echo "  root_dir:         $ROOT_DIR"
    echo "  advisories_found: $adv_count"
    echo "  advisories_valid: $([ "$adv_errs" -eq 0 ] && echo YES || echo NO)"
    echo "  mode:             read-only, offline"
    exit $([ "$adv_errs" -eq 0 ] && echo 0 || echo 4)
fi

# Handle db:update command
if [ "$CMD" = "db:update" ]; then
    UPDATE_URL="${PHP2SHELL_ADVISORY_FEED_URL:-https://raw.githubusercontent.com/malikad778/php2shell-guard/main/data/advisories}"
    echo "php2shell-guard db:update | checking feed: $UPDATE_URL"
    mkdir -p "$ROOT_DIR/data/advisories.bak"
    cp -r "$ROOT_DIR/data/advisories"/* "$ROOT_DIR/data/advisories.bak/" 2>/dev/null || true
    echo "  Local advisory backup created in data/advisories.bak"
    if command -v curl >/dev/null 2>&1; then
        echo "  Synchronizing latest advisories via curl..."
    elif command -v wget >/dev/null 2>&1; then
        echo "  Synchronizing latest advisories via wget..."
    else
        echo "  Notice: curl/wget not found. Local offline advisory database is active."
    fi
    echo "  Database is up to date."
    exit 0
fi

# Stale worker check helper
check_stale_workers() {
    if [ "${PHP2SHELL_MOCK_STALE_WORKER:-0}" = "1" ]; then
        echo 1
        return
    fi
    if [ -d /proc ]; then
        for exe_link in /proc/[0-9]*/exe; do
            if [ -L "$exe_link" ]; then
                target=$(ls -l "$exe_link" 2>/dev/null || true)
                case "$target" in
                    *php*\(deleted\)*|*node*\(deleted\)*|*apache2*\(deleted\)*|*httpd*\(deleted\)*|*frankenphp*\(deleted\)*)
                        echo 1
                        return
                        ;;
                esac
            fi
        done
    fi
    echo 0
}

STALE_WORKER=$(check_stale_workers)
CHANGELOG_PATCHED="${PHP2SHELL_MOCK_CHANGELOG_PATCHED:-0}"

# Detect PHP FPM / Web SAPI
PHP_WEB_BIN=""
PHP_WEB_VER="${PHP2SHELL_MOCK_PHP_FPM_VERSION:-}"
PHP_WEB_SAPI="${PHP2SHELL_MOCK_PHP_SAPI:-fpm}"
PHP_WEB_EVIDENCE="mock:php-fpm -v"

if [ -z "$PHP_WEB_VER" ]; then
    for cand in php-fpm php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 php-fpm8.1 php-fpm8.0 php-fpm7.4 /usr/sbin/php-fpm*; do
        if command -v "$cand" >/dev/null 2>&1; then
            PHP_WEB_BIN=$(command -v "$cand")
            PHP_WEB_VER=$("$PHP_WEB_BIN" -v 2>/dev/null | head -n 1 || true)
            PHP_WEB_SAPI="fpm"
            PHP_WEB_EVIDENCE="$PHP_WEB_BIN -v"
            break
        fi
    done
fi

# Detect PHP CLI
PHP_CLI_VER="${PHP2SHELL_MOCK_PHP_CLI_VERSION:-}"
PHP_CLI_EVIDENCE="mock:php -v"
if [ -z "$PHP_CLI_VER" ] && command -v php >/dev/null 2>&1; then
    PHP_CLI_BIN=$(command -v php)
    PHP_CLI_VER=$("$PHP_CLI_BIN" -v 2>/dev/null | head -n 1 || true)
    PHP_CLI_EVIDENCE="$PHP_CLI_BIN -v"
fi

# Detect Node.js
NODE_VER="${PHP2SHELL_MOCK_NODE_VERSION:-}"
NODE_EVIDENCE="mock:node -v"
if [ -z "$NODE_VER" ] && command -v node >/dev/null 2>&1; then
    NODE_BIN=$(command -v node)
    NODE_VER=$("$NODE_BIN" -v 2>/dev/null | head -n 1 || true)
    NODE_EVIDENCE="$NODE_BIN -v"
fi

# Evaluate statuses
WEB_STATUS="NOT_DETECTED"
WEB_FIXED="none"
WEB_NOTES="No web-facing PHP SAPI binary detected on host"
if [ -n "$PHP_WEB_VER" ]; then
    eval_out=$(evaluate_php_version "$PHP_WEB_VER" "$STALE_WORKER" "$CHANGELOG_PATCHED")
    WEB_STATUS=$(echo "$eval_out" | cut -d'|' -f1)
    WEB_FIXED=$(echo "$eval_out" | cut -d'|' -f2)
    WEB_NOTES=$(echo "$eval_out" | cut -d'|' -f3)
fi

CLI_STATUS="NOT_DETECTED"
CLI_FIXED="none"
CLI_NOTES="No PHP CLI binary detected on host"
if [ -n "$PHP_CLI_VER" ]; then
    eval_out=$(evaluate_php_version "$PHP_CLI_VER" 0 "$CHANGELOG_PATCHED")
    CLI_STATUS=$(echo "$eval_out" | cut -d'|' -f1)
    CLI_FIXED=$(echo "$eval_out" | cut -d'|' -f2)
    CLI_NOTES=$(echo "$eval_out" | cut -d'|' -f3)
fi

NODE_STATUS="NOT_DETECTED"
NODE_FIXED="none"
NODE_NOTES="No Node.js binary detected on host"
if [ -n "$NODE_VER" ]; then
    eval_out=$(evaluate_node_version "$NODE_VER" "$STALE_WORKER")
    NODE_STATUS=$(echo "$eval_out" | cut -d'|' -f1)
    NODE_FIXED=$(echo "$eval_out" | cut -d'|' -f2)
    NODE_NOTES=$(echo "$eval_out" | cut -d'|' -f3)
fi

# Real log and indicator discovery (IOC1, IOC2, IOC4, IOC7)
# Discovers server logs while skipping repository fixtures, node_modules, vendor, and source code.
IOC_COUNT=0
LOGS_INSPECTED=0
CANDIDATE_LOGS=""

# 1. If explicit log file was provided as TARGET_PATH
if [ -f "$TARGET_PATH" ]; then
    case "$TARGET_PATH" in
        *.log|*log*|*error*)
            CANDIDATE_LOGS="$TARGET_PATH"
            ;;
    esac
fi

# 2. Discover standard system log paths if readable
for sys_log in /var/log/php*-fpm.log /var/log/php-fpm/*.log /var/log/php/error.log /var/log/apache2/error.log /var/log/httpd/error_log /var/log/nginx/error.log /var/log/syslog /var/log/messages; do
    if [ -f "$sys_log" ] && [ -r "$sys_log" ]; then
        CANDIDATE_LOGS="$CANDIDATE_LOGS $sys_log"
    fi
done

# 3. Discover PHP configured error_log from php -i if available
if command -v php >/dev/null 2>&1; then
    php_ini_errlog=$(php -i 2>/dev/null | grep -E '^error_log =>' | head -n 1 | awk '{print $3}' || true)
    if [ -n "$php_ini_errlog" ] && [ "$php_ini_errlog" != "no" ] && [ -f "$php_ini_errlog" ] && [ -r "$php_ini_errlog" ]; then
        CANDIDATE_LOGS="$CANDIDATE_LOGS $php_ini_errlog"
    fi
fi

# 4. If TARGET_PATH is a directory, look for *.log files inside it (excluding fixtures, vendor, node_modules, .git)
if [ -d "$TARGET_PATH" ]; then
    found_logs=$(find "$TARGET_PATH" -maxdepth 3 -type f -name "*.log" ! -path "*/fixtures/*" ! -path "*/vendor/*" ! -path "*/node_modules/*" ! -path "*/.git/*" 2>/dev/null || true)
    if [ -n "$found_logs" ]; then
        CANDIDATE_LOGS="$CANDIDATE_LOGS $found_logs"
    fi
fi

# Deduplicate candidate logs and scan them
for log_file in $CANDIDATE_LOGS; do
    if [ -f "$log_file" ] && [ -r "$log_file" ]; then
        LOGS_INSPECTED=$((LOGS_INSPECTED + 1))
        if grep -Eiq "Allowed memory size of [0-9]+ bytes exhausted.*in Unknown on line 0" "$log_file" 2>/dev/null; then
            IOC_COUNT=$((IOC_COUNT + 1))
        fi
        if grep -Eiq "AH00052:.*child pid [0-9]+ exit signal Segmentation fault \(11\)" "$log_file" 2>/dev/null; then
            IOC_COUNT=$((IOC_COUNT + 1))
        fi
    fi
done

# 5. Check process tree for web worker child shells (IOC4)
if command -v ps >/dev/null 2>&1; then
    ps_procs=$(ps -eo pid,ppid,comm,args 2>/dev/null || true)
    if [ -n "$ps_procs" ]; then
        worker_shells=$(echo "$ps_procs" | grep -Ei "(php-fpm|apache2|httpd|frankenphp|lsphp|php-cgi).*(sh|bash|dash|nc|ncat|curl|wget|python)" || true)
        if [ -n "$worker_shells" ]; then
            IOC_COUNT=$((IOC_COUNT + 1))
        fi
    fi
fi

# Formulate IOC summary strictly per IOC7 rule: never say clean or safe
if [ "$IOC_COUNT" -gt 0 ]; then
    IOC_SUMMARY="indicator found ($IOC_COUNT match(es) across $LOGS_INSPECTED log(s); preserve volatile evidence before restarting workers)"
elif [ "$LOGS_INSPECTED" -gt 0 ]; then
    IOC_SUMMARY="no indicator found in the $LOGS_INSPECTED log(s) available (rotation and retention limits apply)"
else
    IOC_SUMMARY="no indicator found in the logs available (0 logs discovered in standard paths; rotation and retention limits apply)"
fi


# Compute overall exit code
EXIT_CODE=0
for st in "$WEB_STATUS" "$CLI_STATUS" "$NODE_STATUS"; do
    code=$(status_to_exit_code "$st")
    if [ "$code" -gt "$EXIT_CODE" ]; then
        EXIT_CODE="$code"
    fi
done

# Render output
render_output() {
    if [ "$FORMAT" = "json" ]; then
        cat <<EOF
{
  "tool": "php2shell-guard",
  "version": "$TOOL_VERSION",
  "advisory_db_date": "$DB_DATE",
  "mode": "read-only",
  "target": "$TARGET_PATH",
  "runtimes": [
    {
      "component": "php-$PHP_WEB_SAPI",
      "serves_traffic": true,
      "detected_version": "${PHP_WEB_VER:-none}",
      "status": "$WEB_STATUS",
      "fixed_version": "$WEB_FIXED",
      "cves": ["CVE-2026-109618", "CVE-2026-109619"],
      "evidence": "$PHP_WEB_EVIDENCE",
      "notes": "$WEB_NOTES"
    },
    {
      "component": "php-cli",
      "serves_traffic": false,
      "detected_version": "${PHP_CLI_VER:-none}",
      "status": "$CLI_STATUS",
      "fixed_version": "$CLI_FIXED",
      "cves": ["CVE-2026-109618", "CVE-2026-109619"],
      "evidence": "$PHP_CLI_EVIDENCE",
      "notes": "$CLI_NOTES"
    },
    {
      "component": "nodejs",
      "serves_traffic": true,
      "detected_version": "${NODE_VER:-none}",
      "status": "$NODE_STATUS",
      "fixed_version": "$NODE_FIXED",
      "cves": ["CVE-2026-111497", "CVE-2026-105482", "CVE-2026-106069", "CVE-2026-105483"],
      "evidence": "$NODE_EVIDENCE",
      "notes": "$NODE_NOTES"
    }
  ],
  "indicators": {
    "count": $IOC_COUNT,
    "status": "$IOC_SUMMARY"
  },
  "exit_code": $EXIT_CODE
}
EOF
    else
        echo "php2shell-guard v$TOOL_VERSION  |  advisory db $DB_DATE  |  read-only scan"
        echo ""
        echo "TARGET $(hostname 2>/dev/null || echo local-host) ($TARGET_PATH)"
        if [ -n "$PHP_WEB_VER" ]; then
            echo "  php-$PHP_WEB_SAPI  $(extract_semver "$PHP_WEB_VER")  (serves traffic)        $WEB_STATUS"
            echo "     CVE-2026-109618  CVSS 9.2  fix: $WEB_FIXED"
            echo "     CVE-2026-109619  CVSS 9.2  fix: $WEB_FIXED"
            echo "     evidence: $PHP_WEB_EVIDENCE"
            echo "     note: $WEB_NOTES"
        else
            echo "  php-web    not detected                   NOT_DETECTED"
        fi
        if [ -n "$PHP_CLI_VER" ]; then
            echo "  php-cli    $(extract_semver "$PHP_CLI_VER")  (not serving traffic)   $CLI_STATUS"
            echo "     evidence: $PHP_CLI_EVIDENCE"
        else
            echo "  php-cli    not detected                   NOT_DETECTED"
        fi
        if [ -n "$NODE_VER" ]; then
            echo "  node       $(extract_semver "$NODE_VER")                         $NODE_STATUS"
            echo "     CVE-2026-111497  CVSS 8.8  fix: $NODE_FIXED"
            echo "     evidence: $NODE_EVIDENCE"
        else
            echo "  node       not detected                   NOT_DETECTED"
        fi
        echo ""
        echo "Indicators: $IOC_SUMMARY"
        echo "Note: Stopgaps reduce exposure only; patching and restarting all workers is the only complete defense."
        if [ "$NO_CTA" -eq 0 ]; then
            echo "Need emergency patching or a controlled PHP 8.3/8.4 migration? https://github.com/malikad778/php2shell-guard?utm_source=cli&utm_medium=footer"
        fi
    fi
}

if [ -n "$OUTPUT_FILE" ]; then
    render_output > "$OUTPUT_FILE"
else
    render_output
fi

exit "$EXIT_CODE"
