#!/usr/bin/env bash
set -euo pipefail

BIN="$(pwd)/password_manager"
if [[ ! -x "$BIN" ]]; then
    echo "[-] Binary $BIN not found. Run 'make' first."
    exit 1
fi

TMPDIR="$(mktemp -d /tmp/ics0022_e2e.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS_COUNT=0
FAIL_COUNT=0

assert_contains() {
    local file="$1"
    local pattern="$2"
    local label="$3"
    if grep -Fq -- "$pattern" "$file"; then
        echo "  [PASS] $label"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  [FAIL] $label (missing: $pattern)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

assert_not_contains() {
    local file="$1"
    local pattern="$2"
    local label="$3"
    if grep -Fq -- "$pattern" "$file"; then
        echo "  [FAIL] $label (unexpectedly found: $pattern)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo "  [PASS] $label"
        PASS_COUNT=$((PASS_COUNT + 1))
    fi
}

MASTER_A="Alice#Master2026!"
MASTER_B="Bob#Master2026!!"
SVC_PASS_1="UltraSecretSvc#101"
SVC_PASS_2="RotatedSecretSvc#202"

echo "=== E2E CLI Security & Functional Integration Tests ==="

# Run without DISPLAY/WAYLAND_DISPLAY so GET never launches a background GUI clipboard daemon
# and strictly verifies that plaintext is NEVER printed to stdout/stderr.
(
    cd "$TMPDIR"
    env -u DISPLAY -u WAYLAND_DISPLAY "$BIN" <<EOF > run1.out 2>&1
SIGNUP ab
SIGNUP alice
weakpass
SIGNUP alice
$MASTER_A
$MASTER_A
LOGIN alice
$MASTER_A
ADD github.com alice_gh extra_junk
ADD github.com alice_gh
$SVC_PASS_1
LIST
UPDATE github.com alice_gh_new
$SVC_PASS_2
GET github.com
EXIT
EOF
)

assert_contains "$TMPDIR/run1.out" "Invalid username" "short username rejected in CLI"
assert_contains "$TMPDIR/run1.out" "Master password must be" "weak master password rejected in CLI"
assert_contains "$TMPDIR/run1.out" "Account 'alice' created" "valid signup succeeds"
assert_contains "$TMPDIR/run1.out" "Vault unlocked for 'alice'" "valid login unlocks vault"
assert_contains "$TMPDIR/run1.out" "Usage: ADD <url> <username>" "trailing junk argument rejected"
assert_contains "$TMPDIR/run1.out" "Added entry for github.com (alice_gh)" "ADD stores credential"
assert_contains "$TMPDIR/run1.out" "Updated entry for github.com (alice_gh_new)" "UPDATE modifies credential"

# Critical Project 2 requirement: NEVER print passwords in cleartext
assert_not_contains "$TMPDIR/run1.out" "$MASTER_A" "master password never printed to stdout/stderr"
assert_not_contains "$TMPDIR/run1.out" "$SVC_PASS_1" "initial service password never printed to stdout/stderr"
assert_not_contains "$TMPDIR/run1.out" "$SVC_PASS_2" "updated service password never printed to stdout/stderr"

# File permissions check (0600)
DB_PERM="$(stat -c '%a' "$TMPDIR/database.db")"
LOG_PERM="$(stat -c '%a' "$TMPDIR/vault.log")"
if [[ "$DB_PERM" == "600" ]]; then
    echo "  [PASS] database.db has 0600 permissions"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  [FAIL] database.db permissions expected 600, got $DB_PERM"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

if [[ "$LOG_PERM" == "600" ]]; then
    echo "  [PASS] vault.log has 0600 permissions"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  [FAIL] vault.log permissions expected 600, got $LOG_PERM"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Encryption at rest check: secrets must NOT exist in plaintext inside database.db
if LC_ALL=C grep -Fq -- "$MASTER_A" "$TMPDIR/database.db" || \
   LC_ALL=C grep -Fq -- "$SVC_PASS_1" "$TMPDIR/database.db" || \
   LC_ALL=C grep -Fq -- "$SVC_PASS_2" "$TMPDIR/database.db"; then
    echo "  [FAIL] plaintext password found in database.db!"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  [PASS] zero plaintext passwords in database.db (encrypted at rest)"
    PASS_COUNT=$((PASS_COUNT + 1))
fi

# Audit log completeness and zero-secret check
assert_contains "$TMPDIR/vault.log" '"event":"SIGNUP"' "log records SIGNUP"
assert_contains "$TMPDIR/vault.log" '"event":"LOGIN"' "log records LOGIN"
assert_contains "$TMPDIR/vault.log" '"event":"VAULT_ADD"' "log records VAULT_ADD"
assert_contains "$TMPDIR/vault.log" '"event":"VAULT_UPDATE"' "log records VAULT_UPDATE"
assert_contains "$TMPDIR/vault.log" '"event":"VAULT_GET"' "log records VAULT_GET"
assert_contains "$TMPDIR/vault.log" '"event":"LOGOUT"' "log records LOGOUT"
assert_not_contains "$TMPDIR/vault.log" "$MASTER_A" "master password never written to vault.log"
assert_not_contains "$TMPDIR/vault.log" "$SVC_PASS_1" "service password 1 never written to vault.log"
assert_not_contains "$TMPDIR/vault.log" "$SVC_PASS_2" "service password 2 never written to vault.log"

# Cross-user isolation & oversized input resilience test
LONG_LINE="$(printf 'A%.0s' {1..400})"
(
    cd "$TMPDIR"
    env -u DISPLAY -u WAYLAND_DISPLAY "$BIN" <<EOF > run2.out 2>&1
$LONG_LINE
SIGNUP bob
$MASTER_B
$MASTER_B
LOGIN bob
$MASTER_B
GET github.com
DEL github.com
UPDATE github.com hacker
EXIT
EOF
)

assert_contains "$TMPDIR/run2.out" "Input too long" "400-byte overflow line safely rejected"
assert_contains "$TMPDIR/run2.out" "No entry found for github.com" "bob cannot access or delete alice's entry"

# Verify Alice's entry still exists and she can delete it cleanly
(
    cd "$TMPDIR"
    env -u DISPLAY -u WAYLAND_DISPLAY "$BIN" <<EOF > run3.out 2>&1
LOGIN alice
$MASTER_A
LIST
DEL github.com
EXIT
EOF
)

assert_contains "$TMPDIR/run3.out" "alice_gh_new" "alice's entry survived bob's unauthorized attempts"
assert_contains "$TMPDIR/run3.out" "Deleted entry for github.com" "alice cleanly deletes her own entry"

echo "=============================================="
echo "E2E SUMMARY: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="

[[ "$FAIL_COUNT" -eq 0 ]]
