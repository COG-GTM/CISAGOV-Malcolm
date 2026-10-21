#!/usr/bin/env bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Regression tests for malcolm-iso/config/includes.chroot/usr/local/bin/ufw_manager.sh,
#   which is run as root via a NOPASSWD sudoers entry. These tests run as an
#   unprivileged user with a stubbed ufw binary and a real yq, and verify that:
#     - the caller can no longer choose the yq binary (-y) or tracking file (-u)
#     - UFW rule arguments beginning with "-" are rejected
#     - entries read back out of the tracking YML during "reset" are validated
#       and passed as single argument vector items
#     - rule arguments containing commas (e.g. 80,443/tcp) round-trip intact
#     - a tracking file replaced with a symlink is refused before ufw is called
#
# Usage: malcolm-iso/tests/test_ufw_manager.sh   (requires yq in PATH)

set -euo pipefail

if (( EUID == 0 )); then
  echo "These tests must be run as an unprivileged user" >&2
  exit 1
fi

TESTS_DIR="$(dirname "$(realpath "$0")")"
UFW_MANAGER="$(realpath "$TESTS_DIR/../config/includes.chroot/usr/local/bin/ufw_manager.sh")"
YQ="$(command -v yq || true)"
if [[ -z "$YQ" ]]; then
  echo "yq (https://github.com/mikefarah/yq) is required to run these tests" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

UFW_LOG="$WORK_DIR/ufw.log"
EVIL_MARKER="$WORK_DIR/evil-was-executed"
STATUS_YML="$WORK_DIR/Malcolm/.ufw-rules.yml"
mkdir -p "$WORK_DIR/Malcolm"

# stub ufw: record each invocation with its arguments as individual, bracketed items
cat > "$WORK_DIR/ufw" <<STUB
#!/usr/bin/env bash
printf '[%s]' "\$@" >> "$UFW_LOG"
printf '\n' >> "$UFW_LOG"
STUB
chmod +x "$WORK_DIR/ufw"

# a binary that must never be executed as a result of running ufw_manager.sh
cat > "$WORK_DIR/evil" <<STUB
#!/usr/bin/env bash
touch "$EVIL_MARKER"
STUB
chmod +x "$WORK_DIR/evil"

export UFW_MANAGER_UFW_BIN="$WORK_DIR/ufw"
export UFW_MANAGER_YQ_BIN="$YQ"
export UFW_MANAGER_STATUS_YML="$STATUS_YML"

FAILURES=0
function pass { echo "PASS: $1"; }
function fail { echo "FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
function assert_rejected {
  local DESC=$1
  shift
  if "$UFW_MANAGER" "$@" >/dev/null 2>&1; then
    fail "$DESC (exit status 0, expected failure)"
  else
    pass "$DESC"
  fi
}
function assert_accepted {
  local DESC=$1
  shift
  if "$UFW_MANAGER" "$@" >/dev/null 2>"$WORK_DIR/stderr"; then
    pass "$DESC"
  else
    fail "$DESC (unexpected failure: $(cat "$WORK_DIR/stderr"))"
  fi
}
function assert_equals {
  local DESC=$1
  local ACTUAL=$2
  local EXPECTED=$3
  if [[ "$ACTUAL" == "$EXPECTED" ]]; then
    pass "$DESC"
  else
    fail "$DESC (expected \"$EXPECTED\", got \"$ACTUAL\")"
  fi
}
function assert_no_evil {
  if [[ -e "$EVIL_MARKER" ]]; then
    fail "$1 (attacker-controlled binary was executed)"
    rm -f "$EVIL_MARKER"
  fi
}
function assert_ufw_log_equals {
  local DESC=$1
  local EXPECTED=$2
  local ACTUAL
  ACTUAL="$(cat "$UFW_LOG" 2>/dev/null || true)"
  if [[ "$ACTUAL" == "$EXPECTED" ]]; then
    pass "$DESC"
  else
    fail "$DESC"
    printf 'expected ufw calls:\n%s\nactual ufw calls:\n%s\n' "$EXPECTED" "$ACTUAL" >&2
  fi
}
function reset_state {
  rm -f "$UFW_LOG" "$EVIL_MARKER" "$STATUS_YML"
}

# ---------------------------------------------------------------------------
# option handling: -y and -u are no longer accepted
reset_state
assert_rejected "-y (caller-chosen yq binary) is rejected" -a reset -y "$WORK_DIR/evil"
assert_no_evil "-y"
assert_rejected "-u (caller-chosen tracking file) is rejected" -a allow -u "$WORK_DIR/elsewhere.yml" 22
assert_equals "-u did not create a caller-chosen file" "$([[ -e "$WORK_DIR/elsewhere.yml" ]] && echo exists || echo absent)" "absent"
assert_ufw_log_equals "rejected invocations never reach ufw" ""

# ---------------------------------------------------------------------------
# action and rule argument validation
reset_state
assert_rejected "unknown action is rejected" -a "allow; id"
assert_rejected "rule argument beginning with - is rejected" -a allow -- -y "$WORK_DIR/evil"
assert_rejected "rule argument beginning with -- is rejected" -a allow 22 --dry-run
assert_rejected "rule argument with shell metacharacters is rejected" -a allow '22;touch /tmp/x'
assert_rejected "rule action without rule arguments is rejected" -a allow
assert_rejected "status with rule arguments is rejected" -a status 22
assert_rejected "reset with rule arguments is rejected" -a reset 22
assert_no_evil "argument validation"
assert_ufw_log_equals "rejected invocations never reach ufw" ""

# ---------------------------------------------------------------------------
# happy path: add rules, then reset deletes them via the tracking file
reset_state
assert_accepted "allow 22" -a allow 22
assert_accepted "allow from ... to any port 443" -a allow from 10.0.0.1 to any port 443
assert_accepted "allow application profile" -a allow 'Nginx Full'
assert_accepted "allow multiport" -a allow 80,443/tcp
assert_equals "tracking file has 4 entries" "$("$YQ" '.rules | length' "$STATUS_YML")" "4"
assert_equals "multiport argument is stored as a single item" "$("$YQ" '.rules[3].rule | join("|")' "$STATUS_YML")" "80,443/tcp"
assert_equals "tracking file mode is 600" "$(stat -c %a "$STATUS_YML")" "600"
assert_accepted "delete allow 22" -d -a allow 22
assert_equals "delete removed its tracking entry" "$("$YQ" '.rules | length' "$STATUS_YML")" "3"
rm -f "$UFW_LOG"
assert_accepted "reset" -a reset
assert_ufw_log_equals "reset deletes each tracked rule with intact argument vectors" \
"[delete][allow][from][10.0.0.1][to][any][port][443]
[delete][allow][Nginx Full]
[delete][allow][80,443/tcp]"
assert_equals "reset emptied the tracking file" "$("$YQ" '.rules | length' "$STATUS_YML")" "0"

# ---------------------------------------------------------------------------
# reset treats the user-writable tracking file as untrusted
reset_state
cat > "$STATUS_YML" <<YML
rules:
  - action: reset
    rule: ["22"]
  - action: allow
    rule: ["-y", "$WORK_DIR/evil"]
  - action: allow
    rule: ["22 -y $WORK_DIR/evil"]
  - action: "allow -v"
    rule: ["22"]
  - action: allow
    rule: ["--dry-run"]
  - action: allow
    rule: ["80"]
YML
assert_accepted "reset with crafted tracking file completes" -a reset
assert_no_evil "reset with crafted tracking file"
assert_ufw_log_equals "reset skips malformed entries and never word-splits rule items" \
"[delete][allow][22 -y $WORK_DIR/evil]
[delete][allow][80]"

# tracking file whose rules element is a map instead of a list
reset_state
printf 'rules:\n  "0 | .rules": {action: allow, rule: ["22"]}\n' > "$STATUS_YML"
assert_accepted "reset with non-list rules completes" -a reset
assert_ufw_log_equals "reset with non-list rules performs no ufw calls" ""

# ---------------------------------------------------------------------------
# a tracking file replaced by a symlink is refused and the target is untouched
reset_state
echo "do not touch" > "$WORK_DIR/target"
ln -s "$WORK_DIR/target" "$STATUS_YML"
assert_rejected "allow refuses a symlinked tracking file" -a allow 22
assert_rejected "reset refuses a symlinked tracking file" -a reset
assert_equals "symlink target was not modified" "$(cat "$WORK_DIR/target")" "do not touch"
assert_ufw_log_equals "ufw is not called when the tracking file is unusable" ""
rm -f "$STATUS_YML"

# ---------------------------------------------------------------------------
echo
if (( FAILURES > 0 )); then
  echo "$FAILURES test(s) failed" >&2
  exit 1
fi
echo "All tests passed"
