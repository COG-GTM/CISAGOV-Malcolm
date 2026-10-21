#!/usr/bin/env bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# This script is granted to members of the netdev group via a NOPASSWD sudoers
#   entry (/etc/sudoers.d/ufw_manager), so its command-line arguments must be
#   treated as untrusted input, and it must only read from and write to paths
#   that an unprivileged user cannot control.

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SCRIPT_PATH="$(realpath "$0")"

# Actions passed directly in to UFW (with "delete" prepended if -d is specified):
#   - allow
#   - deny
#   - reject
#   - limit
# Actions converted to the appropriate status command:
#   - status
#   - numbered
# Other actions:
#   - reset:
#        Reads the contents of UFW_STATUS_YML and performs "delete" operations
#        for all of the entries contained therein.
RULE_ACTIONS=( "allow" "deny" "reject" "limit" )
ALLOWED_ACTIONS=( "${RULE_ACTIONS[@]}" "reset" "status" "numbered" )
ACTION=status
VERBOSE=0
DELETE=

# Only fixed, root-owned binaries are executed; the caller may not choose them.
UFW_BIN=/usr/sbin/ufw
YQ_BIN=/usr/local/bin/yq

# UFW rule arguments are restricted to the characters needed for ports, protocols,
#   addresses/CIDRs, keywords, application profile names and simple comments, and
#   may never begin with "-" so they cannot be interpreted as options.
RULE_TOKEN_PATTERN='^[A-Za-z0-9][A-Za-z0-9 ._:/,-]*$'

# We'll keep a root-owned YML file to keep track of entries that have been previously
#   added to the firewall. Its location is fixed and cannot be overridden by the caller,
#   and it lives outside of any unprivileged user's control so that this script (which
#   runs as root) never creates, follows or rewrites a user-controlled path.
UFW_STATUS_DIR=/var/lib/malcolm
UFW_STATUS_YML="$UFW_STATUS_DIR/ufw-rules.yml"

# The following overrides exist solely so the regression tests can run as an
#   unprivileged user with stubbed binaries. They are ignored when running as root
#   (i.e., via sudo), so they cannot be used to influence a privileged invocation.
if (( EUID != 0 )); then
  UFW_BIN="${UFW_MANAGER_UFW_BIN:-$UFW_BIN}"
  YQ_BIN="${UFW_MANAGER_YQ_BIN:-$YQ_BIN}"
  UFW_STATUS_YML="${UFW_MANAGER_STATUS_YML:-$UFW_STATUS_YML}"
  UFW_STATUS_DIR="$(dirname -- "$UFW_STATUS_YML")"
fi

while getopts :a:dv opts; do
   case ${opts} in
      a) ACTION=${OPTARG,,} ;;
      d) DELETE=delete ;;
      v) VERBOSE=1 ;;
      :) echo "Option -$OPTARG requires an argument" >&2; exit 1 ;;
      *) echo "Unknown option -$OPTARG" >&2; exit 1 ;;
   esac
done
# remaining command-line options are UFW rule args
shift "$((OPTIND -1))"
RULE=("${@}")

[[ $VERBOSE == 1 ]] && set -x

function in_list {
  local NEEDLE=$1
  shift
  local ITEM
  for ITEM in "$@"; do
    [[ $ITEM == "$NEEDLE" ]] && return 0
  done
  return 1
}

function validate_rule_tokens {
  local TOKEN
  if (( $# == 0 )); then
    echo "No UFW rule arguments were specified" >&2
    return 1
  fi
  for TOKEN in "$@"; do
    if [[ ! $TOKEN =~ $RULE_TOKEN_PATTERN ]]; then
      echo "\"$TOKEN\" is not a valid UFW rule argument" >&2
      return 1
    fi
  done
  return 0
}

# Defense in depth: refuse to operate on a tracking file (or directory) that has
#   been replaced with a symlink or some other non-regular file.
function check_status_yml {
  if [[ -L "$UFW_STATUS_DIR" ]] || [[ -L "$UFW_STATUS_YML" ]]; then
    echo "Refusing to use \"$UFW_STATUS_YML\": symbolic links are not permitted" >&2
    return 1
  elif [[ -e "$UFW_STATUS_YML" ]] && [[ ! -f "$UFW_STATUS_YML" ]]; then
    echo "Refusing to use \"$UFW_STATUS_YML\": not a regular file" >&2
    return 1
  fi
  return 0
}

# Make sure the tracking file exists, is well-formed enough to be appended to, and
#   is readable only by its (root) owner.
function ensure_status_yml {
  check_status_yml || return 1
  if [[ ! -d "$UFW_STATUS_DIR" ]]; then
    mkdir -p -- "$UFW_STATUS_DIR"
    chmod 700 -- "$UFW_STATUS_DIR"
  fi
  if [[ ! -f "$UFW_STATUS_YML" ]] || [[ ! -s "$UFW_STATUS_YML" ]]; then
    ( set -o noclobber; rm -f -- "$UFW_STATUS_YML"; echo 'rules: []' > "$UFW_STATUS_YML" )
  fi
  chmod 600 -- "$UFW_STATUS_YML"
}

function add_to_yml {
  local ACTION_ARG=$1
  local -n RULE_ARG=$2
  if [[ -n "$UFW_STATUS_YML" ]]; then
    ACTION_ENV=$ACTION_ARG
    RULE_ENV="$(printf '%s\n' "${RULE_ARG[@]}")"
    DATE_ENV=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    export ACTION_ENV RULE_ENV DATE_ENV
    "$YQ_BIN" -i '.rules += [{"action": strenv(ACTION_ENV), "rule": (strenv(RULE_ENV) | split("\n")), "timestamp": strenv(DATE_ENV)}]' "$UFW_STATUS_YML"
  fi
}

function delete_from_yml {
  local ACTION_ARG=$1
  local -n RULE_ARG=$2
  if [[ -n "$UFW_STATUS_YML" ]]; then
    ACTION_ENV=$ACTION_ARG
    RULE_ENV="$(printf '%s\n' "${RULE_ARG[@]}")"
    export ACTION_ENV RULE_ENV
    "$YQ_BIN" -i '.rules |= map(select(
      (.action != strenv(ACTION_ENV)) or
      ((.rule | join("\n")) != strenv(RULE_ENV))
    ))' "$UFW_STATUS_YML" || true # a failed delete is non-fatal
  fi
}

# validate the requested action and rule arguments before doing anything else
if ! in_list "$ACTION" "${ALLOWED_ACTIONS[@]}"; then
  echo "\"$ACTION\" is not an allowed action" >&2
  exit 1
elif in_list "$ACTION" "${RULE_ACTIONS[@]}"; then
  validate_rule_tokens "${RULE[@]}" || exit 1
elif (( ${#RULE[@]} > 0 )); then
  echo "\"$ACTION\" does not accept UFW rule arguments" >&2
  exit 1
fi

if [[ ! -x "$UFW_BIN" ]]; then
  echo "$UFW_BIN does not exist or is not executable" >&2
  exit 1
fi

if [[ $ACTION == "status" ]]; then
  "$UFW_BIN" status

elif [[ $ACTION == "numbered" ]]; then
  "$UFW_BIN" status numbered

elif [[ $ACTION == "reset" ]]; then
  if [[ -n "$UFW_STATUS_YML" ]] && [[ -f "$UFW_STATUS_YML" ]]; then
    check_status_yml || exit 1
    # make a copy of the YML file to read entries out of so we're not modifying the same one we're reading
    TEMP_YML=$(mktemp --suffix=.yml)
    cp -- "$UFW_STATUS_YML" "$TEMP_YML"
    mapfile -t ENTRIES < <("$YQ_BIN" '.rules | keys | .[]' "$TEMP_YML")
    VERBOSE_FLAG=()
    [[ $VERBOSE == 1 ]] && VERBOSE_FLAG=(-v)
    for entry in "${ENTRIES[@]}"; do
      # defense in depth: only numeric indices, rule actions (never "reset") and
      #   well-formed rule arguments are accepted from the YML file
      if [[ ! $entry =~ ^[0-9]+$ ]]; then
        echo "Skipping malformed entry \"$entry\" in $UFW_STATUS_YML" >&2
        continue
      fi
      ACTION_VAL=$("$YQ_BIN" -r ".rules[$entry].action" "$TEMP_YML")
      mapfile -t RULE_ITEMS < <("$YQ_BIN" -r ".rules[$entry].rule[]" "$TEMP_YML")
      if ! in_list "$ACTION_VAL" "${RULE_ACTIONS[@]}" || ! validate_rule_tokens "${RULE_ITEMS[@]}"; then
        echo "Skipping malformed entry $entry in $UFW_STATUS_YML" >&2
        continue
      fi
      # recursively call this script to delete the rule (failures are non-fatal, what else can we do?)
      "$SCRIPT_PATH" "${VERBOSE_FLAG[@]}" -d -a "$ACTION_VAL" -- "${RULE_ITEMS[@]}" || true
    done
    rm -f -- "$TEMP_YML"
  else
    echo "The YML file tracking UFW rules does not exist or was not defined" >&2
    exit 1
  fi

else
  # make sure we'll be able to track the rule *before* changing the firewall, so
  #   that a rule is never applied without being recorded for a later reset
  if [[ -n "$UFW_STATUS_YML" ]]; then
    ensure_status_yml || exit 1
  fi

  # call UFW to add or delete the rule
  UFW_ARGS=()
  [[ -n "$DELETE" ]] && UFW_ARGS+=("$DELETE")
  UFW_ARGS+=("$ACTION" "${RULE[@]}")
  "$UFW_BIN" "${UFW_ARGS[@]}"

  # track rules created using this script in a YML file that we can use
  #   later to reset the whole thing back to a clean state
  if [[ -n "$UFW_STATUS_YML" ]]; then

    # we do a delete first (even if we're doing an add) to avoid duplicate entries in the YML

    # remove the action from our YML file
    delete_from_yml "$ACTION" RULE

    # now if we're adding, add the action to the YML file
    if [[ -z "$DELETE" ]]; then
      add_to_yml "$ACTION" RULE
    fi

  fi # $UFW_STATUS_YML file check
fi # $ACTION check
