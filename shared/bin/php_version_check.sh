#!/usr/bin/env bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Print the installed PHP version(s) and exit non-zero if any PHP SAPI is
# older than the minimum fixed release for its major.minor series. Used at
# image build time (htadmin, file-upload) so that a build cannot succeed with
# a PHP release that predates the fixes for CVE-2026-109618 and
# CVE-2026-109619 ("PHP2Shell"). PHP_MIN_VERSION (or the positional
# arguments) is a space-separated list of fixed releases, one per series;
# the default is the set of first fixed releases from the advisory. A PHP
# whose series is older than every listed series fails; a series newer than
# every listed one passes (it was released after the fix).
# Can also be run against a built image, e.g.:
#   docker run --rm --entrypoint /usr/local/bin/php_version_check.sh <image>

set -euo pipefail

DEFAULT_MIN_VERSIONS="8.2.35 8.3.36 8.4.27 8.5.12"
if (( $# > 0 )); then
  MIN_VERSIONS="$*"
else
  MIN_VERSIONS="${PHP_MIN_VERSION:-$DEFAULT_MIN_VERSIONS}"
fi

version_ge() {
  # usage: version_ge 8.4.27 8.4.26 -> true if $1 >= $2
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]
}

min_for_series() {
  # usage: min_for_series 8.4.26 -> the listed minimum whose major.minor matches,
  # else "" if the series is newer than all listed ones, else the oldest listed
  # minimum (so an older unlisted series always fails)
  local SERIES="${1%.*}" MIN OLDEST="" NEWEST=""
  for MIN in $MIN_VERSIONS; do
    [[ "${MIN%.*}" == "$SERIES" ]] && { echo "$MIN"; return; }
    [[ -z "$OLDEST" ]] || version_ge "$OLDEST" "$MIN" && OLDEST="$MIN"
    [[ -z "$NEWEST" ]] || version_ge "$MIN" "$NEWEST" && NEWEST="$MIN"
  done
  if version_ge "$1" "$NEWEST"; then echo ""; else echo "$OLDEST"; fi
}

RESULT=0
FOUND=0

for BIN in php php-fpm php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 php-cgi; do
  if command -v "$BIN" >/dev/null 2>&1; then
    FOUND=1
    # e.g. "PHP 8.4.27 (fpm-fcgi) (built: ...)" or "PHP 8.4.27 (cli) (built: ...)"
    VERSION_LINE="$("$BIN" -v 2>/dev/null | head -n 1)"
    VERSION="$(echo "$VERSION_LINE" | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')"
    if [[ -z "$VERSION" ]]; then
      echo "ERROR: could not parse PHP version from \"$BIN -v\" (${VERSION_LINE:-no output})" >&2
      RESULT=1
      continue
    fi
    MIN_VERSION="$(min_for_series "$VERSION")"
    if [[ -z "$MIN_VERSION" ]]; then
      echo "OK: $BIN is PHP $VERSION (series newer than all listed minimums: $MIN_VERSIONS)"
    elif version_ge "$VERSION" "$MIN_VERSION"; then
      echo "OK: $BIN is PHP $VERSION (>= $MIN_VERSION)"
    else
      echo "ERROR: $BIN is PHP $VERSION, older than required minimum $MIN_VERSION" >&2
      RESULT=1
    fi
  fi
done

if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${db:Status-Status} ${Package} ${Version}\n' 'php*' 2>/dev/null | \
    awk '$1 == "installed" { print "package: " $2 " " $3 }' || true
fi

if (( FOUND == 0 )); then
  echo "ERROR: no PHP binaries found" >&2
  RESULT=1
fi

exit $RESULT
