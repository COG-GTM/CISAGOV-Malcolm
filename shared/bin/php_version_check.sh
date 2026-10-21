#!/usr/bin/env bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Print the installed PHP version(s) and exit non-zero if any PHP SAPI is
# older than PHP_MIN_VERSION. Used at image build time (htadmin, file-upload)
# so that a build cannot succeed with a PHP release that predates the fixes
# for CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell"); the first fixed
# 8.4.x release is 8.4.27. Can also be run against a built image, e.g.:
#   docker run --rm --entrypoint /usr/local/bin/php_version_check.sh <image>

set -euo pipefail

PHP_MIN_VERSION="${1:-${PHP_MIN_VERSION:-8.4.27}}"

version_ge() {
  # usage: version_ge 8.4.27 8.4.26 -> true if $1 >= $2
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]
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
    if version_ge "$VERSION" "$PHP_MIN_VERSION"; then
      echo "OK: $BIN is PHP $VERSION (>= $PHP_MIN_VERSION)"
    else
      echo "ERROR: $BIN is PHP $VERSION, older than required minimum $PHP_MIN_VERSION" >&2
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
