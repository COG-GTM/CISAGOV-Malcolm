#!/bin/bash
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.
#
# Regression test for the hardened /hh-extracted-files/<sensor>/ proxy route
# (GHSA-j89q-3q7m-8vr6): the sensor host taken from the URL must be restricted to the
# operator-configured allowlist, the user's credentials must not be forwarded, and the
# response must be treated as an untrusted download.
#
# Usage (from the repository root): bash nginx/tests/test_hedgehog_extracted_files.sh
# Requires only bash; does not require nginx or OpenResty.

set -u

NGINX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR="$NGINX_DIR/scripts/hedgehog_extracted_files_config.sh"
LOCATION_CONF="$NGINX_DIR/nginx_hedgehog_extracted_files_location.conf"
MAPS_CONF="$NGINX_DIR/nginx_hedgehog_extracted_files_maps.conf"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PASS=0
FAIL=0

check() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAIL: $description" >&2
  fi
}

render() {
  # render <hosts value> <ssl verify value>; outputs land in $WORK_DIR
  NGINX_HEDGEHOG_EXTRACTED_FILES_HOSTS="$1" \
  NGINX_HEDGEHOG_EXTRACTED_FILES_SSL_VERIFY="$2" \
    bash "$GENERATOR" "$WORK_DIR/hosts.conf" "$WORK_DIR/ssl.conf" /trust/bundle.pem
}

# --- the generated allowlist map -----------------------------------------------------------

check "empty allowlist renders" render "" false
check "empty allowlist denies by default" grep -q '^  default 0;$' "$WORK_DIR/hosts.conf"
check "empty allowlist contains no allowed hosts" bash -c "! grep -q ' 1;$' '$WORK_DIR/hosts.conf'"
check "map uses hostname matching" grep -q '^  hostnames;$' "$WORK_DIR/hosts.conf"
check "map is keyed on the URL host" grep -q '^map \$hh_extracted_files_host \$hh_extracted_files_host_allowed {$' "$WORK_DIR/hosts.conf"

check "hostnames, IPs and *.domain render" render "sensor1 192.168.122.57 *.sensors.example.org" false
check "hostname entry allowed" grep -qx '  "sensor1" 1;' "$WORK_DIR/hosts.conf"
check "IP entry allowed" grep -qx '  "192.168.122.57" 1;' "$WORK_DIR/hosts.conf"
check "*.domain entry allowed" grep -qx '  "\*.sensors.example.org" 1;' "$WORK_DIR/hosts.conf"
check "no other entries allowed" bash -c "[[ \$(grep -c ' 1;$' '$WORK_DIR/hosts.conf') -eq 3 ]]"

# wildcard entries must not be pathname-expanded against the working directory
GLOB_DIR="$WORK_DIR/glob" && mkdir -p "$GLOB_DIR" && : > "$GLOB_DIR/sensor.example.org"
check "*.domain renders with matching filenames in cwd" bash -c "cd '$GLOB_DIR' && \
  NGINX_HEDGEHOG_EXTRACTED_FILES_HOSTS='*.example.org' NGINX_HEDGEHOG_EXTRACTED_FILES_SSL_VERIFY=false \
  bash '$GENERATOR' '$WORK_DIR/hosts.conf' '$WORK_DIR/ssl.conf' /trust/bundle.pem"
check "*.domain entry is kept literally" grep -qx '  "\*.example.org" 1;' "$WORK_DIR/hosts.conf"
check "*.domain entry is not expanded to filenames" bash -c "! grep -q 'sensor.example.org' '$WORK_DIR/hosts.conf'"
check "newline-separated entries are split" render $'sensor1\nsensor2' false
check "newline-separated second entry allowed" grep -qx '  "sensor2" 1;' "$WORK_DIR/hosts.conf"

# entries that could break out of the map or match everything must be rejected outright
for BAD in \
  'sensor1;' \
  '"sensor1"' \
  'sensor1"' \
  '*' \
  '*.' \
  '.example.org' \
  '~.*' \
  'host$name' \
  'host name' \
  'host\name' \
  'host{name}' \
  '-sensor' \
  'sensor-' \
  '[::1]'
do
  check "rejects allowlist entry: $BAD" bash -c "! render '$BAD' false"
done

# --- the generated TLS verification include -------------------------------------------------

check "ssl verify off by default" render "sensor1" ""
check "ssl verify off renders proxy_ssl_verify off" grep -qx 'proxy_ssl_verify off;' "$WORK_DIR/ssl.conf"
check "ssl verify false renders" render "sensor1" false
check "ssl verify false renders proxy_ssl_verify off" grep -qx 'proxy_ssl_verify off;' "$WORK_DIR/ssl.conf"
check "ssl verify true renders" render "sensor1" true
check "ssl verify true renders proxy_ssl_verify on" grep -qx 'proxy_ssl_verify on;' "$WORK_DIR/ssl.conf"
check "ssl verify true uses trusted CA bundle" grep -qx 'proxy_ssl_trusted_certificate /trust/bundle.pem;' "$WORK_DIR/ssl.conf"
check "ssl verify true checks the sensor name" grep -qx 'proxy_ssl_name \$hh_extracted_files_host;' "$WORK_DIR/ssl.conf"

# --- the shared location body ----------------------------------------------------------------

check "location requires authentication" grep -qx 'include /etc/nginx/nginx_auth_rt.conf;' "$LOCATION_CONF"
check "location is GET-only" grep -qx 'limit_except GET { deny all; }' "$LOCATION_CONF"
check "location captures URL host into map key" grep -qx 'set \$hh_extracted_files_host \$2;' "$LOCATION_CONF"
check "location rejects non-allowlisted hosts with 403" bash -c "grep -A2 'if (\$hh_extracted_files_host_allowed != 1) {' '$LOCATION_CONF' | grep -q 'return 403;'"
check "allowlist check precedes the rewrite" bash -c "[[ \$(grep -n 'return 403;' '$LOCATION_CONF' | cut -d: -f1) -lt \$(grep -n '^rewrite ' '$LOCATION_CONF' | cut -d: -f1) ]]"
check "proxy target uses the validated host on port 8006 only" grep -qx 'proxy_pass https://\$hh_extracted_files_host:8006;' "$LOCATION_CONF"
check "TLS verification is configurable" grep -qx 'include /etc/nginx/nginx_hedgehog_extracted_files_ssl_rt.conf;' "$LOCATION_CONF"
check "location hard-codes no proxy_ssl_verify off" bash -c "! grep -q 'proxy_ssl_verify off' '$LOCATION_CONF'"
check "Authorization header is cleared" grep -qx 'proxy_set_header Authorization "";' "$LOCATION_CONF"
check "Cookie header is cleared" grep -qx 'proxy_set_header Cookie "";' "$LOCATION_CONF"
check "upstream Set-Cookie is hidden" grep -qx 'proxy_hide_header Set-Cookie;' "$LOCATION_CONF"
check "upstream Content-Disposition is replaced" grep -qx 'proxy_hide_header Content-Disposition;' "$LOCATION_CONF"
check "Content-Disposition is added" grep -qx 'add_header Content-Disposition \$hh_extracted_files_disposition always;' "$LOCATION_CONF"
check "nosniff is added" grep -qx 'add_header X-Content-Type-Options nosniff always;' "$LOCATION_CONF"
check "CSP sandbox is added" grep -q '^add_header Content-Security-Policy "sandbox[^"]*" always;$' "$LOCATION_CONF"
check "disposition defaults to attachment" grep -q '^  default *"attachment";$' "$MAPS_CONF"

# --- both server configurations use the shared body -----------------------------------------

for CONF in "$NGINX_DIR/nginx.conf" "$NGINX_DIR/nginx_readonly.conf"; do
  NAME="$(basename "$CONF")"
  check "$NAME includes the maps" grep -qx '  include /etc/nginx/nginx_hedgehog_extracted_files_maps.conf;' "$CONF"
  check "$NAME hh-extracted-files location uses the shared body" bash -c "grep -A1 'location ~\* ^/(dashboards/app/)?hh-extracted-files/' '$CONF' | grep -qx '      include /etc/nginx/nginx_hedgehog_extracted_files_location.conf;'"
  check "$NAME has no unguarded proxy to the URL host" bash -c "! grep -qE 'set \\\$upstream \\\$2:8006|proxy_set_header Host \\\$2;' '$CONF'"
done

echo "passed: $PASS, failed: $FAIL"
[[ $FAIL -eq 0 ]]
