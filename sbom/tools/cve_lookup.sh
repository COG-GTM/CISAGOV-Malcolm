#!/usr/bin/env bash
# Answer "are we exposed to <CVE>?" from the committed OSV results.
#
#   sbom/tools/cve_lookup.sh CVE-2025-12345 [GHSA-... ...]
#
# Prints one line per (view, deployable, package) where the identifier appears
# either as the OSV record id or as an alias (CVE ids are usually aliases of
# distro or GHSA records). Exit 0 if found anywhere, 1 if not.
set -euo pipefail
[[ $# -ge 1 ]] || { echo "usage: $0 <CVE-ID|GHSA-ID> ..." >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
found=1
for id in "$@"; do
  hits="$(jq -r --arg id "$id" '
      .results[]?.packages[]? as $p
      | $p.vulnerabilities[]?
      | select(.id == $id or ((.aliases // []) | index($id)))
      | [ (input_filename | capture("osv/(?<view>[^/]+)/(?<dep>[^/]+)\\.osv\\.json")) as $f | $f.view, $f.dep,
          $p.package.ecosystem, $p.package.name, $p.package.version, .id,
          ([.affected[]? | select((.package.name | ascii_downcase) == ($p.package.name | ascii_downcase)) | .ranges[]?.events[]? | .fixed // empty] | unique | join(",") | if . == "" then "no fix listed" else "fixed in " + . end)
        ] | @tsv' osv/*/*.osv.json | LC_ALL=C sort -u)"
  if [[ -n "$hits" ]]; then
    found=0
    printf 'view\tdeployable\tecosystem\tpackage\tversion\tosv_id\tfix\n%s\n' "$hits" | column -t -s $'\t'
  else
    echo "$id: not present in any Malcolm deployable (checked $(ls osv/*/*.osv.json | wc -l) OSV result files)"
  fi
done
exit $found
