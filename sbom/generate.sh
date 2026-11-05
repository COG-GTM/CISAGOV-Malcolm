#!/usr/bin/env bash
# Regenerate the Malcolm SBOM set under sbom/.
#
# For every Dockerfile under Dockerfiles/ and for the Python installer under
# scripts/, this writes:
#   sbom/source/<deployable>.{cdx,spdx}.json   repo files the deployable is built from
#   sbom/built/<deployable>.{cdx,spdx}.json    the published GHCR image (or, for the
#                                              installer, the resolved pip environment)
#   sbom/osv/{source,built}/<deployable>.osv.json   osv-scanner results for each SBOM
# then sbom/vulns.csv, sbom/licenses.csv, sbom/provenance.json, sbom/summary.md
# and sbom/SHA256SUMS.
#
# Images are read straight from the registry (syft registry: source); nothing is
# built locally and Docker Hub is never contacted.
#
# Environment:
#   MALCOLM_VERSION  image tag to scan (default: the tag used in docker-compose.yml)
#   IMAGE_REPO       registry prefix (default: ghcr.io/idaholab/malcolm)
#   PLATFORM         image platform (default: linux/amd64)
#   ONLY             space-separated deployable names to (re)generate, for development
#   SKIP_BUILT=1     skip the built view (no network needed except for OSV)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/sbom"
TOOLS="$OUT/tools"
PYTHON="${PYTHON:-python3}"
IMAGE_REPO="${IMAGE_REPO:-ghcr.io/idaholab/malcolm}"
PLATFORM="${PLATFORM:-linux/amd64}"
MALCOLM_VERSION="${MALCOLM_VERSION:-$(grep -P '^\s+image:.*/malcolm/' "$REPO_ROOT/docker-compose.yml" | awk '{print $2}' | cut -d: -f2 | sort | uniq -c | sort -nr | head -n 1 | awk '{print $2}')}"
ONLY="${ONLY:-}"
SKIP_BUILT="${SKIP_BUILT:-0}"

for tool in syft osv-scanner "$PYTHON" git; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done

# Packages only; file-level entries would triple the SBOM size and carry no
# supplier/version data. Unpinned requirements (">=") are recorded with the
# lower bound so they still show up as components in the source view.
export SYFT_FILE_METADATA_SELECTION=none
export SYFT_PYTHON_GUESS_UNPINNED_REQUIREMENTS=true
export SYFT_CHECK_FOR_APP_UPDATE=false
export OSV_SCANNER_TELEMETRY=0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT/source" "$OUT/built" "$OUT/osv/source" "$OUT/osv/built"

# Dockerfile name -> image name where they differ.
image_name() {
  case "$1" in
    filebeat) echo filebeat-oss ;;
    logstash) echo logstash-oss ;;
    nginx)    echo nginx-proxy ;;
    *)        echo "$1" ;;
  esac
}

wanted() {
  [[ -z "$ONLY" ]] && return 0
  for w in $ONLY; do [[ "$w" == "$1" ]] && return 0; done
  return 1
}

run_osv() {
  # osv-scanner exits 1 when vulnerabilities are found and 128 when the SBOM has
  # no scannable packages; both are normal here.
  local sbom="$1" out="$2" rc=0
  # run from $WORK: osv-scanner treats a cwd entry named "source" as ambiguous with its subcommand
  # see normalize.py: Go stdlib "go1.x" versions are rewritten in a scan-only copy
  local scan_in="$WORK/osv-input-$(basename "$sbom")"
  "$PYTHON" "$TOOLS/normalize.py" osv-input "$sbom" "$scan_in"
  (cd "$WORK" && osv-scanner scan source -L "$scan_in" --format json --output-file "$out" --verbosity error >/dev/null) || rc=$?
  if [[ $rc -eq 128 ]]; then
    echo '{"results": []}' > "$out"
  elif [[ $rc -ne 0 && $rc -ne 1 ]]; then
    echo "osv-scanner failed ($rc) on $sbom" >&2
    exit "$rc"
  fi
}

scan_dir() {
  # scan_dir <dir> <name> <out-prefix> [syft-json]
  local dir="$1" name="$2" prefix="$3" syftjson="${4:-}"
  local extra=()
  [[ -n "$syftjson" ]] && extra=(-o "syft-json=$syftjson")
  syft scan "dir:$dir" -q --source-name "$name" --source-version "$MALCOLM_VERSION" \
    -o "cyclonedx-json@1.5=$prefix.cdx.json" -o "spdx-json@2.3=$prefix.spdx.json" "${extra[@]}"
  "$PYTHON" "$TOOLS/normalize.py" licenses "$prefix.cdx.json" "$prefix.spdx.json"
}

scan_image() {
  # scan_image <image-ref> <out-prefix> <syft-json>
  syft scan "registry:$1" -q --platform "$PLATFORM" \
    -o "cyclonedx-json@1.5=$2.cdx.json" -o "spdx-json@2.3=$2.spdx.json" -o "syft-json=$3"
  "$PYTHON" "$TOOLS/normalize.py" licenses "$2.cdx.json" "$2.spdx.json"
}

echo "Malcolm version: $MALCOLM_VERSION  images: $IMAGE_REPO/*:$MALCOLM_VERSION ($PLATFORM)"
echo "syft $(syft version -o json | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["version"])')  osv-scanner $(osv-scanner --version | head -n1 | awk '{print $NF}')"

declare -a DEPLOYABLES=()
declare -A SOURCE_FILES=()

for df in "$REPO_ROOT"/Dockerfiles/*.Dockerfile; do
  svc="$(basename "$df" .Dockerfile)"
  DEPLOYABLES+=("$svc")
  wanted "$svc" || continue
  img="$IMAGE_REPO/$(image_name "$svc"):$MALCOLM_VERSION"
  echo "== $svc"

  stage="$WORK/stage/$svc"
  mkdir -p "$stage"
  mapfile -t paths < <("$PYTHON" "$TOOLS/dockerfile_sources.py" --root "$REPO_ROOT" "$df")
  paths+=("Dockerfiles/$svc.Dockerfile")
  for p in "${paths[@]}"; do
    (cd "$REPO_ROOT" && cp -a --parents "$p" "$stage/")
  done
  printf '%s\n' "${paths[@]}" | sort -u > "$WORK/$svc.sources.txt"
  echo "   source: ${#paths[@]} paths"
  scan_dir "$stage" "malcolm/$svc" "$OUT/source/$svc" "$WORK/$svc.source.syft.json"
  run_osv "$OUT/source/$svc.cdx.json" "$OUT/osv/source/$svc.osv.json"

  if [[ "$SKIP_BUILT" != 1 ]]; then
    echo "   built:  $img"
    scan_image "$img" "$OUT/built/$svc" "$WORK/$svc.built.syft.json"
    run_osv "$OUT/built/$svc.cdx.json" "$OUT/osv/built/$svc.osv.json"
  fi
done

# Python installer (scripts/install.py, scripts/configure, scripts/control.py, scripts/installer/)
svc=installer
DEPLOYABLES+=("$svc")
if wanted "$svc"; then
  echo "== $svc"
  stage="$WORK/stage/$svc"
  mkdir -p "$stage"
  (cd "$REPO_ROOT" && git ls-files scripts | grep -v '^scripts/third-party-' | cpio -pdm --quiet "$stage")
  (cd "$REPO_ROOT" && git ls-files scripts | grep -v '^scripts/third-party-' | sort -u) > "$WORK/$svc.sources.txt"
  scan_dir "$stage" "malcolm/$svc" "$OUT/source/$svc" "$WORK/$svc.source.syft.json"
  run_osv "$OUT/source/$svc.cdx.json" "$OUT/osv/source/$svc.osv.json"

  if [[ "$SKIP_BUILT" != 1 ]]; then
    venv="$WORK/venv"
    # --upgrade-deps: pip/setuptools in the venv come from PyPI, not from whatever the host Python bundles
    "$PYTHON" -m venv --upgrade-deps "$venv"
    "$venv/bin/pip" install --quiet --disable-pip-version-check -r "$REPO_ROOT/scripts/installer/requirements.txt"
    "$venv/bin/pip" freeze --all > "$OUT/built/$svc.requirements-resolved.txt"
    site="$(ls -d "$venv"/lib/python*/site-packages)"
    echo "   built:  resolved pip environment ($("$venv/bin/python" --version 2>&1))"
    scan_dir "$site" "malcolm/$svc-resolved" "$OUT/built/$svc" "$WORK/$svc.built.syft.json"
    run_osv "$OUT/built/$svc.cdx.json" "$OUT/osv/built/$svc.osv.json"
  fi
fi

"$PYTHON" "$TOOLS/enrich.py" --repo-root "$REPO_ROOT" --out "$OUT" --work "$WORK" \
  --version "$MALCOLM_VERSION" --image-repo "$IMAGE_REPO" --platform "$PLATFORM" \
  --deployables "${DEPLOYABLES[@]}"

"$TOOLS/manifest.sh"
echo "done: $(wc -l < "$OUT/SHA256SUMS") files listed in $OUT/SHA256SUMS"
