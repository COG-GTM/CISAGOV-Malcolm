#!/usr/bin/env bash
# Rewrite sbom/SHA256SUMS over every file under sbom/ (except itself).
# Verify with:  (cd sbom && sha256sum -c SHA256SUMS)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
