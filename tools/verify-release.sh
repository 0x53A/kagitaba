#!/usr/bin/env bash
# Run this script from a reviewed source checkout, not from an unverified bundle.
set -euo pipefail
if [[ $# != 2 || ! $2 =~ ^[0-9a-f]{40}$ ]]; then
  echo "Usage: bash tools/verify-release.sh DISTRIBUTION_DIR EXPECTED_SOURCE_COMMIT" >&2
  exit 2
fi
cd -- "$1"
expected_commit=$2
policy=(
  --repo 0x53A/kagitaba
  --cert-identity https://github.com/0x53A/kagitaba/.github/workflows/release.yml@refs/heads/main
  --source-ref refs/heads/main
  --source-digest "$expected_commit"
  --deny-self-hosted-runners
)
for artifact in kagitaba-app kagitaba-app-x86_64-unknown-linux-gnu.tar.gz sbom.spdx.json SHA256SUMS; do
  gh attestation verify "$artifact" "${policy[@]}" --bundle provenance.sigstore.json
done
gh attestation verify kagitaba-app "${policy[@]}" --bundle sbom.sigstore.json \
  --predicate-type https://spdx.dev/Document
sha256sum --strict --check SHA256SUMS
echo "Verified build provenance, SBOM attestation, and checksums for $expected_commit"
