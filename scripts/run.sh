#!/usr/bin/env bash
# One-command local runner (no compose needed): builds and scans the current host.
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -q -t bastion-open:local . | tail -1
docker run --rm \
  -v /:/host:ro \
  -v "$(pwd)/config:/app/config:ro" \
  -v bastion-open-data:/data \
  bastion-open:local "$@"
echo
echo "report: docker run --rm -v bastion-open-data:/data alpine cat /data/report.md"
