#!/usr/bin/env bash
# Assemble a deployable Function App folder in azure-function/dist/.
#
# The scripts stay where they are in the repo (one copy, the tested one); this
# copies them next to the wrapper so the deployed package is self-contained.
#
#   ./azure-function/package.sh
#   cd azure-function/dist && func azure functionapp publish <app-name> --python
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
scripts="$here/../phishing-inbox-triage/scripts"
dist="$here/dist"

rm -rf "$dist"
mkdir -p "$dist/scripts"
cp "$here/function_app.py" "$here/runner.py" "$here/host.json" "$here/requirements.txt" "$dist/"
# collect_export imports the other three, so all four ship.
cp "$scripts/graph_submit.py" "$scripts/collect_export.py" \
   "$scripts/triage.py" "$scripts/parse_headers.py" "$dist/scripts/"

echo "built $dist"
find "$dist" -type f | sort | sed "s|^$dist/|  |"
