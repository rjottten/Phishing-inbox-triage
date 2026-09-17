#!/usr/bin/env bash
# Copy the shipped scripts into the function app so they deploy with it.
# They are stdlib-only, so this is a copy and nothing more.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/../skills/phishing-inbox-triage/scripts"

rm -rf "$here/scripts"
mkdir -p "$here/scripts"
for f in graph_submit.py triage.py parse_headers.py; do
    cp "$src/$f" "$here/scripts/$f"
done
echo "copied $(ls "$here/scripts" | tr '\n' ' ')into azure-function/scripts/"
