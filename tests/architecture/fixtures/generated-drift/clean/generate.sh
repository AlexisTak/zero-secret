#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
tr '[:lower:]' '[:upper:]' <contracts/source.txt >generated/output.txt
