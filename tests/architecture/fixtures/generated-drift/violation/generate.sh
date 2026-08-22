#!/usr/bin/env bash
# Générateur factice pour le test — remplace `buf generate` (indisponible en local ici).
# Déterministe : mêmes contrats -> même sortie.
set -euo pipefail
cd "$(dirname "$0")"
tr '[:lower:]' '[:upper:]' <contracts/source.txt >generated/output.txt
