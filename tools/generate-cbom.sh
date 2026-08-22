#!/usr/bin/env bash
# Régénère l'inventaire cryptographique (CBOM) depuis les suites déclarées dans zs-crypto.
# Non implémenté — aucune suite crypto n'existe encore (backlog, après validation référent-crypto).
set -euo pipefail

echo "generate-cbom: NO-OP — aucune suite crypto déclarée pour l'instant." >&2
echo '{"bomFormat":"CBOM","specVersion":"NON-IMPLEMENTE","components":[]}'
