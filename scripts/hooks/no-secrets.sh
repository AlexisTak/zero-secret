#!/usr/bin/env bash
# PreToolUse — bloque l'écriture d'un secret en dur, y compris dans les tests et fixtures.
# Règle 1 du CLAUDE.md. Sortie 2 = blocage.
set -uo pipefail

INPUT=$(cat)
FILE=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // empty')
CONTENT=$(printf '%s' "$INPUT" | jq -r '.tool_input.content // .tool_input.new_string // empty')

[[ -z "$FILE" || -z "$CONTENT" ]] && exit 0

# Motifs de secrets. Volontairement large : un faux positif coûte moins qu'une fuite.
PATTERNS=(
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  '(password|passwd|secret|token|api_?key|private_?key)\s*[:=]\s*["'"'"'][^"'"'"'{$][^"'"'"']{7,}'
  'Bearer\s+[A-Za-z0-9._~+/-]{20,}'
  'hvs\.[A-Za-z0-9_-]{20,}'
  'AKIA[0-9A-Z]{16}'
  'ghp_[A-Za-z0-9]{30,}'
)

for p in "${PATTERNS[@]}"; do
  if printf '%s' "$CONTENT" | grep -Eqi "$p"; then
    echo "BLOQUÉ — secret potentiellement en dur dans $FILE (motif: ${p:0:40}...)." >&2
    echo "Règle 1 : aucun secret durable dans le dépôt, y compris en fixture de test." >&2
    echo "Action attendue : générer la valeur à l'exécution, ou la lire depuis OpenBao." >&2
    echo "Si c'est un faux positif, dis-le explicitement à l'utilisateur avant de contourner." >&2
    exit 2
  fi
done

exit 0
