#!/usr/bin/env bash
# PostToolUse — formate le fichier modifié. Ne bloque jamais (sortie 0).
set -uo pipefail

INPUT=$(cat)
FILE=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // empty')
[[ -z "$FILE" || ! -f "$FILE" ]] && exit 0

case "$FILE" in
  *.rs)    command -v rustfmt >/dev/null && rustfmt --edition 2024 "$FILE" 2>/dev/null ;;
  *.go)    command -v gofmt   >/dev/null && gofmt -w "$FILE" 2>/dev/null ;;
  *.ts|*.tsx|*.json) command -v prettier >/dev/null && prettier --write "$FILE" 2>/dev/null ;;
  *.cedar) command -v cedar   >/dev/null && cedar format --write "$FILE" 2>/dev/null ;;
  *.rego)  command -v opa     >/dev/null && opa fmt -w "$FILE" 2>/dev/null ;;
  *.proto) command -v buf     >/dev/null && buf format -w "$FILE" 2>/dev/null ;;
esac

exit 0
