#!/usr/bin/env bash
# PreToolUse — bloque tout import cryptographique direct hors de crates/zs-crypto.
# Règle 4 du CLAUDE.md. Sortie 2 = blocage, stderr renvoyé à Claude.
set -uo pipefail

INPUT=$(cat)
FILE=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // empty')
CONTENT=$(printf '%s' "$INPUT" | jq -r '.tool_input.content // .tool_input.new_string // empty')

[[ -z "$FILE" ]] && exit 0

# La façade et ses tests ont le droit d'importer les bibliothèques crypto.
case "$FILE" in
  */crates/zs-crypto/*|*/crates/zs-hsm/*) exit 0 ;;
esac

FORBIDDEN_RS='^\s*use\s+(ring|aws_lc_rs|openssl|p256|p384|ed25519_dalek|x25519_dalek|rsa|sha2|hmac|aes_gcm|chacha20poly1305|rustls::crypto)\b'
FORBIDDEN_GO='"(crypto/(ecdsa|ed25519|rsa|aes|cipher|hmac|sha256|sha512|elliptic)|golang\.org/x/crypto/[a-z0-9]+)"'

case "$FILE" in
  *.rs)
    if printf '%s' "$CONTENT" | grep -Eq "$FORBIDDEN_RS"; then
      echo "BLOQUÉ — import cryptographique direct dans $FILE." >&2
      echo "Règle 4 : toute opération crypto passe par crates/zs-crypto." >&2
      echo "Action attendue : ajouter l'opération à la façade sous forme de suite versionnée," >&2
      echo "la déclarer au CBOM, puis l'appeler depuis ici." >&2
      exit 2
    fi
    ;;
  *.go)
    if printf '%s' "$CONTENT" | grep -Eq "$FORBIDDEN_GO"; then
      echo "BLOQUÉ — import cryptographique direct dans $FILE." >&2
      echo "Règle 4 : passer par pkg/zscrypto (binding de crates/zs-crypto)." >&2
      exit 2
    fi
    ;;
esac

# Garde-fou complémentaire : refus par défaut (règle 2).
if printf '%s' "$CONTENT" | grep -Eq 'unwrap_or\(true\)|unwrap_or_default\(\).*[Aa]llow|return true.*// *(fallback|default)'; then
  echo "BLOQUÉ — valeur par défaut potentiellement permissive détectée dans $FILE." >&2
  echo "Règle 2 : tout chemin d'erreur produit un refus explicite." >&2
  exit 2
fi

exit 0
