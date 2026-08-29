#!/usr/bin/env bash
# Contrôle statique de deploy/compose.dev.yml — pas de bind non-loopback, pas de privilège ni de
# namespace de l'hôte non justifié.
#
# Ce script n'est qu'un point d'entrée : le contrôle réel vit dans check_compose_dev.py, qui parse
# le YAML au lieu de le grepper. La version précédente, à base de grep, laissait passer les formes
# les plus probables d'une régression — port non entre guillemets, syntaxe longue avec host_ip,
# network_mode: host, cap_add — et son motif \s (extension GNU) ne matchait rien sur BSD/macOS,
# produisant un « OK » sans avoir rien vérifié.
#
# Refus par défaut (règle absolue #2) : interpréteur Python absent, PyYAML absent ou fichier
# illisible sont des échecs explicites, jamais un succès silencieux.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
compose_file="$racine/deploy/compose.dev.yml"
controle="$racine/tests/security/infrastructure/check_compose_dev.py"

if [[ ! -f "$compose_file" ]]; then
  echo "check_compose_dev: $compose_file introuvable" >&2
  exit 1
fi

for interpreteur in python3 python; do
  if command -v "$interpreteur" >/dev/null 2>&1; then
    exec "$interpreteur" "$controle" "$compose_file"
  fi
done

echo "check_compose_dev: aucun interpréteur Python trouvé — contrôle impossible, refus par défaut" >&2
exit 1
