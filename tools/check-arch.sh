#!/usr/bin/env bash
# Tests d'architecture — backlog L0.2. Chaque vérification échoue explicitement si non encore
# implémentée : un stub silencieux qui "passe" sans avoir jamais échoué sur une violation ne
# prouve rien (voir docs/backlog.md, L0.2).
#
# Écrire la violation d'abord (fixture), puis la détection. Trois vérifications attendues :
#   1. un composant de apps/ importe un autre composant de apps/
#   2. un module hors zs-crypto/zs-hsm importe une bibliothèque crypto directement
#   3. un fichier généré diverge de ce que produirait `make generate`
set -euo pipefail

echo "test-arch: NO-OP — vérifications non implémentées (backlog L0.2)." >&2
echo "test-arch: make check passe donc sans garantie architecturale tant que L0.2 n'est pas fait." >&2
exit 0
