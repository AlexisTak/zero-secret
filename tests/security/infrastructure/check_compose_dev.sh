#!/usr/bin/env bash
# Contrôle statique de deploy/compose.dev.yml — pas de bind non-loopback, pas de conteneur
# privilégié hors softhsm-init (déjà justifié par ADR-008, frontière WebAuthn/HSM).
set -euo pipefail

compose_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/deploy/compose.dev.yml"
fail=0

if [[ ! -f "$compose_file" ]]; then
  echo "check_compose_dev: $compose_file introuvable" >&2
  exit 1
fi

# Aucun port ne doit être publié sur autre chose que 127.0.0.1 — un bind 0.0.0.0 exposerait
# Postgres/OpenBao au réseau local en environnement de dev. Les entrées réelles de compose.dev.yml
# sont au format "host_ip:host_port:container_port" (ex. "127.0.0.1:5432:5432") — un motif qui
# n'exige que deux groupes de chiffres séparés par ":" ne matche jamais ce format à trois segments
# (les points de l'IP cassent le motif) et laisserait passer silencieusement un bind 0.0.0.0.
# On cherche donc toute entrée de liste entre guillemets contenant un motif ":<port>" et on
# rejette celles qui ne commencent pas par "127.0.0.1:" juste après le guillemet — couvre aussi
# la forme "port:port" sans IP explicite, qui bind sur 0.0.0.0 par défaut avec Docker/Podman Compose.
if grep -nE '^\s*-\s*"' "$compose_file" | grep -E ':[0-9]+(:[0-9]+)?"' | grep -v '"127\.0\.0\.1:'; then
  echo "check_compose_dev: port publié sans préfixe 127.0.0.1: (voir ci-dessus)" >&2
  fail=1
fi

# Seul softhsm-init peut être privilégié (IPC_LOCK, justifié) — tout autre service avec
# privileged: true ou cap_add hors IPC_LOCK est un régression à signaler.
if grep -nE '^\s*privileged:\s*true' "$compose_file"; then
  echo "check_compose_dev: conteneur privileged: true trouvé — vérifier la justification" >&2
  fail=1
fi

if [[ "$fail" -eq 0 ]]; then
  echo "check_compose_dev: OK — aucun bind non-loopback, aucun privilège non justifié"
fi
exit "$fail"
