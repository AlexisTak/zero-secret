#!/usr/bin/env bash
# Tests d'architecture — backlog L0.2. Appelé par `make test-arch` (donc par `make check`).
# Détecteurs testés contre fixtures de violation/clean dans tests/architecture/run.sh — lancer
# ce fichier après toute modification ici.
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

source "$SCRIPT_DIR/lib/check-apps-isolation.sh"
source "$SCRIPT_DIR/lib/check-no-direct-crypto.sh"

fail=0

if ! check_apps_isolation "$REPO_ROOT"; then
	echo "test-arch : violation d'isolation apps/ détectée ci-dessus." >&2
	fail=1
fi

if ! check_no_direct_crypto "$REPO_ROOT"; then
	echo "test-arch : import crypto direct détecté ci-dessus." >&2
	fail=1
fi

# La vérification "fichier généré à jour" dépend de `buf`, absent de cet environnement de dev.
# Le mécanisme est testé indépendamment (tests/architecture/run.sh, fixture generated-drift) ;
# ici, no-op documenté tant que buf n'est pas disponible ou que contracts/ n'a rien à générer.
if command -v buf >/dev/null 2>&1; then
	source "$SCRIPT_DIR/lib/check-generated-up-to-date.sh"
	if ! check_generated_up_to_date "$REPO_ROOT" "buf generate contracts/proto" contracts; then
		echo "test-arch : fichier généré divergent détecté ci-dessus." >&2
		fail=1
	fi
else
	echo "test-arch : NO-OP pour generated-up-to-date — buf absent de cet environnement." >&2
fi

if [[ "$fail" -eq 0 ]]; then
	echo "test-arch : aucune violation détectée."
fi

exit "$fail"
