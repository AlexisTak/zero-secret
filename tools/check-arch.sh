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

# Seul le Go est généré par buf et committé (pkg/gen/) — voir contracts/buf.gen.yaml. Le Rust
# est généré à la compilation par crates/zs-policy/build.rs, non committé (ADR-004) : rien à
# comparer ici pour lui.
if command -v buf >/dev/null 2>&1; then
	source "$SCRIPT_DIR/lib/check-generated-up-to-date.sh"
	if ! check_generated_up_to_date "$REPO_ROOT" "cd contracts && buf generate" pkg/gen; then
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
