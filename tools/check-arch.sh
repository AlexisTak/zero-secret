#!/usr/bin/env bash
# Tests d'architecture — backlog L0.2. Appelé par `make test-arch` (donc par `make check`).
# Détecteurs testés contre fixtures de violation/clean dans tests/architecture/run.sh — lancer
# ce fichier après toute modification ici.
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

source "$SCRIPT_DIR/lib/check-apps-isolation.sh"
source "$SCRIPT_DIR/lib/check-no-direct-crypto.sh"
source "$SCRIPT_DIR/lib/check-webauthn-no-hsm.sh"
source "$SCRIPT_DIR/lib/check-cbom-coverage.sh"
source "$SCRIPT_DIR/lib/check-zs-crypto-deps.sh"

fail=0

if ! check_apps_isolation "$REPO_ROOT"; then
	echo "test-arch : violation d'isolation apps/ détectée ci-dessus." >&2
	fail=1
fi

if ! check_no_direct_crypto "$REPO_ROOT"; then
	echo "test-arch : import crypto direct détecté ci-dessus." >&2
	fail=1
fi

if ! check_webauthn_no_hsm "$REPO_ROOT"; then
	echo "test-arch : zs-webauthn dépend de zs-hsm, violation de frontière (ADR-008)." >&2
	fail=1
fi

if ! check_cbom_coverage "$REPO_ROOT"; then
	echo "test-arch : suite crypto sans entrée CBOM détectée ci-dessus (invariant 9, ADR-011)." >&2
	fail=1
fi

if ! check_zs_crypto_deps "$REPO_ROOT"; then
	echo "test-arch : zs-crypto dépend d'un crate applicatif, violation de frontière (ADR-012)." >&2
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

# api_generated.go (access-broker, admin-api) est généré par oapi-codegen depuis
# contracts/openapi/*.yaml (tools/generate-openapi.sh) — même invariant que pkg/gen ci-dessus.
if command -v go >/dev/null 2>&1; then
	source "$SCRIPT_DIR/lib/check-generated-up-to-date.sh"
	if ! check_generated_up_to_date "$REPO_ROOT" "bash tools/generate-openapi.sh" \
		apps/access-broker/internal/httpapi/api_generated.go \
		apps/admin-api/internal/httpapi/api_generated.go; then
		echo "test-arch : fichier généré divergent détecté ci-dessus (OpenAPI)." >&2
		fail=1
	fi
else
	echo "test-arch : NO-OP pour generated-up-to-date/OpenAPI — go absent de cet environnement." >&2
fi

if [[ "$fail" -eq 0 ]]; then
	echo "test-arch : aucune violation détectée."
fi

exit "$fail"
