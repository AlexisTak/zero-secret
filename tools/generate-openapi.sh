#!/usr/bin/env bash
# Régénère les types + interface serveur HTTP depuis contracts/openapi/*.yaml (oapi-codegen v2.8.0,
# via `go run` — aucune installation globale requise). Fichiers générés committés
# (apps/<app>/internal/httpapi/api_generated.go) : ne jamais les éditer à la main.
#
# oapi-codegen doit tourner depuis le module Go cible : lancé depuis contracts/openapi/ il ne
# trouve aucun go.mod dans les 5 niveaux parents attendus et ne génère rien, sans erreur bloquante.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
OAPI_CODEGEN="github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0"

generate() {
	local app="$1"
	local spec="$REPO_ROOT/contracts/openapi/$app.yaml"
	local config="$REPO_ROOT/contracts/openapi/$app.gen.yaml"
	echo "-- $app --"
	(cd "$REPO_ROOT/apps/$app" && go run "$OAPI_CODEGEN" -config "$config" "$spec")
}

generate access-broker
generate admin-api

echo "Types et interface serveur régénérés dans apps/{access-broker,admin-api}/internal/httpapi/api_generated.go."
