#!/usr/bin/env bash
# Vérification du corpus Cedar — backlog L2.1 (ADR-003). Appelé par `make test`.
#
# Deux étapes, dans cet ordre :
#   1. `cedar validate` en mode strict, avec --deny-warnings : toute politique du corpus doit
#      typer contre contracts/cedar/schema.cedarschema.json. C'est la garantie apportée par
#      ADR-003 contre la confusion de requête ; une politique qui ne valide pas est un échec,
#      pas un avertissement.
#   2. `cedar run-tests` sur chaque fichier de cas de policies/tests/ : cas nominaux ET cas de
#      refus attendus.
#
# Le CLI Cedar attend un fichier de politiques unique ; le corpus est réparti en plusieurs
# fichiers dans policies/access/. On les concatène dans un fichier temporaire. Les identifiants
# de politique sont fixés par les annotations @id() : la concaténation ne les déplace donc pas.
#
# N'évalue rien d'autre que ce que le dépôt contient : aucun accès réseau, aucun état externe.
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

SCHEMA="$REPO_ROOT/contracts/cedar/schema.cedarschema.json"
ACCESS_DIR="$REPO_ROOT/policies/access"
TESTS_DIR="$REPO_ROOT/policies/tests"

if ! command -v cedar >/dev/null 2>&1; then
	echo "cedar-test : CLI 'cedar' absent du PATH." >&2
	echo "             installer avec 'cargo install cedar-policy-cli --locked'." >&2
	exit 1
fi

if [[ ! -f "$SCHEMA" ]]; then
	echo "cedar-test : schéma introuvable : $SCHEMA" >&2
	exit 1
fi

BUNDLE=$(mktemp -t cedar-access.XXXXXX)
trap 'rm -f "$BUNDLE"' EXIT

shopt -s nullglob
policies=("$ACCESS_DIR"/*.cedar)
shopt -u nullglob

if [[ ${#policies[@]} -eq 0 ]]; then
	echo "cedar-test : aucune politique dans $ACCESS_DIR." >&2
	exit 1
fi

cat "${policies[@]}" >"$BUNDLE"

fail=0

echo "-- cedar validate (strict, --deny-warnings) : ${#policies[@]} fichier(s) --"
if ! cedar validate \
	--schema "$SCHEMA" --schema-format json \
	--policies "$BUNDLE" \
	--validation-mode strict --deny-warnings; then
	echo "cedar-test : validation du corpus d'accès en échec." >&2
	fail=1
fi

shopt -s nullglob globstar
cases=("$TESTS_DIR"/**/*.json)
shopt -u nullglob globstar

if [[ ${#cases[@]} -eq 0 ]]; then
	# Refus par défaut appliqué à l'outillage : une politique sans cas de test n'est pas
	# terminée (policies/CLAUDE.md). Un corpus de tests vide est un échec, pas un succès.
	echo "cedar-test : aucun fichier de cas dans $TESTS_DIR." >&2
	exit 1
fi

for f in "${cases[@]}"; do
	echo "-- cedar run-tests : ${f#"$REPO_ROOT/"} --"
	if ! cedar run-tests \
		--schema "$SCHEMA" --schema-format json \
		--policies "$BUNDLE" \
		--tests "$f"; then
		echo "cedar-test : cas en échec dans ${f#"$REPO_ROOT/"}." >&2
		fail=1
	fi
done

if [[ $fail -ne 0 ]]; then
	echo "cedar-test : ÉCHEC." >&2
	exit 1
fi

echo "cedar-test : OK."
