#!/usr/bin/env bash
# Régénère l'inventaire cryptographique (CBOM, CycloneDX 1.6) depuis
# security/crypto-inventory/suites.toml — source de vérité, éditée à la main, revue humaine.
# cbom.json est dérivé : ne jamais l'éditer directement (ADR-011).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
SUITES_FILE="$REPO_ROOT/security/crypto-inventory/suites.toml"

if [[ ! -f "$SUITES_FILE" ]]; then
	echo "generate-cbom: $SUITES_FILE introuvable." >&2
	exit 1
fi

# Extraction minimale, volontairement sans dépendance TOML externe : le format de
# security/crypto-inventory/suites.toml est contraint (un bloc [[suite]] par suite, une clé par
# ligne, forme `cle = "valeur"`). Un bloc est traité à chaque nouveau [[suite]] ou en fin de
# fichier — accumulation simple, pas de parseur TOML général.
components=()
id="" role="" env="" compliant=""

flush() {
	[[ -n "$id" ]] || return 0
	local component
	component=$(printf '{"bom-ref":"suite/%s","type":"cryptographic-asset","name":"%s","cryptoProperties":{"assetType":"protocol","protocolProperties":{}},"properties":[{"name":"zs:suite","value":"%s"},{"name":"zs:role","value":"%s"},{"name":"zs:execution-environment","value":"%s"},{"name":"zs:anssi-2027-compliant","value":"%s"}]}' \
		"$id" "$id" "$id" "$role" "$env" "$compliant")
	components+=("$component")
}

while IFS= read -r line; do
	if [[ "$line" == "[[suite]]" ]]; then
		flush
		id="" role="" env="" compliant=""
		continue
	fi
	if [[ "$line" =~ ^id[[:space:]]*=[[:space:]]*\"([^\"]*)\" ]]; then
		id="${BASH_REMATCH[1]}"
	elif [[ "$line" =~ ^role[[:space:]]*=[[:space:]]*\"([^\"]*)\" ]]; then
		role="${BASH_REMATCH[1]}"
	elif [[ "$line" =~ ^execution_environment[[:space:]]*=[[:space:]]*\"([^\"]*)\" ]]; then
		env="${BASH_REMATCH[1]}"
	elif [[ "$line" =~ ^anssi_2027_compliant[[:space:]]*=[[:space:]]*([a-z]+) ]]; then
		compliant="${BASH_REMATCH[1]}"
	fi
done <"$SUITES_FILE"
flush

if [[ ${#components[@]} -eq 0 ]]; then
	echo "generate-cbom: aucune suite déclarée dans $SUITES_FILE." >&2
	exit 1
fi

joined=$(
	IFS=,
	echo "${components[*]}"
)
printf '{"bomFormat":"CBOM","specVersion":"1.6","serialNumber":"urn:uuid:zero-secret-cbom","version":1,"components":[%s]}\n' "$joined"
