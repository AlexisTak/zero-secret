#!/usr/bin/env bash
# Invariant 9 (zs-crypto/CLAUDE.md) : « toute suite est déclarée au CBOM. Une suite ajoutée sans
# entrée CBOM fait échouer la construction. » Comblé ici (H1, ADR-011) — jusque là, aucun contrôle
# n'existait, et authenticator-proof/v1 (L1.1) était déjà en défaut.
#
# Détection : toute chaîne littérale de la forme "<nom>/vN" dans crates/zs-crypto/src/**/*.rs
# doit avoir une entrée `id = "<nom>/vN"` dans security/crypto-inventory/suites.toml. Les blocs
# `mod tests { ... }` sont retirés avant la détection (revu en L1.2c/ADR-012 : un test peut
# légitimement fabriquer un identifiant de suite valide fictif, ex. "autre-suite/v1", pour
# vérifier un refus de suite inconnue — sans ce filtrage, ce genre de test devient un faux
# positif permanent du détecteur).
set -euo pipefail

# Dupliquée depuis check-no-direct-crypto.sh (même logique, comptage d'accolades) plutôt que
# partagée : garde ce fichier indépendamment sourçable/testable sans dépendre de l'ordre de
# chargement des autres détecteurs.
_strip_test_modules() {
	awk '
		/^[[:space:]]*mod tests([[:space:]]|\{)/ { in_test = 1; depth = 0 }
		in_test {
			depth += gsub(/{/, "{")
			depth -= gsub(/}/, "}")
			if (depth <= 0 && /}/) { in_test = 0 }
			next
		}
		{ print }
	' "$1"
}

check_cbom_coverage() {
	local root="$1"
	local suites_file="$root/security/crypto-inventory/suites.toml"
	local violations=0

	if [[ ! -f "$suites_file" ]]; then
		echo "VIOLATION cbom-coverage : $suites_file introuvable." >&2
		return 1
	fi

	local zs_crypto_dir="$root/crates/zs-crypto/src"
	[[ -d "$zs_crypto_dir" ]] || return 0

	local f match
	while IFS= read -r -d '' f; do
		while IFS= read -r match; do
			[[ -z "$match" ]] && continue
			if ! grep -Fq "id = \"$match\"" "$suites_file"; then
				echo "VIOLATION cbom-coverage : suite '$match' référencée dans $f sans entrée dans $suites_file." >&2
				violations=$((violations + 1))
			fi
		done < <(_strip_test_modules "$f" | grep -ohE '"[a-z0-9][a-z0-9-]*/v[0-9]+"' | tr -d '"' | sort -u)
	done < <(find "$zs_crypto_dir" -name '*.rs' -print0)

	return "$violations"
}
