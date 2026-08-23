#!/usr/bin/env bash
# Invariant 9 (zs-crypto/CLAUDE.md) : « toute suite est déclarée au CBOM. Une suite ajoutée sans
# entrée CBOM fait échouer la construction. » Comblé ici (H1, ADR-011) — jusque là, aucun contrôle
# n'existait, et authenticator-proof/v1 (L1.1) était déjà en défaut.
#
# Détection : toute chaîne littérale de la forme "<nom>/vN" dans crates/zs-crypto/src/**/*.rs
# doit avoir une entrée `id = "<nom>/vN"` dans security/crypto-inventory/suites.toml. Limite
# connue : ne filtre pas les blocs `mod tests { ... }` (contrairement à
# check-no-direct-crypto.sh) — aucun faux positif constaté à ce jour (les suites invalides
# utilisées en test, ex. "authenticator-proof/v0-inexistante", ne correspondent pas au motif
# strict `/v[0-9]+"`), à revoir si un futur test introduit un identifiant de suite valide fictif.
set -euo pipefail

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
		done < <(grep -ohE '"[a-z0-9][a-z0-9-]*/v[0-9]+"' "$f" | tr -d '"' | sort -u)
	done < <(find "$zs_crypto_dir" -name '*.rs' -print0)

	return "$violations"
}
