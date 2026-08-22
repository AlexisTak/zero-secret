#!/usr/bin/env bash
# Vérifie qu'aucun fichier généré ne diverge de ce que produirait la commande de génération.
# La commande et le dossier généré sont paramétrables pour rester testables sans buf (absent
# de cet environnement de développement).
#
# Usage : check_generated_up_to_date <racine> <commande_de_génération> <dossier_généré...>
set -euo pipefail

check_generated_up_to_date() {
	local root="$1"
	local generate_cmd="$2"
	shift 2
	local -a generated_dirs=("$@")

	local work
	work=$(mktemp -d)

	cp -r "$root"/. "$work"/
	if ! (cd "$work" && eval "$generate_cmd") >/dev/null 2>&1; then
		echo "check-generated-up-to-date : échec de la commande de génération dans la copie de travail." >&2
		rm -rf "$work"
		return 1
	fi

	local violations=0
	local d
	for d in "${generated_dirs[@]}"; do
		if ! diff -rq "$root/$d" "$work/$d" >/tmp/gen-diff.$$ 2>&1; then
			echo "VIOLATION generated-up-to-date : $d diverge de ce que produit la génération :" >&2
			cat /tmp/gen-diff.$$ >&2
			violations=$((violations + 1))
		fi
		rm -f /tmp/gen-diff.$$
	done

	rm -rf "$work"
	return "$violations"
}
