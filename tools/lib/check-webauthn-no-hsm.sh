#!/usr/bin/env bash
# Frontière R5 (referent-crypto, backlog L1.2, ADR-008), étendue à zs-audit (backlog L1.4,
# ADR-010) : ni crates/zs-webauthn ni crates/zs-audit ne dépendent jamais de crates/zs-hsm.
# La chaîne de vérification passe par identity-provider -> zs-webauthn (aucun HSM) ; celle
# d'émission (assertion signée, événement d'audit scellé) passe par
# identity-provider -> zs-crypto -> zs-hsm. Un import direct de zs-hsm dans l'un de ces deux
# crates serait le signe qu'une signature/émission s'est glissée dans le mauvais crate — à
# bloquer avant que quiconque en ait la tentation, pas après coup.
set -euo pipefail

check_webauthn_no_hsm() {
	local root="$1"
	local violations=0
	local crate_dir

	for crate_dir in "$root/crates/zs-webauthn" "$root/crates/zs-audit"; do
		[[ -d "$crate_dir" ]] || continue

		local f
		while IFS= read -r -d '' f; do
			if grep -Eq '^\s*zs-hsm\s*=' "$f" 2>/dev/null; then
				echo "VIOLATION webauthn-no-hsm : $f déclare une dépendance à zs-hsm." >&2
				violations=$((violations + 1))
			fi
		done < <(find "$crate_dir" -name 'Cargo.toml' -print0)

		while IFS= read -r -d '' f; do
			if grep -Eq '^\s*use\s+zs_hsm\b' "$f" 2>/dev/null; then
				echo "VIOLATION webauthn-no-hsm : $f importe zs_hsm directement." >&2
				violations=$((violations + 1))
			fi
		done < <(find "$crate_dir" -name '*.rs' -print0)
	done

	return "$violations"
}
