#!/usr/bin/env bash
# Frontière posée en L1.2c (referent-crypto, ADR-012) : crates/zs-crypto ne dépend d'aucun autre
# crate du workspace, sauf crates/zs-hsm (émission via HSM, ADR-011). Direction inverse déjà
# vérifiée (crates/zs-webauthn, crates/zs-audit ne dépendent jamais de zs-hsm,
# check-webauthn-no-hsm.sh) — celle-ci ferme l'autre sens : zs-crypto est la façade la plus bas
# niveau du projet, elle ne doit dépendre d'aucun crate applicatif (zs-webauthn, zs-audit,
# zs-policy), sous peine d'inverser silencieusement la direction de dépendance voulue.
set -euo pipefail

check_zs_crypto_deps() {
	local root="$1"
	local dir="$root/crates/zs-crypto"
	local violations=0

	[[ -d "$dir" ]] || return 0

	local f
	while IFS= read -r -d '' f; do
		local line
		while IFS= read -r line; do
			local crate
			crate=$(printf '%s' "$line" | grep -Eo '^[A-Za-z0-9_-]+' || true)
			if [[ -n "$crate" && "$crate" != "zs-hsm" ]]; then
				echo "VIOLATION zs-crypto-deps : $f déclare une dépendance à '$crate' (seul zs-hsm est autorisé)." >&2
				violations=$((violations + 1))
			fi
		done < <(awk '/^\[dependencies/{f=1;next} /^\[/{f=0} f' "$f" | grep -E '^zs-[A-Za-z0-9_-]+\s*=' || true)
	done < <(find "$dir" -name 'Cargo.toml' -print0)

	while IFS= read -r -d '' f; do
		if grep -Eq '^\s*use\s+zs_(webauthn|audit|policy)\b' "$f" 2>/dev/null; then
			echo "VIOLATION zs-crypto-deps : $f importe un crate applicatif du workspace directement." >&2
			violations=$((violations + 1))
		fi
	done < <(find "$dir" -name '*.rs' -print0)

	return "$violations"
}
