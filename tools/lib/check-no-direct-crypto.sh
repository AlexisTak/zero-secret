#!/usr/bin/env bash
# Règle 4 (CLAUDE.md) : toute crypto passe par crates/zs-crypto. Aucun autre module n'importe
# une bibliothèque crypto directement. zs-hsm est également exempté (FFI PKCS#11, ADR-001).
set -euo pipefail

# Motifs des dépendances/imports crypto interdits hors façade.
RUST_CRATE_PATTERN='^(ring|rustls|aws-lc-rs|p256|ed25519-[A-Za-z0-9_-]+)$'
RUST_USE_PATTERN='^\s*use\s+(ring|rustls|aws_lc_rs|p256|ed25519_[A-Za-z0-9_]+)\b'
GO_IMPORT_PATTERN='"(crypto/[A-Za-z0-9_/]+|golang\.org/x/crypto[A-Za-z0-9_/]*)"'

_is_exempt_dir() {
	local path="$1" root="$2"
	# zs-crypto/zs-hsm composent la crypto légitimement. Les fixtures de test d'architecture
	# contiennent des violations volontaires : à exclure seulement quand on balaie tout le
	# dépôt (root en dehors des fixtures), jamais quand root pointe déjà sur une fixture —
	# sinon le test qui vérifie que la fixture de violation est bien détectée ne verrait rien.
	if [[ "$path" == */crates/zs-crypto/* || "$path" == */crates/zs-hsm/* ]]; then
		return 0
	fi
	if [[ "$path" == */tests/architecture/fixtures/* && "$root" != */tests/architecture/fixtures* ]]; then
		return 0
	fi
	return 1
}

check_no_direct_crypto() {
	local root="$1"
	local violations=0
	local f

	# --- Rust : Cargo.toml [dependencies] ---
	while IFS= read -r -d '' f; do
		_is_exempt_dir "$f" "$root" && continue
		local line
		while IFS= read -r line; do
			local crate
			crate=$(printf '%s' "$line" | grep -Eo '^[A-Za-z0-9_-]+' || true)
			if [[ -n "$crate" ]] && printf '%s' "$crate" | grep -Eq "$RUST_CRATE_PATTERN"; then
				echo "VIOLATION no-direct-crypto : $f déclare la dépendance '$crate' hors zs-crypto/zs-hsm." >&2
				violations=$((violations + 1))
			fi
		done < <(awk '/^\[dependencies/{f=1;next} /^\[/{f=0} f' "$f" 2>/dev/null || true)
	done < <(find "$root" -name 'Cargo.toml' -print0)

	# --- Rust : use statements directs (au cas où la dépendance viendrait d'ailleurs, ex. workspace) ---
	while IFS= read -r -d '' f; do
		_is_exempt_dir "$f" "$root" && continue
		if grep -Eq "$RUST_USE_PATTERN" "$f" 2>/dev/null; then
			echo "VIOLATION no-direct-crypto : $f importe une bibliothèque crypto directement (use)." >&2
			violations=$((violations + 1))
		fi
	done < <(find "$root" -name '*.rs' -print0)

	# --- Go : imports crypto stdlib / x/crypto ---
	while IFS= read -r -d '' f; do
		_is_exempt_dir "$f" "$root" && continue
		if grep -Eq "$GO_IMPORT_PATTERN" "$f" 2>/dev/null; then
			echo "VIOLATION no-direct-crypto : $f importe une bibliothèque crypto Go directement." >&2
			violations=$((violations + 1))
		fi
	done < <(find "$root" -name '*.go' -print0)

	return "$violations"
}
