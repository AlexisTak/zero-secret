#!/usr/bin/env bash
# Règle 4 (CLAUDE.md) : toute crypto passe par crates/zs-crypto. Aucun autre module n'importe
# une bibliothèque crypto directement. zs-hsm est également exempté (FFI PKCS#11, ADR-001).
set -euo pipefail

# Motifs des dépendances/imports crypto interdits hors façade. Étendu (referent-crypto, L1.1,
# ADR-006) : la première version ne couvrait que les crates déjà nommées dans zs-crypto/CLAUDE.md
# — un contributeur pouvait ajouter webauthn-rs (donc OpenSSL, donc de la vérification de
# signature) dans zs-webauthn sans que ce hook bronche. ciborium/coset restent hors motif : ce
# sont des décodeurs de structure, pas de la crypto (ADR-006). Étendu à nouveau (referent-crypto,
# H1, ADR-011) : cryptoki/cryptoki-sys (FFI PKCS#11) ne doivent être importables que depuis
# zs-hsm, déjà exempté ci-dessous — sans ce motif, n'importe quel crate aurait pu ouvrir une
# session HSM directement, contournant zs-crypto.
RUST_CRATE_PATTERN='^(ring|rustls|aws-lc-rs|aws-lc-sys|p256|ed25519-[A-Za-z0-9_-]+|openssl|openssl-sys|webauthn-rs(-core)?|rsa|ml-dsa|ml-kem|x509-parser|elliptic-curve|signature|der|spki|curve25519-dalek|cryptoki(-sys)?)$'
RUST_USE_PATTERN='^\s*use\s+(ring|rustls|aws_lc_rs|aws_lc_sys|p256|ed25519_[A-Za-z0-9_]+|openssl|webauthn_rs(_core)?|rsa|ml_dsa|ml_kem|x509_parser|elliptic_curve|signature|der|spki|curve25519_dalek|cryptoki(_sys)?)\b'
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

# Retire les blocs `mod tests { ... }` d'un fichier Rust (comptage d'accolades, approximatif
# mais suffisant : ce dépôt formate avec rustfmt, une accolade de `mod tests` déséquilibrée par
# une chaîne littérale contenant `{`/`}` serait déjà un signal de code suspect en soi).
strip_test_modules() {
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
	# Les blocs `mod tests { ... }` sont retirés avant le grep : un test qui simule un acteur
	# externe (ex. un authentificateur FIDO2 dans un fixture de test) peut légitimement importer
	# une bibliothèque crypto pour fabriquer une signature de test, sans que ça ne dispense le
	# code de production de passer par zs-crypto — cette exemption ne vaut que pour ce bloc précis.
	while IFS= read -r -d '' f; do
		_is_exempt_dir "$f" "$root" && continue
		if strip_test_modules "$f" | grep -Eq "$RUST_USE_PATTERN"; then
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
