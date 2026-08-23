#!/usr/bin/env bash
# Tests d'architecture — backlog L0.2. Chaque détecteur est exercé contre une fixture de
# violation (échec attendu) et une fixture propre (succès attendu), puis contre le vrai dépôt
# (succès attendu). Écrit pour échouer bruyamment si une violation n'est pas détectée : c'est
# le test de refus qui compte sur ce projet, pas le chemin heureux.
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
FIXTURES="$SCRIPT_DIR/fixtures"

# shellcheck source=../../tools/lib/check-apps-isolation.sh
source "$REPO_ROOT/tools/lib/check-apps-isolation.sh"
# shellcheck source=../../tools/lib/check-no-direct-crypto.sh
source "$REPO_ROOT/tools/lib/check-no-direct-crypto.sh"
# shellcheck source=../../tools/lib/check-generated-up-to-date.sh
source "$REPO_ROOT/tools/lib/check-generated-up-to-date.sh"
# shellcheck source=../../tools/lib/check-webauthn-no-hsm.sh
source "$REPO_ROOT/tools/lib/check-webauthn-no-hsm.sh"
# shellcheck source=../../tools/lib/check-cbom-coverage.sh
source "$REPO_ROOT/tools/lib/check-cbom-coverage.sh"
# shellcheck source=../../tools/lib/check-zs-crypto-deps.sh
source "$REPO_ROOT/tools/lib/check-zs-crypto-deps.sh"

fail=0
pass=0

# assert_fails <label> <commande...>
assert_fails() {
	local label="$1"
	shift
	if "$@" >/tmp/arch-test-out.$$ 2>&1; then
		echo "ÉCHEC ATTENDU NON OBTENU — $label : le détecteur a laissé passer une violation." >&2
		cat /tmp/arch-test-out.$$ >&2
		fail=$((fail + 1))
	else
		echo "OK (refus) — $label"
		pass=$((pass + 1))
	fi
	rm -f /tmp/arch-test-out.$$
}

# assert_passes <label> <commande...>
assert_passes() {
	local label="$1"
	shift
	if "$@" >/tmp/arch-test-out.$$ 2>&1; then
		echo "OK (accepté) — $label"
		pass=$((pass + 1))
	else
		echo "FAUX POSITIF — $label : le détecteur rejette un cas propre." >&2
		cat /tmp/arch-test-out.$$ >&2
		fail=$((fail + 1))
	fi
	rm -f /tmp/arch-test-out.$$
}

# --- apps-isolation ----------------------------------------------------------
assert_fails "apps-isolation / fixture violation" \
	check_apps_isolation "$FIXTURES/apps-isolation/violation"
assert_passes "apps-isolation / fixture clean" \
	check_apps_isolation "$FIXTURES/apps-isolation/clean"
assert_passes "apps-isolation / dépôt réel" \
	check_apps_isolation "$REPO_ROOT"

# --- no-direct-crypto ---------------------------------------------------------
assert_fails "no-direct-crypto / fixture violation" \
	check_no_direct_crypto "$FIXTURES/no-direct-crypto/violation"
assert_passes "no-direct-crypto / fixture clean" \
	check_no_direct_crypto "$FIXTURES/no-direct-crypto/clean"
assert_passes "no-direct-crypto / dépôt réel" \
	check_no_direct_crypto "$REPO_ROOT"

# --- generated-up-to-date ------------------------------------------------------
assert_fails "generated-up-to-date / fixture violation" \
	check_generated_up_to_date "$FIXTURES/generated-drift/violation" "bash generate.sh" generated
assert_passes "generated-up-to-date / fixture clean" \
	check_generated_up_to_date "$FIXTURES/generated-drift/clean" "bash generate.sh" generated

# --- webauthn-no-hsm -----------------------------------------------------------
assert_fails "webauthn-no-hsm / fixture violation" \
	check_webauthn_no_hsm "$FIXTURES/webauthn-no-hsm/violation"
assert_passes "webauthn-no-hsm / fixture clean" \
	check_webauthn_no_hsm "$FIXTURES/webauthn-no-hsm/clean"
assert_passes "webauthn-no-hsm / dépôt réel" \
	check_webauthn_no_hsm "$REPO_ROOT"

# --- cbom-coverage --------------------------------------------------------------
assert_fails "cbom-coverage / fixture violation" \
	check_cbom_coverage "$FIXTURES/cbom-coverage/violation"
assert_passes "cbom-coverage / fixture clean" \
	check_cbom_coverage "$FIXTURES/cbom-coverage/clean"
assert_passes "cbom-coverage / dépôt réel" \
	check_cbom_coverage "$REPO_ROOT"

# --- zs-crypto-deps --------------------------------------------------------------
assert_fails "zs-crypto-deps / fixture violation" \
	check_zs_crypto_deps "$FIXTURES/zs-crypto-deps/violation"
assert_passes "zs-crypto-deps / fixture clean" \
	check_zs_crypto_deps "$FIXTURES/zs-crypto-deps/clean"
assert_passes "zs-crypto-deps / dépôt réel" \
	check_zs_crypto_deps "$REPO_ROOT"

echo
echo "$pass test(s) passé(s), $fail test(s) en échec."
[[ "$fail" -eq 0 ]]
