#!/usr/bin/env bash
# Démonstration reproductible du parcours JIT complet (identité → demande d'accès → décision
# Cedar signée → credential éphémère → audit vérifiable — CLAUDE.md §26, « critère de réussite »,
# et mission d'audit Priorité 2 : « vérifie que ce workflow existe réellement dans le code »).
#
# Orchestre des preuves RÉELLES déjà existantes dans le dépôt — tests d'intégration contre un
# SoftHSM2 et une PostgreSQL réels, jamais un mock de la cryptographie — plutôt que d'en fabriquer
# une nouvelle. Voir CLAUDE.md règle 24 : « ne jamais simuler une propriété de sécurité en la
# présentant comme réelle ». Ce script est un orchestrateur, pas une nouvelle suite de tests : il
# ne remplace aucune des preuves qu'il invoque, il les enchaîne dans l'ordre du parcours JIT et
# échoue au premier maillon rompu (refus par défaut, règle absolue #2).
#
# Prérequis : `make setup && make up` déjà exécutés (PostgreSQL migré via tools/migrate.sh,
# `.env.dev` présent, SoftHSM2 initialisé localement — voir DEMARRAGE.md). `ZS_HSM_MODULE` doit
# pointer vers la bibliothèque PKCS#11 locale ; `SOFTHSM2_PIN` reprend le même défaut que
# crates/zs-hsm/tests/pkcs11_integration.rs et apps/policy-engine/tests/decide_integration.rs
# si absent de l'environnement.
#
# Limite assumée, à lire avant d'interpréter le résultat : aucun script ne peut légitimement
# automatiser une cérémonie WebAuthn/CTAP2 avec un authentificateur matériel (elle exige une
# action physique hors de la portée de bash). L'étape 1 délègue donc à l'unique test qui prouve
# réellement le protocole contre le HTTP réel d'identity-provider et un HSM réel
# (apps/identity-provider/tests/http_ceremony.rs, authentificateur logiciel de test) — ce n'est
# pas une resimplification maison, et ce n'est pas la preuve qu'un porteur humain a agi.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"

ENV_FILE="$ROOT/.env.dev"
if [[ ! -f "$ENV_FILE" ]]; then
	echo "ÉCHEC — $ENV_FILE absent. Lancer 'make up' d'abord (génère les mots de passe dev)." >&2
	exit 1
fi
# shellcheck source=/dev/null
source "$ENV_FILE"

: "${PGHOST:=localhost}"
: "${PGPORT:=5432}"
: "${PGDATABASE:=zero_secret}"
: "${SOFTHSM2_PIN:=1234test5678}"

if [[ -z "${ZS_HSM_MODULE:-}" ]]; then
	echo "ÉCHEC — ZS_HSM_MODULE non défini. Doit pointer vers libsofthsm2.so (voir DEMARRAGE.md)." >&2
	exit 1
fi

export ZS_IDP_IDENTITY_DATABASE_URL="postgres://identity_app:${IDENTITY_APP_PASSWORD}@${PGHOST}:${PGPORT}/${PGDATABASE}"
export ZS_IDP_AUDIT_DATABASE_URL="postgres://audit_writer:${AUDIT_WRITER_PASSWORD}@${PGHOST}:${PGPORT}/${PGDATABASE}"
export ZS_HSM_MODULE SOFTHSM2_PIN

fail=0
step() {
	echo
	echo "=== $1 ==="
}

step "1/6 — Identité : cérémonie WebAuthn/FIDO2 (AAL3) contre HTTP + HSM réels, assertion signée (identity-assertion/v1, ADR-012)"
echo "Preuve : apps/identity-provider/tests/http_ceremony.rs — enregistrement puis authentification"
echo "réels contre le routeur HTTP réel d'identity-provider et un SoftHSM2 réel ; rejeu de challenge"
echo "refusé, signature invalide refusée."
cargo test -p identity-provider --test http_ceremony -- --ignored --nocapture || fail=1

step "2/6 — Politique : décision Cedar déterministe et hors ligne, scellée par le HSM (decision-seal/v1, ADR-015/019)"
echo "Preuve : apps/policy-engine/tests/decide_integration.rs — Pdp::decide réel contre le corpus"
echo "policies/access/db_connect.cedar, décision scellée par un HSM réel, vérifiée via VerifyDecision."
cargo test -p policy-engine --test decide_integration -- --ignored --nocapture || fail=1

step "3/6 — HSM : pool PKCS#11 réel, refus strict sans repli logiciel (H1, ADR-011)"
echo "Preuve : crates/zs-hsm/tests/pkcs11_integration.rs"
cargo test -p zs-hsm -- --include-ignored --nocapture || fail=1

step "4/6 — Émission JIT et anti-rejeu réseau (access-broker → credential-issuer → OpenBao, ADR-020/025)"
echo "Preuve : suite Go réelle sur gRPC/HTTP réels — ordre d'émission sans décision valide refusé"
echo "avant tout appel OpenBao, rejeu de la même décision refusé via le réseau."
(cd apps/credential-issuer && go test ./... -run 'TestDecisionInvalideEstRefuseeAvantAppelOpenBao|TestEffectDenyEstRefuseSansAppelOpenBao|TestRejeuDeLaMemeDecisionEstRefuseViaLeReseau|TestVerbeNonSupporteEstRefuse' -v) || fail=1

step "5/6 — Chaîne d'audit : vecteurs scellés/chaînés, détection de rupture (audit-seal/v1, ADR-013)"
echo "Preuve : crates/zs-audit — vecteurs figés (chain_vectors.rs) et tests unitaires de chain.rs"
echo "(prev_hash incohérent, trou de séquence, séquence dupliquée — tous refusés)."
cargo test -p zs-audit || fail=1

step "6/6 — Permissions PostgreSQL : le rôle applicatif ne peut ni modifier ni supprimer un événement d'audit"
bash tests/e2e/audit_writer_refuses_delete.sh || fail=1

echo
if [[ "$fail" -eq 0 ]]; then
	echo "=== JIT DEMO : parcours complet prouvé, 6/6 étapes vertes ==="
else
	echo "=== JIT DEMO : ÉCHEC — au moins une étape a échoué, voir ci-dessus ===" >&2
fi

echo
echo "Ce que cette démonstration NE prouve PAS (limites explicites, CLAUDE.md §12/§24) :"
echo "  - le transport gRPC interne est en clair aujourd'hui (mTLS/SPIFFE-SPIRE PLANNED, ADR-036) ;"
echo "  - l'étape 1 utilise l'authentificateur logiciel de test d'http_ceremony.rs, pas une clé"
echo "    FIDO2 matérielle — représentatif du protocole, pas la preuve qu'un porteur humain a agi ;"
echo "  - aucune mesure de performance n'est produite ici (objectifs de service p99 : NOT MEASURED,"
echo "    voir docs/architecture.md) ;"
echo "  - le câblage réseau réel access-broker → credential-issuer (HTTP → gRPC) n'est pas rejoué"
echo "    ici en un seul processus bout en bout : chaque segment est prouvé par le test qui lui est"
echo "    propre (étapes 1 à 4), pas par une requête HTTP unique traversant les six binaires."

exit "$fail"
