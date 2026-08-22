#!/usr/bin/env bash
# Backlog L0.6 — critère d'acceptation : le rôle applicatif audit_writer échoue explicitement
# sur un DELETE (et un UPDATE). Prouvé par un test qui se connecte réellement en tant que ce
# rôle, PAS par une lecture du fichier de migration.
#
# Prérequis : `make up && make generate` (migrate) déjà exécutés — .env.dev doit exister.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
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

fail=0
test_event_id="00000000-0000-7000-8000-00000000006c" # constante, nettoyée avant et après

run_as_audit_writer() {
	PGPASSWORD="$AUDIT_WRITER_PASSWORD" psql \
		-h "$PGHOST" -p "$PGPORT" -U audit_writer -d "$PGDATABASE" \
		-v ON_ERROR_STOP=1 -tA -c "$1" 2>&1
}

run_as_postgres() {
	psql -h "$PGHOST" -p "$PGPORT" -U postgres -d "$PGDATABASE" -v ON_ERROR_STOP=1 -tA -c "$1"
}

# Nettoyage préventif : un run précédent interrompu peut avoir laissé la ligne en place.
run_as_postgres "DELETE FROM audit.events WHERE event_id = '$test_event_id';" >/dev/null

# --- INSERT doit réussir : c'est le seul usage légitime de ce rôle -----------------------
insert_out=$(run_as_audit_writer "
	INSERT INTO audit.events
		(event_id, sequence, occurred_at, event_type, actor, outcome, prev_hash, signature)
	VALUES
		('$test_event_id', 999999999, now(), 'audit.chain_verified',
		 '{\"subject_id\": \"test-l0.6\", \"kind\": \"system\"}'::jsonb,
		 'success',
		 '$(printf '0%.0s' {1..64})',
		 '{\"suite\": \"audit-seal/v1\", \"value\": \"dGVzdA==\"}'::jsonb);
") || { echo "ÉCHEC INATTENDU — audit_writer ne peut pas INSERT (devrait pouvoir) : $insert_out" >&2; fail=1; }

# --- DELETE doit échouer, explicitement, avec insufficient_privilege (42501) -------------
delete_out=$(run_as_audit_writer "DELETE FROM audit.events WHERE event_id = '$test_event_id';" 2>&1) && {
	echo "ÉCHEC — audit_writer a pu supprimer une ligne du journal d'audit. C'est exactement" >&2
	echo "        ce que L0.6 doit empêcher." >&2
	fail=1
} || {
	if echo "$delete_out" | grep -q "42501\|permission denied\|insufficient privilege"; then
		echo "OK — DELETE refusé explicitement : $delete_out"
	else
		echo "ÉCHEC — DELETE a échoué mais pas pour la bonne raison : $delete_out" >&2
		fail=1
	fi
}

# --- UPDATE doit échouer aussi, même raison ------------------------------------------------
update_out=$(run_as_audit_writer "UPDATE audit.events SET outcome = 'error' WHERE event_id = '$test_event_id';" 2>&1) && {
	echo "ÉCHEC — audit_writer a pu modifier une ligne du journal d'audit." >&2
	fail=1
} || {
	if echo "$update_out" | grep -q "42501\|permission denied\|insufficient privilege"; then
		echo "OK — UPDATE refusé explicitement : $update_out"
	else
		echo "ÉCHEC — UPDATE a échoué mais pas pour la bonne raison : $update_out" >&2
		fail=1
	fi
}

# --- Nettoyage : via un rôle qui PEUT supprimer (postgres), pas audit_writer -------------
run_as_postgres "DELETE FROM audit.events WHERE event_id = '$test_event_id';" >/dev/null

exit "$fail"
