#!/usr/bin/env bash
# Applique les migrations PostgreSQL (deploy/migrations/*.sql, dans l'ordre) sur l'environnement
# local démarré par `make up`. Idempotent : une table schema_migrations trace ce qui est déjà
# appliqué, ne rejoue jamais un fichier deux fois.
#
# Mots de passe des rôles applicatifs générés ici, à l'exécution — jamais en dur dans les
# migrations (règle absolue #1). Écrits dans .env.dev (gitignored) pour que les tests locaux
# (tests/e2e/) puissent s'y connecter sans les redemander.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MIGRATIONS_DIR="$ROOT/deploy/migrations"

: "${PGHOST:=localhost}"
: "${PGPORT:=5432}"
: "${PGUSER:=postgres}"
: "${PGDATABASE:=zero_secret}"
export PGHOST PGPORT PGUSER PGDATABASE

gen_password() {
	# 32 octets aléatoires encodés en base64 sans caractères ambigus pour psql -v (pas de guillemet).
	head -c 32 /dev/urandom | base64 | tr -d '=+/\n' | head -c 40
}

ENV_FILE="$ROOT/.env.dev"
if [[ ! -f "$ENV_FILE" ]]; then
	{
		echo "# Généré par tools/migrate.sh — mots de passe dev locaux, jamais committés."
		echo "IDENTITY_APP_PASSWORD=$(gen_password)"
		echo "AUTHZ_APP_PASSWORD=$(gen_password)"
		echo "ISSUANCE_APP_PASSWORD=$(gen_password)"
		echo "AUDIT_WRITER_PASSWORD=$(gen_password)"
		echo "AUDIT_READER_PASSWORD=$(gen_password)"
	} >"$ENV_FILE"
	echo "migrate: mots de passe dev générés dans $ENV_FILE" >&2
fi
# shellcheck source=/dev/null
source "$ENV_FILE"

psql -v ON_ERROR_STOP=1 -c "CREATE TABLE IF NOT EXISTS schema_migrations (
	filename text PRIMARY KEY,
	applied_at timestamptz NOT NULL DEFAULT now()
);" >/dev/null

for migration in "$MIGRATIONS_DIR"/*.sql; do
	name=$(basename "$migration")
	already=$(psql -v ON_ERROR_STOP=1 -tA -c \
		"SELECT 1 FROM schema_migrations WHERE filename = '$name';")
	if [[ "$already" == "1" ]]; then
		echo "migrate: $name déjà appliquée, ignorée." >&2
		continue
	fi

	echo "migrate: application de $name..." >&2
	psql -v ON_ERROR_STOP=1 \
		-v identity_app_password="$IDENTITY_APP_PASSWORD" \
		-v authz_app_password="$AUTHZ_APP_PASSWORD" \
		-v issuance_app_password="$ISSUANCE_APP_PASSWORD" \
		-v audit_writer_password="$AUDIT_WRITER_PASSWORD" \
		-v audit_reader_password="$AUDIT_READER_PASSWORD" \
		-f "$migration"
	psql -v ON_ERROR_STOP=1 -c \
		"INSERT INTO schema_migrations (filename) VALUES ('$name');" >/dev/null
done

echo "migrate: terminé." >&2
