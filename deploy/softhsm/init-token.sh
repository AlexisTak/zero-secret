#!/usr/bin/env sh
# Initialise un token SoftHSM2 pour l'environnement de dev local (backlog L0.6). PIN et SO-PIN
# générés ici, à l'exécution — jamais en dur (règle absolue #1), écrits dans un fichier local
# gitignored pour que credential-issuer (backlog L2+) puisse s'y connecter en dev.
#
# SoftHSM2 est une bibliothèque PKCS#11, pas un service réseau : ce conteneur ne fait
# qu'initialiser le token dans un volume partagé ($SOFTHSM2_TOKEN_DIR), que les conteneurs
# applicatifs futurs (credential-issuer) monteront pour y accéder localement via zs-hsm.
set -eu

: "${SOFTHSM2_TOKEN_DIR:=/var/lib/softhsm/tokens}"
: "${SOFTHSM2_CONF:=/etc/softhsm2.conf}"
: "${TOKEN_LABEL:=zero-secret-dev}"
: "${ENV_OUT:=/env-out/.env.softhsm}"

mkdir -p "$SOFTHSM2_TOKEN_DIR"
cat >"$SOFTHSM2_CONF" <<EOF
directories.tokendir = $SOFTHSM2_TOKEN_DIR
objectstore.backend = file
log.level = INFO
EOF
export SOFTHSM2_CONF

if softhsm2-util --show-slots 2>/dev/null | grep -q "$TOKEN_LABEL"; then
	echo "init-token: token '$TOKEN_LABEL' déjà initialisé, ignoré." >&2
	exit 0
fi

gen_pin() {
	head -c 16 /dev/urandom | od -An -tu1 | tr -d ' \n' | head -c 8
}

PIN=$(gen_pin)
SO_PIN=$(gen_pin)

softhsm2-util --init-token --free --label "$TOKEN_LABEL" --pin "$PIN" --so-pin "$SO_PIN"

mkdir -p "$(dirname "$ENV_OUT")"
{
	echo "# Généré par deploy/softhsm/init-token.sh — dev local uniquement, jamais committé."
	echo "SOFTHSM2_TOKEN_LABEL=$TOKEN_LABEL"
	echo "SOFTHSM2_PIN=$PIN"
	echo "SOFTHSM2_SO_PIN=$SO_PIN"
} >"$ENV_OUT"

echo "init-token: token '$TOKEN_LABEL' initialisé, identifiants dans $ENV_OUT." >&2
