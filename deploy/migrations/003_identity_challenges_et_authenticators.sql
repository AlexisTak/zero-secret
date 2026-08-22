-- Migration 003 — stockage des challenges de cérémonie et des authentificateurs enregistrés
-- (backlog L1.1). Droits déjà accordés à identity_app par la migration 001
-- (SELECT/INSERT/UPDATE, jamais DELETE — la révocation est un UPDATE de statut, pas une
-- suppression, cf. commentaire de la migration 001).

BEGIN;

CREATE TABLE identity.challenges (
    challenge      bytea PRIMARY KEY,
    subject_id     text NOT NULL,
    ceremony_kind  text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,

    CONSTRAINT challenges_ceremony_kind_check
        CHECK (ceremony_kind IN ('registration', 'authentication'))
);

-- La consommation d'un challenge doit être atomique côté base (UPDATE ... WHERE used_at IS NULL
-- RETURNING), jamais un SELECT puis UPDATE séparés — c'est la fenêtre TOCTOU qui rend le rejeu
-- réellement exploitable (mise en garde referent-crypto, ADR-006). L'index sur expires_at sert
-- au nettoyage périodique des challenges expirés, pas encore implémenté (backlog ultérieur).
CREATE INDEX challenges_expires_at_idx ON identity.challenges (expires_at);

CREATE TABLE identity.authenticators (
    credential_id        bytea PRIMARY KEY,
    subject_id           text NOT NULL,
    suite                text NOT NULL,
    algorithm            text NOT NULL,
    public_key           bytea NOT NULL,
    sign_count           bigint NOT NULL DEFAULT 0,
    aaguid               bytea NOT NULL,
    attestation_format   text NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    revoked_at           timestamptz,

    CONSTRAINT authenticators_algorithm_check CHECK (algorithm IN ('es256', 'eddsa')),
    CONSTRAINT authenticators_attestation_format_check
        CHECK (attestation_format IN ('none', 'packed'))
);

CREATE INDEX authenticators_subject_id_idx ON identity.authenticators (subject_id);

GRANT SELECT, INSERT, UPDATE ON identity.challenges TO identity_app;
GRANT SELECT, INSERT, UPDATE ON identity.authenticators TO identity_app;
REVOKE DELETE ON identity.challenges FROM identity_app;
REVOKE DELETE ON identity.authenticators FROM identity_app;

COMMIT;
