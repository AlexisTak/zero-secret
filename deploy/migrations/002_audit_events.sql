-- Migration 002 — table du journal d'audit, structure alignée sur
-- contracts/events/audit-event.schema.json (source de vérité — toute divergence entre les deux
-- doit être corrigée ici, jamais dans le schéma JSON pour "coller" à une table existante).
--
-- Champs composites (actor, target, decision, context, signature) en JSONB plutôt qu'en
-- colonnes ou tables séparées : la structure exacte de ces objets vit dans le contrat JSON
-- Schema, pas dans le schéma relationnel. Modéliser chaque champ imbriqué en table dès L0
-- serait concevoir pour un besoin hypothétique avant que L1.4 ne précise l'usage réel.

BEGIN;

CREATE TABLE audit.events (
    event_id        uuid PRIMARY KEY,
    sequence        bigint NOT NULL,
    occurred_at     timestamptz NOT NULL,
    authority_domain text,
    event_type      text NOT NULL,
    actor           jsonb NOT NULL,
    target          jsonb,
    outcome         text NOT NULL,
    decision        jsonb,
    context         jsonb,
    prev_hash       text NOT NULL,
    signature       jsonb NOT NULL,
    inserted_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT events_outcome_check CHECK (outcome IN ('success', 'denied', 'error')),
    CONSTRAINT events_prev_hash_format CHECK (prev_hash ~ '^[0-9a-f]{64}$')
);

-- Un trou dans la séquence par domaine d'autorité est une anomalie bloquante (contrat JSON
-- Schema) : l'unicité ici est ce qui rend un trou détectable par une requête simple, pas
-- seulement par le rejeu complet de la chaîne.
CREATE UNIQUE INDEX events_authority_sequence_idx
    ON audit.events (authority_domain, sequence);

CREATE INDEX events_occurred_at_idx ON audit.events (occurred_at);
CREATE INDEX events_event_type_idx ON audit.events (event_type);

-- Droits explicites sur CETTE table, indépendamment de ALTER DEFAULT PRIVILEGES (migration
-- 001) : celui-ci ne s'applique qu'aux tables créées par le même rôle qui l'a déclaré — ne pas
-- en dépendre silencieusement pour la garantie la plus sensible du système.
GRANT SELECT, INSERT ON audit.events TO audit_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON audit.events FROM audit_writer;
GRANT SELECT ON audit.events TO audit_reader;

COMMIT;
