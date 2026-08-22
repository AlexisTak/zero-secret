-- Migration 001 — quatre schémas cloisonnés, un rôle applicatif par schéma.
--
-- Règle d'architecture (docs/architecture.md) : « aucun rôle applicatif en écriture sur plus
-- d'un schéma ». Règle absolue du CLAUDE.md racine : refus par défaut. Ce fichier ne doit
-- JAMAIS être modifié une fois appliqué (règle du CLAUDE.md racine, section « jamais sans
-- validation explicite ») — toute évolution passe par une migration suivante.
--
-- Mots de passe : variables psql (:'xxx_password'), jamais en dur ici. Générés à l'exécution
-- par tools/migrate.sh (règle absolue #1 — aucun secret durable, y compris en dev local).
-- Rôles LOGIN directement (pas de séparation groupe/login) : la rotation de mot de passe sans
-- toucher aux GRANT est un besoin de prod, pas de ce lot — voir ADR à écrire si L2+ l'exige.

BEGIN;

CREATE SCHEMA IF NOT EXISTS identity;
CREATE SCHEMA IF NOT EXISTS authz;
CREATE SCHEMA IF NOT EXISTS issuance;
CREATE SCHEMA IF NOT EXISTS audit;

-- Aucun rôle ne doit hériter de droits sur public par défaut : refus par défaut.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- --- identity ---------------------------------------------------------------
CREATE ROLE identity_app LOGIN PASSWORD :'identity_app_password';
GRANT USAGE ON SCHEMA identity TO identity_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA identity TO identity_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA identity
    GRANT SELECT, INSERT, UPDATE ON TABLES TO identity_app;
-- Pas de DELETE : la révocation d'authentificateur est un UPDATE de statut (backlog L1.3),
-- jamais une suppression — l'historique doit rester consultable.
REVOKE DELETE ON ALL TABLES IN SCHEMA identity FROM identity_app;

-- --- authz --------------------------------------------------------------------
CREATE ROLE authz_app LOGIN PASSWORD :'authz_app_password';
GRANT USAGE ON SCHEMA authz TO authz_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA authz TO authz_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA authz
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO authz_app;

-- --- issuance -------------------------------------------------------------------
CREATE ROLE issuance_app LOGIN PASSWORD :'issuance_app_password';
GRANT USAGE ON SCHEMA issuance TO issuance_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA issuance TO issuance_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA issuance
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO issuance_app;
-- issuance a besoin de DELETE : un bail de credential expiré est purgé (pas le credential lui
-- même — jamais stocké — seulement l'état de bail), contrairement à identity et audit.

-- --- audit ----------------------------------------------------------------------
-- Le rôle le plus contraint du système : journal en ajout seul.
CREATE ROLE audit_writer LOGIN PASSWORD :'audit_writer_password';
GRANT USAGE ON SCHEMA audit TO audit_writer;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA audit TO audit_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit
    GRANT SELECT, INSERT ON TABLES TO audit_writer;
-- Révocation EXPLICITE, pas une simple omission : un GRANT ALL accidentel plus tard dans une
-- migration future se heurterait à une révocation déjà écrite, pas à un silence.
REVOKE UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA audit FROM audit_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit
    REVOKE UPDATE, DELETE, TRUNCATE ON TABLES FROM audit_writer;

-- Rôle de lecture seule pour l'export SIEM et la vérification de chaîne (audit-collector en
-- lecture, pas en écriture — un composant qui vérifie le journal ne doit pas pouvoir l'altérer).
CREATE ROLE audit_reader LOGIN PASSWORD :'audit_reader_password';
GRANT USAGE ON SCHEMA audit TO audit_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO audit_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit
    GRANT SELECT ON TABLES TO audit_reader;

COMMIT;
