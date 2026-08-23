-- Migration 005 — colonne des octets canoniques scellés (H5, ADR-023).
--
-- audit.events (migration 002) décompose l'événement en colonnes structurées mais ne conserve
-- pas les octets canoniques exacts produits par zs_crypto::audit_seal::seal — ceux que
-- zs_audit::chain::hash_sealed_event doit rehacher pour dériver le prev_hash de l'événement
-- suivant. Les reconstruire à partir des colonnes décomposées exigerait une seconde
-- implémentation de la canonicalisation JCS en dehors de zs-crypto : exactement le risque de
-- divergence silencieuse déjà signalé dans le commentaire de module d'audit_seal.rs. Stocker
-- l'opaque évite cette réimplémentation — le module de chaînage ne connaît déjà que des octets
-- opaques (voir zs-audit/src/chain.rs).
--
-- Table encore vide à ce stade (aucun écrivain réel n'existe avant H5) : ajout sans DEFAULT ni
-- backfill nécessaire.

BEGIN;

ALTER TABLE audit.events ADD COLUMN sealed_bytes bytea NOT NULL;

COMMIT;
