-- Migration 004 — support du compteur de signature fixé à l'enregistrement (backlog L1.2,
-- mise en garde referent-crypto). La très grande majorité des authentificateurs synchronisés
-- (passkeys) renvoient signCount=0 en permanence (spec WebAuthn L3 §6.1.1 l'autorise). Décider
-- « ce compteur est-il significatif ? » une seule fois, à l'enregistrement, et ne jamais le
-- réévaluer par assertion : sinon un clone force 0 sur une assertion ultérieure et désactive la
-- détection de clonage pour de bon, y compris pour un authentificateur qui la supportait.
--
-- Limite connue et assumée : l'heuristique (sign_count non nul dès l'enregistrement => compteur
-- significatif) peut classer à tort un authentificateur matériel comme non significatif si son
-- tout premier sign_count observé vaut 0. Rare en pratique (les authentificateurs matériels
-- démarrent typiquement à 1), documenté plutôt que caché.

BEGIN;

ALTER TABLE identity.authenticators
    ADD COLUMN counter_supported boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN identity.authenticators.counter_supported IS
    'Figé une fois à l''enregistrement, jamais réévalué par assertion ultérieure — voir commentaire de migration 004.';

COMMIT;
