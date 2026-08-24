# Décisions d'architecture (ADR)

Une décision structurante non écrite ici est une décision qui sera re-litigée à chaque session,
par toi comme par un agent. Le coût d'un ADR est de dix minutes ; le coût de son absence est une
divergence silencieuse.

| N° | Titre | Statut | Date |
|---|---|---|---|
| [001](ADR-001-langages-et-frontieres.md) | Langages et frontières de composants | accepté | 2026-08-22 |
| [002](ADR-002-gestionnaire-de-secrets.md) | OpenBao comme gestionnaire de secrets | accepté | 2026-08-22 |
| [003](ADR-003-moteur-de-politiques.md) | Cedar pour les décisions d'accès, OPA pour la plateforme | accepté | 2026-08-22 |
| [004](ADR-004-generation-code-rust-proto.md) | Génération du code Rust depuis les contrats proto : build.rs, pas buf generate | accepté | 2026-08-22 |
| [005](ADR-005-jenkins-remplace-github-actions.md) | Jenkins remplace GitHub Actions pour la CI, clé de signature stockée (dérogation) | accepté | 2026-08-22 |
| [006](ADR-006-verification-webauthn-frontiere-crypto.md) | Vérification WebAuthn : frontière entre zs-webauthn et zs-crypto (authenticator-proof) | accepté | 2026-08-22 |
| [007](ADR-007-suite-identity-assertion.md) | Spécification de la suite identity-assertion (émission, HSM) | accepté | 2026-08-22 |
| [008](ADR-008-decoupage-l1-2-emission-assertion.md) | Découpage de L1.2 et frontière d'émission de l'assertion d'identité | accepté | 2026-08-22 |
| [009](ADR-009-recuperation-quorum-sans-nouvelle-suite.md) | Récupération à quorum : réutilisation d'authenticator-proof, sans nouvelle suite | accepté | 2026-08-22 |
| [010](ADR-010-audit-seal-hsm-partage-et-chainage.md) | Découpage de L1.4, prérequis HSM partagé (H1) et modèle de chaînage | accepté | 2026-08-22 |
| [011](ADR-011-integration-pkcs11-et-pool-de-sessions.md) | Intégration PKCS#11 (H1), pool de sessions et CBOM | accepté | 2026-08-23 |
| [012](ADR-012-format-assertion-identite-scellee.md) | Format de l'assertion d'identité scellée (identity-assertion/v1) | accepté | 2026-08-23 |
| [013](ADR-013-format-evenement-audit-scelle.md) | Format de l'événement d'audit scellé (audit-seal/v1) | accepté | 2026-08-23 |
| [014](ADR-014-schema-cedar-et-corpus-db-connect.md) | Schéma d'entités Cedar et premier corpus de politiques (db.connect) | accepté | 2026-08-23 |
| [015](ADR-015-pdp-cedar-et-liaison-de-decision.md) | PDP Cedar (policy-engine) et liaison de décision (decision-binding/v1) | accepté | 2026-08-23 |
| [016](ADR-016-service-verification-assertion.md) | Service de vérification d'assertion d'identité (H3, prérequis L2.3) | accepté | 2026-08-23 |
| [017](ADR-017-parcours-jit-access-broker.md) | Parcours JIT (access-broker) : bibliothèque d'abord, portée réduite | accepté | 2026-08-23 |
| [018](ADR-018-client-openbao-credential-issuer.md) | Client OpenBao (credential-issuer, H2, prérequis L2.4) | accepté | 2026-08-23 |
| [019](ADR-019-signature-de-decision.md) | Signature de décision (decision-seal/v1, H4, prérequis L2.4) | accepté | 2026-08-23 |
| [020](ADR-020-emission-credential-issuer.md) | Émission de credential (credential-issuer, L2.4) | accepté | 2026-08-23 |
| [021](ADR-021-quorum-admin-api.md) | Quorum sur les opérations critiques (admin-api, L2.5, portée réduite) | accepté | 2026-08-23 |
| [022](ADR-022-openapi-access-broker-admin-api.md) | Première entrée HTTP réelle (access-broker, admin-api, contracts/openapi/) | accepté | 2026-08-23 |
| [023](ADR-023-ceremonie-webauthn-http-identity-provider.md) | Endpoints HTTP de cérémonie WebAuthn (identity-provider, H5) | accepté | 2026-08-23 |
| [024](ADR-024-frontiere-crypto-typescript-console-web.md) | Frontière crypto TypeScript (console-web) | accepté | 2026-08-23 |
| [025](ADR-025-entree-reseau-credential-issuer.md) | Entrée réseau réelle pour credential-issuer + câblage access-broker (L2.4 suite) | accepté | 2026-08-24 |
| [026](ADR-026-pont-audit-rust-go.md) | Pont d'audit Rust↔Go : audit-sealer (Rust) + audit-collector (Go), socket Unix | accepté | 2026-08-24 |
| [027](ADR-027-champ-decision-audit-seal.md) | Champ decision dans audit-seal/v1 (policy.decided), access-broker câblé sur audit-collector | accepté | 2026-08-24 |
| [028](ADR-028-quorum-operation-audit-admin-api.md) | admin-api câblé sur audit-collector : un quorum.operation par porteur distinct | accepté | 2026-08-24 |

## Règles

- Statut : `proposé` → `accepté` → éventuellement `remplacé par ADR-NNN`. Un ADR n'est jamais
  supprimé ni réécrit après acceptation : il est remplacé.
- Seul un humain fait passer un ADR de `proposé` à `accepté`.
- Un ADR sans seconde option crédible n'est pas une décision mais une contrainte : le formuler
  comme telle.
- Un ADR sans conséquence négative identifiée n'a pas été assez creusé.
- Utiliser `/adr <sujet>` pour générer le squelette.
