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

## Règles

- Statut : `proposé` → `accepté` → éventuellement `remplacé par ADR-NNN`. Un ADR n'est jamais
  supprimé ni réécrit après acceptation : il est remplacé.
- Seul un humain fait passer un ADR de `proposé` à `accepté`.
- Un ADR sans seconde option crédible n'est pas une décision mais une contrainte : le formuler
  comme telle.
- Un ADR sans conséquence négative identifiée n'a pas été assez creusé.
- Utiliser `/adr <sujet>` pour générer le squelette.
