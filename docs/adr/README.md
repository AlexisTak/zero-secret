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

## Règles

- Statut : `proposé` → `accepté` → éventuellement `remplacé par ADR-NNN`. Un ADR n'est jamais
  supprimé ni réécrit après acceptation : il est remplacé.
- Seul un humain fait passer un ADR de `proposé` à `accepté`.
- Un ADR sans seconde option crédible n'est pas une décision mais une contrainte : le formuler
  comme telle.
- Un ADR sans conséquence négative identifiée n'a pas été assez creusé.
- Utiliser `/adr <sujet>` pour générer le squelette.
