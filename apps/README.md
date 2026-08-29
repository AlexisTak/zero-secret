# apps/

Binaires déployables. Un dossier = un artefact. Aucune dépendance croisée entre composants de
`apps/` — le partage passe par `crates/` (Rust) ou `pkg/` (Go), voir [ADR-001](../docs/adr/ADR-001-langages-et-frontieres.md).

| Composant | Langage | Rôle |
|---|---|---|
| `identity-provider` | Rust | WebAuthn/FIDO2 : enregistrement, vérification, cycle de vie des authentificateurs |
| `policy-engine` | Rust | PDP — évaluation de politique, sans état, sans appel réseau pendant l'évaluation |
| `access-broker` | Go | Parcours JIT : motif, approbation, appel PDP, déclenchement d'émission |
| `credential-issuer` | Go | Seul composant autorisé à dialoguer avec OpenBao/HSM |
| `audit-collector` | Go | Réception, chaînage, signature du journal d'audit |
| `admin-api` | Go | **OPTIONAL** — quorum sur les opérations critiques (gouvernance). Hors chaîne Core : l'approbation du parcours JIT passe par le champ `approvals` d'`access-broker` |
| `console-web` | TypeScript | Interface, rendu serveur, aucune logique de sécurité côté client |

Détail des responsabilités : [docs/architecture.md](../docs/architecture.md).
