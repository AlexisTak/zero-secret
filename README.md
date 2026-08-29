# biscuits-shield — zero-secret

Infrastructure d'accès sans secrets statiques : identités cryptographiques (FIDO2/WebAuthn),
moteur de politiques, credentials éphémères juste-à-temps (JIT). prototype d'expérimentation destiné à l'écosystème institutionnel
français de cybersécurité (administrations, opérateurs, CESTI).

> Nous ne demandons pas que cette architecture soit adoptée sur la seule foi de notre
> démonstration. Nous proposons qu'elle soit testée, auditée, confrontée à la réalité
> opérationnelle.

---

## Le problème

Les infrastructures critiques s'appuient historiquement sur des **secrets statiques** : mots de
passe, clés d'API permanentes, comptes de service persistants, accès fournisseurs qui restent
ouverts hors des fenêtres de maintenance. Un secret statique compromis offre un accès durable,
souvent long à détecter :

- un mot de passe de base de données figé dans un `.env` reste valable des mois si le serveur
  qui le porte est compromis ;
- un compte administrateur permanent est exploitable 24h/24, y compris quand personne ne
  l'utilise ;
- une clé d'API en dur dans le code se rote rarement, par construction.

Le MFA (OTP, SMS, push) protège bien la porte d'entrée, mais colmate un système qui reste
fondé sur un secret partagé — le mot de passe. Il ne supprime pas la dépendance au secret
lui-même.

## L'idée

Remplacer la **connaissance d'un secret** par la **preuve cryptographique d'une identité**,
couplée à une **autorisation dynamique et temporelle** :

1. **Identité cryptographique, pas mot de passe.** WebAuthn/FIDO2 : l'authentification résiste au
   phishing par construction (l'assertion est liée au domaine d'origine).
2. **Décision d'accès dynamique, pas rôle statique.** Un moteur de politiques évalue chaque
   demande dans son contexte (heure, réseau, posture du poste, ticket, approbation) et rend une
   décision motivée et rejouable.
3. **Credential éphémère, pas secret permanent.** Généré juste-à-temps pour la durée strictement
   nécessaire de l'opération, jamais stocké au repos, expire seul.
4. **Traçabilité exhaustive.** Chaque étape produit un événement d'audit signé et chaîné —
   invérifiable a posteriori n'est pas une option.

Un compte administrateur n'existe plus 24h/24 : il est créé à la volée, pour la durée de
l'intervention, après approbation, et disparaît de lui-même. Un secret de base de données n'est
plus écrit dans un fichier de configuration : il est délivré par le gestionnaire de secrets au
moment de la connexion, avec une durée de vie bornée.

## Pourquoi ce dépôt existe

J'ai développé ce prototype pour le proposer à l'évaluation d'une entité publique
volontaire — une expérimentation pilote, pas un produit fini. Le dépôt est construit pour être
**audité par des tiers qui n'ont jamais parlé à ses auteurs** : RSSI, CESTI, red team. Cette
contrainte façonne tout le reste — voir [Méthode](#méthode-et-garanties) plus bas.

**Niveau de maturité** : prototype technique fonctionnel, pas encore éprouvé par une revue de
code indépendante ni un test d'intrusion. Assumé comme tel, pas présenté autrement.

---

## Architecture

### Les trois plans

| Plan | Contenu | Contrainte dominante |
|---|---|---|
| **Contrôle** | administration, politiques, cycle de vie des identités | intégrité ; tolère une indisponibilité brève |
| **Données** | vérification d'assertion, décision, émission de credential | latence et disponibilité ; seul plan dimensionné pour la charge |
| **Observation** | collecte, signature, conservation des preuves | ne doit jamais bloquer le plan de données, ni perdre un événement sans alarme |

Le plan d'observation est découplé du plan de données par une file durable : une saturation de
l'audit ne dégrade jamais l'accès ; une interruption de l'audit déclenche une alarme, jamais un
silence.

### Composants

| Composant | Langage | Responsabilité **unique** |
|---|---|---|
| `identity-provider` | Rust | WebAuthn/FIDO2 : enregistrement, vérification, cycle de vie des authentificateurs, émission d'assertions signées. Ne décide d'aucune autorisation. |
| `policy-engine` | Rust | PDP (*Policy Decision Point*). Évalue une requête contre les politiques Cedar, rend une décision motivée. Sans état, déterministe, **rejouable hors ligne** — aucun appel réseau pendant l'évaluation. |
| `access-broker` | Go | Orchestre le parcours JIT : motif, ticket, approbation, appel au PDP, déclenchement d'émission, expiration, révocation. |
| `credential-issuer` | Go | Seul composant autorisé à dialoguer avec OpenBao, la PKI et le HSM. |
| `audit-collector` | Go | Réception des événements, horodatage, chaînage séquentiel (`prev_hash`), exposition d'un journal vérifiable. Les événements sont destinés à un SIEM **externe** (OpenTelemetry, JSON) — ce dépôt n'implémente pas de SIEM. |
| `audit-sealer` | Rust | Pont de scellement cryptographique pour `audit-collector` (Go) — toute la crypto du dépôt passe par des crates Rust auditées ; ce composant sert cette frontière sur socket Unix, jamais un port réseau ouvert. |
| `admin-api` | Go | **OPTIONAL** — quorum sur les opérations critiques (gouvernance). Hors chaîne Core : l'approbation du parcours JIT passe par le champ `approvals` d'`access-broker`, pas par ce composant. |
| `console-web` | TypeScript | Interface, rendu serveur. Aucune logique de sécurité côté client. |

Aucun composant de `apps/` ne dépend d'un autre : le partage passe uniquement par `crates/`
(Rust) ou `pkg/` (Go), vérifié mécaniquement en CI ([ADR-001](docs/adr/ADR-001-langages-et-frontieres.md)).

### Flux nominal (parcours JIT)

```
1. Utilisateur → identity-provider     authentification WebAuthn (AAL3 pour les accès privilégiés)
2. Utilisateur → access-broker         demande d'accès : ressource, motif, référence de ticket
3. access-broker → approbateur         sollicitation d'approbation (si la politique l'exige)
4. access-broker → policy-engine       DecisionRequest (contexte complet en entrée)
5. policy-engine → access-broker       DecisionResponse : effect, max_ttl, constraints, decision_hash
6. access-broker → credential-issuer   ordre d'émission portant la décision signée
7. credential-issuer → OpenBao/HSM     génération d'un credential à durée de vie bornée
8. → utilisateur                       credential éphémère
9. expiration automatique              révocation côté ressource, événement d'audit
```

Chaque flèche produit un événement d'audit signé et chaîné. Une étape sans événement est
considérée comme un défaut, pas un détail à combler plus tard.

Détail complet (données, objectifs de service, scénarios d'attaque tenus, limites assumées) :
[docs/architecture.md](docs/architecture.md).

---

## Périmètre

Toutes les technologies citées dans ce dépôt ne sont pas requises pour faire tourner
biscuits-shield. Quatre niveaux, explicites :

| Niveau | Signification |
|---|---|
| **CORE** | Nécessaire pour démontrer et garantir le modèle zero-secret. Implémenté, testé, dans le chemin critique. |
| **OPTIONAL** | Implémenté et testé, mais retirable sans casser une garantie du Core. |
| **EXPERIMENTAL** | Hors chemin critique. Son échec ne compromet aucune propriété de sécurité du Core. |
| **FUTURE / RESEARCH** | Décidé et documenté, **non implémenté à ce jour**. Aucune ligne de code correspondante dans le dépôt. |

**CORE** — `identity-provider`, `policy-engine`, `access-broker`, `credential-issuer`,
`audit-collector`, `audit-sealer`, `console-web`, les crates `zs-*`, les politiques d'accès Cedar
de `policies/access/`, les contrats de `contracts/`.

**OPTIONAL** — `admin-api` (quorum de gouvernance), `policies/detection/` (règles Sigma).

**EXPERIMENTAL** — `extensions/policy-platform/` (conformité d'infrastructure en Rego/OPA, aucun
composant applicatif ne l'évalue).

**FUTURE / RESEARCH** — SPIFFE/SPIRE, cryptographie post-quantique, rejeu hors ligne
(`zs-replay`), ancrage périodique du journal. Décisions prises et documentées en ADR ; **rien de
tout cela n'est implémenté aujourd'hui**.

---

## Pile technique

### Requis (CORE)

| Domaine | Techno | Où |
|---|---|---|
| Composants critiques | Rust (édition 2024) | `apps/identity-provider`, `apps/policy-engine`, `apps/audit-sealer`, `crates/` |
| Orchestration, API | Go 1.25 | `apps/access-broker`, `apps/credential-issuer`, `apps/audit-collector`, `pkg/` |
| Interface | TypeScript, rendu serveur | `apps/console-web` — aucune logique de sécurité côté client |
| Authentification | WebAuthn / FIDO2 | `crates/zs-webauthn`, `apps/identity-provider` |
| Autorisation | **Cedar** | `policies/access/`, évalué par `apps/policy-engine` via `crates/zs-policy` |
| Secrets dynamiques | OpenBao (MPL-2.0) | via `apps/credential-issuer` uniquement |
| Persistance | PostgreSQL 17+ | 4 schémas cloisonnés : `identity`, `authz`, `issuance`, `audit` |
| HSM | PKCS#11 (SoftHSM2 en dev) | `crates/zs-hsm` uniquement |
| Observabilité | OpenTelemetry | via `pkg/zstelemetry` |

### Non requis

| Techno | Niveau | Précision |
|---|---|---|
| Rego / OPA | EXPERIMENTAL | Conformité d'infrastructure uniquement (`extensions/policy-platform/`). **Ne participe à aucune décision d'accès** et ne remplace jamais Cedar. |
| Règles Sigma | OPTIONAL | Contenu de détection destiné à un SIEM **externe** (`policies/detection/`). Ce dépôt n'implémente pas de SIEM. |
| SPIFFE / SPIRE | FUTURE | Cible retenue pour l'identité machine et le mTLS entre composants ([ADR-001](docs/adr/ADR-001-langages-et-frontieres.md)). **Aucune implémentation dans le dépôt** : les communications internes sont aujourd'hui en clair, limite signalée dans chaque modèle de menaces. |
| ML-KEM, ML-DSA | RESEARCH | Voir la trajectoire post-quantique ci-dessous. |

**Aucune primitive cryptographique n'est écrite dans ce dépôt.** Tout passe par
[`crates/zs-crypto`](crates/zs-crypto), façade unique vers des bibliothèques auditées
(`aws-lc-rs`). Un détecteur statique (`no-direct-crypto`) bloque toute autre voie en CI.

**Trajectoire post-quantique — préparation, pas implémentation.** Ce dépôt ne contient
**aucune** implémentation post-quantique : ni ML-KEM, ni ML-DSA, ni suite hybride, ni dépendance
correspondante. Les signatures reposent aujourd'hui sur ECDSA P-256.

Ce qui existe est la préparation de la migration : chaque suite est versionnée et déclarée dans
[`security/crypto-inventory/suites.toml`](security/crypto-inventory/suites.toml) avec son champ
`anssi_2027_compliant`, son successeur prévu et l'ADR qui la justifie. Les cibles d'hybridation
(`ECDSA P-256 + ML-DSA-65`, `X25519 + ML-KEM-768`) sont des **décisions d'architecture au statut
proposé** ([ADR-030 à ADR-032](docs/adr/README.md)), pas du code.

Ne présentez pas ce projet comme « PQC-ready » : il est *PQC-instruit*, ce qui n'est pas la même
chose.

---

## Où trouver quoi

```
apps/          binaires déployables — 1 dossier = 1 artefact, pas de dépendance croisée
crates/        bibliothèques Rust internes (zs-crypto, zs-webauthn, zs-policy, zs-audit, zs-hsm, …)
pkg/           bibliothèques Go internes
contracts/     OpenAPI 3.1, protobuf, JSON Schema d'événements, schéma Cedar — SOURCE DE VÉRITÉ
policies/      Cedar (accès, CORE) et règles Sigma (détection, OPTIONAL) — avec leurs tests
extensions/    hors Core — policy-platform (Rego/OPA, conformité d'infrastructure)
deploy/        compose Podman de développement, migrations SQL, configuration OTel
security/      modèles de menaces STRIDE, SBOM, CBOM, inventaire cryptographique
tests/         e2e, conformance, scénarios adverses
docs/adr/      décisions d'architecture actées — [index](docs/adr/README.md)
```

Chaque dossier de premier niveau a son propre `README.md` (`apps/`, `crates/`, `pkg/`) ou
`CLAUDE.md` (`crates/zs-crypto/`, `policies/`) qui détaille ses conventions propres.

---

## Démarrer

```bash
make setup      # dépendances, SoftHSM2, hooks git, outillage (cargo-deny, opa, gitleaks, …)
make up         # environnement local complet (Podman) : Postgres, OpenBao, SoftHSM2
make check      # fmt + lint + tests d'architecture — rapide, à lancer souvent
make test       # unitaires + politiques (Cedar + Rego)
make down       # arrête l'environnement local
```

Détail des cibles (`test-crypto`, `fuzz`, `audit`, `sbom`, `replay`, …) : voir le `Makefile` à la
racine, chaque cible est commentée.

---

## Méthode et garanties

Ce projet est conçu pour être justifiable par un tiers, pas seulement pour fonctionner. Quelques
garanties structurelles, vérifiées mécaniquement plutôt qu'affirmées :

- **Refus par défaut.** Tout chemin d'erreur, timeout, politique absente ou entrée malformée
  produit un refus explicite — jamais une valeur par défaut permissive.
- **Aucun secret durable.** Détection continue (gitleaks) en CI et en pré-commit ; les fixtures
  de test génèrent leurs clés à l'exécution.
- **`policy-engine` reste rejouable hors ligne.** Aucun appel réseau pendant l'évaluation d'une
  décision — le contexte arrive intégralement en entrée.
- **Les tests d'attaque priment sur les tests nominaux.** Une politique sans cas de refus attendu
  n'est pas considérée terminée.
- **Chaque fonctionnalité produit son événement d'audit**, signé et couvert par un test, dans la
  même contribution qui l'introduit.

Le détail complet des règles (et pourquoi elles existent) : [`CLAUDE.md`](CLAUDE.md). Les
décisions d'architecture actées, avec leur justification : [`docs/adr/`](docs/adr/README.md).
Les modèles de menaces par composant : [`security/threat-models/`](security/threat-models/).

---

## Licence

[GNU AGPLv3](LICENSE) — les modifications d'un service qui expose ce code sur un réseau doivent
être partagées, y compris pour un usage en ligne sans distribution du binaire. Choix cohérent
avec la vocation du projet : être audité, repris, amélioré publiquement, pas privatisé.
