# Architecture — zero-secret

Référence de vérité pour toute décision de conception. Version condensée du plan de développement
v1.0 (22/08/2026). En cas de divergence, ce fichier fait foi pour le code ; le PDF fait foi pour
la trajectoire projet.

## Le problème résolu

Les infrastructures s'appuient sur des secrets statiques : mots de passe, clés d'API permanentes,
comptes de service persistants. Une compromission donne un accès durable, souvent indétectable.
On remplace la **connaissance d'un secret** par la **preuve cryptographique d'une identité**,
couplée à une autorisation dynamique et à un credential qui expire seul.

## Les trois plans

| Plan | Contenu | Contrainte dominante |
|---|---|---|
| **Contrôle** | administration, politiques, cycle de vie des identités | intégrité ; tolère une indisponibilité brève |
| **Données** | vérification d'assertion, décision, émission de credential | latence et disponibilité ; seul plan dimensionné pour la charge |
| **Observation** | collecte, signature, conservation des preuves | ne doit jamais bloquer le plan de données, ni perdre un événement sans alarme |

Le découplage entre plan de données et plan d'observation passe par une file durable. Une
saturation de l'audit ne dégrade pas l'accès ; une interruption de l'audit déclenche une alarme.

## Composants

| Composant | Langage | Responsabilité **unique** |
|---|---|---|
| `identity-provider` | Rust | WebAuthn/FIDO2 : enregistrement, vérification, cycle de vie des authentificateurs, émission d'assertions signées. **Ne décide d'aucune autorisation.** |
| `policy-engine` | Rust | PDP. Évalue une requête contre les politiques, rend une décision motivée. Sans état, déterministe, rejouable hors ligne. **Aucun appel réseau pendant l'évaluation.** |
| `access-broker` | Go | Parcours JIT : motif, ticket ITSM, approbation, appel PDP, déclenchement d'émission, expiration, révocation. |
| `credential-issuer` | Go | Interface unique vers OpenBao, la PKI et le HSM. **Seul composant autorisé à dialoguer avec le HSM.** |
| `audit-collector` | Go | Réception, horodatage, chaînage séquentiel (`prev_hash`, ancrage périodique — ADR-031), signature, exposition d'un journal vérifiable, export SIEM. |
| `admin-api` | Go | Administration des politiques, identités, approbations. Quorum sur les opérations critiques. |
| `console-web` | TypeScript | Interface. **Aucune logique de sécurité côté client.** |

## Flux nominal (parcours JIT)

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

Chaque étape produit un événement d'audit signé. Une étape sans événement est un défaut bloquant.

## Règles de dépendance

- Les dépendances entre composants sont **unidirectionnelles** et vérifiées en CI.
- `policy-engine` ne dépend d'aucun autre composant applicatif.
- `credential-issuer` n'accepte d'ordre que d'un `access-broker` authentifié en mTLS et porteur
  d'une décision signée par le PDP.
- Aucun composant n'écrit dans la base d'un autre. Les échanges passent par `contracts/`.

## Données

Quatre schémas PostgreSQL, rôles séparés, aucun rôle applicatif en écriture sur plus d'un schéma :

- `identity` — identités, authentificateurs, clés publiques, compteurs de signature
- `authz` — politiques, affectations, approbations
- `issuance` — baux de credentials, états d'expiration
- `audit` — journal en ajout seul ; `UPDATE` et `DELETE` révoqués pour tous les rôles applicatifs

**Ne sont jamais stockés** : un credential, un secret, un condensat de mot de passe, une donnée
biométrique. Seulement des clés publiques, des empreintes, des identifiants de baux.

## Objectifs de service (pilote)

| Indicateur | Cible |
|---|---|
| Évaluation de politique (p99) | < 25 ms |
| Émission de credential (p99) | < 400 ms |
| Vérification d'assertion WebAuthn (p99) | < 80 ms |
| Délai de révocation effective | < 5 s |
| Disponibilité du plan de données | 99,9 % |
| Perte d'événements d'audit | 0, détection obligatoire |

## Scénarios d'attaque que l'architecture doit tenir

Ces six scénarios sont implémentés comme tests exécutables dans `tests/adversarial/`.

1. **Hameçonnage** → échec par conception : WebAuthn lie l'assertion au domaine d'origine.
2. **Vol de credential en mémoire** → impact borné à la fenêtre résiduelle ; pas de persistance.
3. **Compromission d'un poste admin** → une nouvelle tâche exige une action matérielle FIDO2 ;
   le malware peut suivre une session active mais n'exfiltre aucun secret permanent.
4. **Compromission d'un serveur applicatif** → vol d'un certificat court aux droits strictement
   nécessaires ; usage anormal détecté par le SIEM.
5. **Compromission prestataire** → aucun compte dormant, mouvement latéral bloqué.
6. **Compromission de l'IdP** → **limite structurelle assumée du modèle.** Traitée par HSM,
   distribution de l'autorité et détection dédiée, jamais présentée comme résolue.

## Limites assumées

- La compromission de l'IdP reste un risque critique résiduel.
- La reprise après sinistre n'est pas prête tant que l'exercice de destruction/reconstruction
  n'a pas été réalisé et chronométré (lot L6). Avant cela, aucun accès critique ne transite ici.
- Les politiques ABAC fondées sur la télémétrie des postes sont expérimentales.
- La charge d'exploitation est supérieure à celle d'un modèle à secrets statiques. À mesurer
  honnêtement, pas à minimiser.
