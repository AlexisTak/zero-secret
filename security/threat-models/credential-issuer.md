# Modèle de menaces — credential-issuer

**Dernière révision** : 2026-08-22 — **Déclencheur** : lot L0.5, avant tout code L2

## Périmètre

Interface unique vers OpenBao, la PKI et le HSM. **Seul composant autorisé à dialoguer avec le
HSM.** N'accepte d'ordre que d'un `access-broker` authentifié en mTLS et porteur d'une décision
signée par le PDP. Génère un credential à durée de vie bornée, jamais persisté au-delà de sa
propre émission.

C'est le composant qui manipule effectivement le matériel de confiance final (via `zs-hsm`) —
sa compromission équivaut à la capacité d'émettre n'importe quel accès, sans passer par le PDP,
si la vérification de signature de décision est contournée.

## Actifs

- La capacité d'émission elle-même — c'est l'actif le plus critique du plan de données après
  la clé de signature du PDP.
- Le matériel cryptographique manipulé transitoirement (clés éphémères de session vers
  OpenBao/HSM) — jamais persisté, mais présent en mémoire pendant l'émission.
- L'intégrité de la vérification « décision signée par le PDP » — c'est le seul rempart entre
  ce composant et une émission arbitraire.
- La configuration de connexion au HSM (SoftHSM2 en dev, HSM matériel en prod) — pas un secret
  au sens classique, mais une cible de sabotage (rediriger vers un HSM contrôlé par
  l'attaquant).

## Entrées non fiables

| Entrée | Origine | Analyseur | Couverte par fuzzing ? |
|---|---|---|---|
| Ordre d'émission (décision signée) | `access-broker`, mTLS interne | Vérification de signature via `zs-crypto` (jamais directement) | Prévu — surface prioritaire, signature à vérifier avant tout traitement |
| Réponse d'OpenBao/PKI | OpenBao (composant tiers, MPL-2.0, ADR-002) | Client OpenBao officiel, validation de la structure de réponse | Hors périmètre de ce dépôt (bibliothèque tierce), mais une réponse malformée doit rester un refus |
| Réponse du HSM (PKCS#11) | `zs-hsm` (FFI, seul point d'`unsafe` du dépôt) | `zs-hsm` lui-même | Prévu — FFI, surface classique de bugs mémoire, prioritaire pour `make fuzz` |

L'entrée la plus critique est l'ordre d'émission : toute la garantie du système repose sur le
fait qu'il ne peut pas être forgé sans la clé de signature du PDP, détenue exclusivement par
`policy-engine`.

## STRIDE

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | Un ordre d'émission arrive d'un composant se faisant passer pour `access-broker` | Faible (mTLS SPIFFE) | Critique (émission non autorisée) | mTLS avec identité SPIFFE, vérifiée avant tout traitement de l'ordre | Dépend entièrement de la robustesse de l'infrastructure SPIFFE/SPIRE — non revérifiée par ce composant |
| **T**ampering | Un ordre d'émission légitime est rejoué ou modifié (TTL allongé, ressource substituée) | Faible si la signature couvre l'intégralité de la décision | Critique | La signature du PDP porte sur `decision_hash` = empreinte requête + politiques ; toute modification du contenu invalide la signature | Si le `decision_hash` ne couvre pas un champ pertinent (ex. le TTL demandé n'est pas inclus dans l'empreinte signée), une modification de ce champ passerait inaperçue — à vérifier explicitement lors de l'implémentation du contrat de vérification (backlog L2+) |
| **R**epudiation | Une émission de credential est contestée a posteriori | Faible | Moyen | Événement d'audit signé à l'émission, portant la décision source et l'identifiant du bail | Si l'audit échoue à être écrit avant l'émission effective (ordre des opérations), une fenêtre de répudiation existe — à trancher : audit avant ou après émission ? (angle mort explicite, voir hypothèses) |
| **I**nformation Disclosure | Fuite du credential émis (en transit, en mémoire, en journal) | Faible à moyenne selon l'hygiène du code | Critique (c'est littéralement le secret d'accès) | Aucun credential en journal (règle absolue #1), transmission chiffrée à l'utilisateur, pas de persistance au-delà de l'émission | Le scénario 2 de `docs/architecture.md` (vol de credential en mémoire) est explicitement assumé comme un risque à impact borné — la fenêtre résiduelle est la durée de vie du credential, pas plus |
| **D**enial of Service | Épuisement de la capacité d'émission (rate limit du HSM, de la PKI, ou d'OpenBao) | Moyenne (dépend du dimensionnement de l'infra tierce) | Élevé (bloque toute émission de nouveaux accès) | Objectif de service défini (émission < 400 ms p99), à charger-tester ; isolation des pannes d'infra tierce du reste du plan de données à spécifier | Aucune stratégie de dégradation (que faire si OpenBao est indisponible ?) n'est encore définie — dette explicite avant L2 |
| **E**levation of Privilege | Le credential émis porte des droits plus larges que ceux autorisés par la décision (ex. mauvais mapping `constraints` → droits PKI/OpenBao réels) | Moyenne si le mapping n'est pas testé explicitement | Critique | Traduction stricte et testée entre les `constraints` de la `DecisionResponse` et les paramètres réels d'émission (policy, rôle, scope) | C'est un point de traduction manuel entre deux systèmes de représentation des droits (Cedar côté PDP, politiques OpenBao/PKI côté émission) — source classique d'erreur de configuration ; mesure compensatoire à ajouter : test de non-régression comparant chaque `constraint` connue à son effet réel émis |

## LINDDUN — volet vie privée

Ne traite pas de donnée personnelle au-delà de l'identifiant de bail et de la référence de
décision, déjà pseudonymisés en amont. Pas de donnée biométrique.

## Scénarios d'attaque testés

| Menace | Test | Statut |
|---|---|---|
| Ordre d'émission sans signature valide | `internal/issuer/issuer_test.go` — `TestDecisionInvalideEstRefuseeAvantAppelOpenBao` | Écrit |
| Vol de credential en mémoire (scénario 2) | `tests/adversarial/` — impact borné à la fenêtre résiduelle démontré | Non écrit |
| Rejeu d'un ordre d'émission déjà traité | `internal/issuer/issuer_test.go` (`TestDecisionDejaConsommeeEstRefuseeSansSecondAppelOpenBao`) et `internal/grpcapi/handler_test.go` (`TestRejeuDeLaMemeDecisionEstRefuseViaLeReseau`, bout en bout réseau) | Écrit |
| Compromission prestataire (scénario 5) | `tests/adversarial/` — aucun compte dormant après retrait d'un accès prestataire | Non écrit |

## Hypothèses de sécurité

- Le HSM (SoftHSM2 en dev, HSM matériel en prod) est intègre et protège correctement les clés
  qu'il détient — ce composant ne vérifie pas l'intégrité du HSM lui-même, il en dépend.
- La clé de signature du PDP n'est jamais accessible à `credential-issuer` — la vérification se
  fait avec la clé **publique** correspondante, via `zs-crypto`.
- OpenBao et la PKI sont disponibles et se comportent conformément à leur documentation
  officielle — pas revérifié ici (ADR-002).
- **Ordre des opérations tranché (R7, ADR-008/012, réappliqué L2.4)** : `event_id` généré avant
  l'appel OpenBao, `credential.issued` construit seulement après un succès réel — mais
  `credential.issued` n'est toujours pas scellé (voir addendum ci-dessous), la garantie de
  non-répudiation reste donc partielle.

## Addendum (L2.4 suite, ADR-025) — entrée réseau réelle

- `credential-issuer` a désormais un vrai serveur gRPC (`CredentialIssuanceService`), appelé par
  `access-broker` après une décision `ALLOW`. Le rejeu d'une décision — répertorié ci-dessus
  comme théorique tant qu'aucun réseau n'existait — est désormais réellement exploitable et
  fermé (`ConsumedDecisionStore` implémenté en mémoire, mono-instance).
- `credential.issued` reste construit mais non scellé — pas aggravé par ce lot, angle mort
  hérité, à réexaminer avec un futur pont d'audit Rust↔Go (voir critère de réexamen d'ADR-025).
- Pas de mTLS entre `access-broker` et `credential-issuer` — l'hypothèse « seul access-broker
  authentifié peut dialoguer avec credential-issuer » (périmètre de ce document) n'est donc pas
  encore appliquée techniquement, seulement par convention réseau (adresses non exposées).
