# Modèle de menaces — access-broker

**Dernière révision** : 2026-08-22 — **Déclencheur** : lot L0.5, avant tout code L2

## Périmètre

Parcours JIT complet : réception du motif et du ticket ITSM, sollicitation d'approbation,
appel au `policy-engine`, déclenchement de l'émission de credential, suivi de l'expiration et
de la révocation. C'est l'orchestrateur du plan de données — il ne décide rien lui-même
(la décision vient du PDP) et ne détient aucun secret durable (l'émission vient de
`credential-issuer`).

Frontières de confiance : utilisateur authentifié (assertion `identity-provider`) →
`access-broker` (Go, exposé) → `policy-engine` (mTLS interne) → `credential-issuer` (mTLS
interne, ordre d'émission portant la décision signée). Composant le plus exposé du plan de
données : c'est lui qui reçoit les requêtes utilisateur directement.

## Actifs

- La décision signée du PDP, en transit entre l'évaluation et l'ordre d'émission — sa
  substitution romprait le lien entre « ce qui a été autorisé » et « ce qui a été émis ».
- Les références de tickets ITSM et motifs (traçabilité de la demande).
- La disponibilité du parcours JIT — un `access-broker` indisponible bloque tout accès neuf
  (mais n'affecte pas les credentials déjà émis, qui expirent seuls).
- L'état d'approbation en cours (une approbation ne doit être consommée qu'une fois, pour une
  seule demande).

## Entrées non fiables

| Entrée | Origine | Analyseur | Couverte par fuzzing ? |
|---|---|---|---|
| Requête d'accès (ressource, motif, ticket) | Utilisateur authentifié, HTTP | Validation de schéma OpenAPI (`contracts/openapi/`) | Non prévu — surface HTTP structurée, priorité moindre que le binaire WebAuthn |
| Réponse d'approbation | Approbateur (humain ou système), HTTP | Vérification que l'approbateur est distinct du demandeur et habilité | Non prévu |
| `DecisionResponse` (proto) | `policy-engine`, mTLS interne | Désérialisation prost côté Go | Sans objet — appelant de confiance mTLS, mais une réponse malformée doit rester un refus, pas un plantage |

## STRIDE

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | Un attaquant se fait passer pour l'approbateur légitime d'une demande | Faible à moyenne selon le mécanisme d'authentification de l'approbateur (non encore spécifié) | Élevé (approbation frauduleuse → émission réelle) | Authentification forte requise pour l'approbateur (même socle WebAuthn que le demandeur, à spécifier précisément en L2) | Le mécanisme d'authentification de l'approbateur n'est pas encore défini — angle mort explicite à combler avant L2 |
| **T**ampering | Modification de la décision du PDP entre l'évaluation et l'ordre d'émission (l'accès-broker élève lui-même le TTL ou l'effet) | Faible (décision transmise en interne, mTLS) | Critique (contournement total du PDP) | `credential-issuer` n'accepte d'ordre que porteur d'une décision **signée** par le PDP (règle d'architecture explicite) — `access-broker` ne peut pas forger une décision `ALLOW` | Si la clé de signature du PDP est compromise, cette protection tombe — dépend entièrement de l'hypothèse de sécurité sur `zs-crypto`/HSM, hors périmètre de ce composant |
| **R**epudiation | Un utilisateur nie avoir demandé un accès effectivement accordé | Faible | Moyen | Chaque étape du parcours JIT produit un événement d'audit signé (motif, ticket, approbation, décision, émission) | La qualité de la preuve dépend de l'authentification initiale de l'utilisateur (héritée d'`identity-provider`) — une faille en amont se répercute ici sans que ce composant puisse la détecter |
| **I**nformation Disclosure | Fuite du motif ou de la justification saisis par l'utilisateur (texte libre) | Moyenne | Moyen (peut contenir une information sensible sur la ressource ou l'incident traité) | Champ borné en taille (`contracts/events/audit-event.schema.json`), pas de journal applicatif verbeux au-delà de l'événement structuré | Risque résiduel assumé — un utilisateur peut toujours saisir une donnée sensible dans un champ texte libre, aucun filtrage de contenu n'est prévu |
| **D**enial of Service | Volume de demandes d'accès dépassant la capacité de sollicitation d'approbation ou d'appel au PDP | Moyenne (composant le plus exposé, en façade) | Moyen (bloque le plan de données, dimensionné pour la charge selon `docs/architecture.md`) | Limitation de débit à spécifier (backlog L2+), objectifs de service définis (émission < 400 ms p99) à tester en charge | Aucune limitation de débit n'est encore implémentée — dette explicite avant mise en charge |
| **E**levation of Privilege | Un utilisateur soumet une demande dont le contexte (posture, réseau) est falsifié pour obtenir une décision plus favorable | Moyenne si le contexte est déclaré par le client | Élevé | Le contexte transmis au PDP doit provenir de sources vérifiées côté serveur (posture du poste via un agent, pas une déclaration du client) — à spécifier précisément quelle partie du contexte est vérifiable et laquelle est déclarative | Angle mort : la distinction entre contexte vérifié et contexte déclaré n'est pas encore tranchée dans le contrat `DecisionRequest.Context` — à clarifier avant L2, sans quoi le PDP évalue potentiellement des données non fiables comme si elles l'étaient |

## LINDDUN — volet vie privée

Traite motif, référence de ticket et justification — données potentiellement sensibles sur
l'activité professionnelle de l'utilisateur, pas des données personnelles au sens strict sauf
si le texte libre en introduit (risque résiduel déjà noté ci-dessus). Pas de donnée biométrique.

## Scénarios d'attaque testés

| Menace | Test | Statut |
|---|---|---|
| Compromission d'un poste admin (scénario 3) | `tests/adversarial/` — nouvelle tâche sans action FIDO2 fraîche | Non écrit — backlog L2+ |
| Compromission d'un serveur applicatif (scénario 4) | `tests/adversarial/` — usage anormal d'un certificat court détecté | Non écrit |
| Approbateur = demandeur | `tests/adversarial/` — auto-approbation refusée | Non écrit |
| Décision falsifiée en transit | `apps/credential-issuer/internal/issuer/issuer_test.go` (`TestDecisionInvalideEstRefuseeAvantAppelOpenBao`) + `internal/grpcapi/handler_test.go` (bout en bout réseau) — ordre d'émission sans signature PDP valide, refusé par `credential-issuer` | Écrit (L2.4 suite, ADR-025) |

## Hypothèses de sécurité

- L'authentification initiale de l'utilisateur (assertion `identity-provider`) est valide et
  vérifiée en amont — ce composant ne revérifie pas la signature WebAuthn elle-même.
- `credential-issuer` applique strictement la règle « decision signée requise » — `access-broker`
  compte sur cette vérification en aval, il ne la duplique pas.
- Le mécanisme d'authentification de l'approbateur existe et est robuste — **non vérifié**,
  c'est un angle mort explicite de ce modèle (voir STRIDE Spoofing ci-dessus).
- mTLS/SPIFFE est établi correctement vers `policy-engine` et `credential-issuer` en amont de ce
  composant — **hypothèse, pas encore appliquée techniquement** : les trois liaisons gRPC sont
  en clair dans ce dépôt à ce jour (L2.4 suite, ADR-025).

## Addendum (L2.4 suite, ADR-025) — déclenchement réel de l'émission

`access-broker` appelle réellement `credential-issuer` après une décision `ALLOW`
(`internal/httpapi/handler.go`) — jusqu'ici la liaison n'existait qu'en commentaire. Un échec
d'émission (OpenBao indisponible, décision déjà consommée côté `credential-issuer`) ne fait
jamais échouer la requête HTTP ni ne change `allowed` : seuls `lease_id`/
`lease_duration_seconds` restent absents de la réponse — l'appelant doit vérifier leur présence
pour savoir si un accès exploitable a réellement été émis, pas seulement lire `allowed`.
