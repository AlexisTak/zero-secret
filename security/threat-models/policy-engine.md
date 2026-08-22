# Modèle de menaces — policy-engine

**Dernière révision** : 2026-08-22 — **Déclencheur** : lot L0.5, avant tout code L1/L2

## Périmètre

PDP (Policy Decision Point). Évalue une `DecisionRequest` (contexte complet fourni en entrée)
contre les politiques Cedar, rend une `DecisionResponse` motivée. **Sans état, déterministe,
rejouable hors ligne. Aucun appel réseau pendant l'évaluation** (règle absolue #5 du `CLAUDE.md`
racine) — c'est la propriété la plus structurante de ce composant, celle qui rend l'évaluation
auditable et rejouable via `make replay`.

Frontière de confiance : `access-broker` (Go, appelant authentifié en mTLS) → `policy-engine`
(Rust) → réponse signée. Ne consulte aucune base de données, aucun service externe pendant
l'évaluation ; les politiques et le contexte sont chargés en amont ou fournis dans la requête.

## Actifs

- La capacité de décision elle-même : falsifier ou contourner une évaluation équivaut à
  accorder un accès non autorisé.
- L'intégrité des politiques Cedar évaluées (`policies/access/`) et du schéma d'entités
  (`contracts/cedar/`) — une politique corrompue ou un schéma flou ouvre la confusion de
  requête identifiée dans ADR-003.
- Le `decision_hash` scellé à l'audit — c'est la preuve rejouable de la décision ; sa
  falsification casserait la vérifiabilité de tout l'historique.
- Déterminisme : la garantie que la même requête + les mêmes politiques produisent toujours la
  même décision est elle-même un actif (c'est ce qui permet le rejeu).

## Entrées non fiables

| Entrée | Origine | Analyseur | Couverte par fuzzing ? |
|---|---|---|---|
| `DecisionRequest` (proto) | `access-broker`, réseau interne mTLS | Désérialisation prost (`zs-policy`), puis validation de schéma Cedar | Prévu — surface prioritaire pour `make fuzz`, non encore ciblée |
| Politiques Cedar chargées | `policies/access/`, déployées avec le composant | Validation statique Cedar contre `contracts/cedar/` au chargement | Sans objet (contenu versionné, pas une entrée réseau) — mais un défaut de validation au chargement serait un refus par défaut manqué, à tester explicitement |
| Contexte d'évaluation (posture, approbations, ticket) — fourni **dans** `DecisionRequest`, jamais recherché par le PDP | `access-broker` | Même désérialisation que `DecisionRequest` | Idem |

L'absence d'appel réseau pendant l'évaluation élimine une classe entière d'entrées non fiables
(pas de requête sortante à falsifier, pas de source de données externe à empoisonner) — c'est
la mesure compensatoire structurelle de ce composant, pas un oubli du tableau ci-dessus.

## STRIDE

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | Un appelant non authentifié se fait passer pour `access-broker` | Faible (mTLS SPIFFE requis par l'architecture) | Élevé (évaluation de politique sur requête forgée) | mTLS avec identité SPIFFE vérifiée à la frontière réseau, avant même d'atteindre le PDP | La vérification mTLS est hors du périmètre de ce composant (assumée en amont) — si l'infrastructure SPIFFE/SPIRE est mal configurée, le PDP ne le détecterait pas lui-même |
| **T**ampering | Une politique Cedar est modifiée pour élargir un accès par effet de bord | Faible à moyenne (dépend du contrôle d'accès sur `policies/access/`) | Critique (élargissement d'accès silencieux) | Règle de `policies/CLAUDE.md` : refus par défaut, aucun cas de test de refus supprimé sans ADR ; revue humaine obligatoire sur ce dossier (CODEOWNERS) | Un contributeur autorisé introduisant une régression légitime-en-apparence reste possible ; seule la contrepartie en détection (règle Sigma associée, `policies/CLAUDE.md`) permettrait de le voir a posteriori |
| **R**epudiation | Une décision `ALLOW` est contestée : « la politique n'aurait jamais dû permettre ça » | Moyenne (attendu en usage normal, pas un incident) | Faible à moyen (résolu par le rejeu, pas une faille) | `decision_hash` scellé, `policy_version` explicite dans le contrat, `make replay` reproduit la décision à l'identique hors ligne | Si l'horodatage ou la version de politique enregistrée est ambigu (ex. déploiement concurrent de deux versions), le rejeu peut ne pas retrouver exactement le contexte — mesure compensatoire à formaliser : verrouillage de version au déploiement (hors périmètre L0.5) |
| **I**nformation Disclosure | Le contenu du contexte d'évaluation (posture, justification) fuite via un journal d'erreur trop verbeux | Moyenne | Moyen à élevé (le contexte peut contenir des informations sensibles sur l'utilisateur ou la ressource) | Aucun contexte complet en journal applicatif — seul l'événement d'audit structuré, aux champs définis par `contracts/events/`, en garde une trace | Le contrat d'audit actuel autorise un champ `justification` (texte libre, borné à 512 caractères) — un utilisateur pourrait y saisir une donnée sensible par erreur ; risque résiduel assumé, à mentionner dans la documentation utilisateur d'`access-broker` |
| **D**enial of Service | Politique pathologique (récursion, explosion combinatoire) fait dépasser l'objectif de service (25 ms p99) | Faible à moyenne (dépend de la complexité admise en politique) | Moyen (dégrade le plan de données, ne le bloque pas totalement selon l'architecture à trois plans) | Cedar est conçu pour l'analyse statique et borne l'expressivité (ADR-003) ; limite de complexité à valider par test de charge (`tests/load/`) | Aucune limite de temps d'évaluation explicite n'est encore spécifiée dans le contrat — à ajouter avant la mise en charge (backlog L2+) |
| **E**levation of Privilege | Une requête ambiguë ou un type de ressource flou fait matcher une politique non destinée à cette ressource (confusion de requête, menace nommée par ADR-003) | Moyenne sans schéma strict, faible avec | Critique | Schéma d'entités Cedar typé, validation statique des politiques contre ce schéma (ADR-003) ; `contracts/cedar/` comme source de vérité | C'est la menace structurante ayant motivé le choix de Cedar — reste un risque si le schéma lui-même est mal conçu (type trop large, hiérarchie d'entités ambiguë) ; mesure compensatoire : cas de test dédié à la ressource « proche mais hors périmètre » (`policies/CLAUDE.md`, cas d'attaque n°5) |

## LINDDUN — volet vie privée

Le contexte d'évaluation peut porter un `subject_id` et une `justification` en texte libre.
Non applicable pour la donnée biométrique (jamais présente ici). Le PDP ne persiste rien
lui-même (sans état) : la question de rétention relève de `audit-collector`, pas de ce
composant.

## Scénarios d'attaque testés

| Menace | Test | Statut |
|---|---|---|
| Confusion de requête (type de ressource ambigu) | `tests/adversarial/` — requête sur ressource au préfixe commun mais hors périmètre | Non écrit — backlog L2+ |
| Politique retirée toujours évaluée | `tests/adversarial/` — décision après retrait d'une règle | Non écrit |
| Requête forgée hors mTLS | `tests/adversarial/` — appel direct sans identité SPIFFE | Non écrit, dépend de l'infra L0.6 |
| Dépassement de complexité d'évaluation | `tests/load/` — politique pathologique | Non écrit |

Aucun test encore écrit : composant non implémenté (backlog L2+), modèle préparé en avance de
phase conformément à la méthode de travail attendue (lire avant d'écrire).

## Hypothèses de sécurité

- L'identité de l'appelant (`access-broker`) est vérifiée par mTLS/SPIFFE avant d'atteindre ce
  composant — le PDP ne revérifie pas cette identité lui-même.
- Les politiques et le schéma Cedar déployés sont ceux validés en CI (`buf breaking` pour les
  contrats associés, tests Cedar pour les politiques) — aucune vérification d'intégrité au
  chargement n'est prévue au-delà de ça pour l'instant.
- L'horloge système est synchronisée — la validité temporelle des approbations et du contexte
  en dépend.
- La couche réseau ne modifie pas la requête en transit (intégrité assurée par mTLS).
