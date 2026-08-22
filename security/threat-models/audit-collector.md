# Modèle de menaces — audit-collector

**Dernière révision** : 2026-08-22 — **Déclencheur** : lot L0.5, avant tout code L1.4

## Périmètre

Réception, horodatage, chaînage Merkle, signature, exposition d'un journal vérifiable, export
SIEM. C'est le plan d'observation : découplé du plan de données par une file durable — une
saturation de l'audit ne dégrade pas l'accès, mais une interruption de l'audit **doit**
déclencher une alarme (contrainte explicite de `docs/architecture.md`). C'est la source de
vérité pour tout rejeu (`make replay`) et pour toute preuve devant un tiers (RSSI, CESTI).

## Actifs

- L'intégrité du chaînage — c'est la propriété qui rend le journal vérifiable ; un chaînage
  cassé ou falsifiable invalide la garantie de non-répudiation de tout le système.
- La disponibilité et la complétude du journal — un événement manquant est indiscernable d'une
  action qui n'a jamais eu lieu, sauf alarme immédiate.
- La clé de signature des événements (composante du CBOM, gérée via `zs-crypto`/HSM comme les
  autres signatures du système).
- Les données elles-mêmes (contexte, décisions, identités pseudonymisées) — moins sensibles
  individuellement que leur intégrité collective, mais soumises aux mêmes contraintes RGPD.

## Entrées non fiables

| Entrée | Origine | Analyseur | Couverte par fuzzing ? |
|---|---|---|---|
| Événement d'audit (JSON) | Tout composant du système (`identity-provider`, `policy-engine` via `access-broker`, `credential-issuer`, `admin-api`) | Validation contre `contracts/events/audit-event.schema.json` | Prévu — schéma JSON, cible naturelle pour un fuzzer de schéma |
| Requête de lecture du journal (export SIEM, vérification de chaîne) | SIEM externe, opérateur | Contrôle d'accès en lecture seule, pas de mutation possible (`UPDATE`/`DELETE` révoqués au niveau schéma PostgreSQL) | Non prioritaire — surface de lecture, pas d'écriture |

L'entrée la plus critique est l'événement d'audit lui-même : c'est un flux à haut volume,
provenant de tous les autres composants, et la seule barrière avant l'écriture en base est la
validation de schéma — un défaut ici pourrait laisser passer un événement mal formé qui
casserait le chaînage en aval.

## STRIDE

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | Un émetteur non légitime injecte de faux événements d'audit | Faible (mTLS SPIFFE entre composants internes) | Élevé (pollution ou fabrication de preuve) | Authentification mTLS de chaque émetteur, `actor.kind` porté par l'événement lui-même mais vérifié contre l'identité mTLS de la connexion | Si un composant légitime est compromis, il peut émettre de faux événements en son propre nom — cette limite est structurelle, pas spécifique à `audit-collector` |
| **T**ampering | Modification d'un événement déjà écrit pour effacer une trace | Très faible si le rôle applicatif ne peut pas faire `UPDATE`/`DELETE` (backlog L0.6) | Critique (invalide toute la garantie d'audit) | Schéma `audit` : `UPDATE` et `DELETE` révoqués pour tous les rôles applicatifs (backlog L0.6, à prouver par test, pas par lecture de migration) ; chaînage Merkle rend toute modification détectable même en cas de contournement du contrôle d'accès applicatif | Un accès direct au superutilisateur PostgreSQL contournerait le contrôle de rôle — seul le chaînage cryptographique resterait comme détection, pas comme prévention ; c'est un risque résiduel structurel assumé, cohérent avec le scénario 6 (aucune protection n'est absolue face à un accès superutilisateur, seule la détection compte) |
| **R**epudiation | Un composant nie avoir émis un événement qu'il a bien produit | Très faible (c'est l'inverse même de la fonction de ce composant) | Non applicable — ce composant EST la mesure contre la répudiation des autres, il ne peut pas raisonnablement répudier ses propres événements sans invalider sa propre fonction | Chaînage et signature garantissent l'attribution ; sans objet au-delà | Non applicable — c'est la mesure compensatoire de tout le reste du système, pas une menace propre à ce composant |
| **I**nformation Disclosure | Fuite du journal complet (export SIEM mal configuré, ou accès en lecture trop large) | Moyenne (le journal agrège des données de tout le système, cible de valeur) | Élevé (agrégation = surface bien plus large que chaque composant pris isolément) | Contrôle d'accès en lecture strict, export SIEM authentifié, aucune donnée biométrique ni secret dans les événements (contrainte de schéma explicite : « INTERDIT : credential, clé, jeton complet, donnée biométrique ») | Le champ `justification` (texte libre, jusqu'à 512 caractères) peut porter une donnée sensible saisie par erreur en amont — ce composant ne peut pas la filtrer a posteriori sans casser l'intégrité du chaînage (modifier un événement déjà chaîné est interdit par construction) ; risque résiduel assumé, à traiter en amont (validation à la source, pas ici) |
| **D**enial of Service | Flot d'événements dépasse la capacité d'ingestion, ou la file durable sature | Moyenne (volume proportionnel à l'activité de tout le système) | Faible pour le plan de données (découplé par construction), élevé pour l'observabilité elle-même | File durable entre plan de données et plan d'observation (architecture à trois plans) ; alarme obligatoire en cas d'interruption de l'audit, jamais un blocage silencieux | Une saturation prolongée pourrait dépasser la capacité de rattrapage de la file — au-delà d'un certain volume ou d'une certaine durée, une perte d'événements devient possible malgré la conception ; à borner par un objectif de service explicite (« perte d'événements d'audit : 0, détection obligatoire » — la détection est garantie, la prévention absolue ne l'est pas) |
| **E**levation of Privilege | Un rôle en lecture seule sur le schéma `audit` obtient un accès en écriture par mauvaise configuration | Faible si les migrations sont correctement testées | Critique | Rôles PostgreSQL séparés par schéma (`identity`, `authz`, `issuance`, `audit`), aucun rôle applicatif en écriture sur plus d'un schéma | Vérifié par test uniquement à partir de L0.6 (« le rôle applicatif `audit_writer` échoue explicitement sur un `DELETE` — le prouver par un test ») ; jusque-là, c'est une intention de conception non encore prouvée |

## LINDDUN — volet vie privée

C'est le composant qui agrège le plus de données à caractère potentiellement personnel de tout
le système (identifiants de principal, horodatages d'activité, justifications en texte libre).
Aucune donnée biométrique. La politique de rétention et la portée exacte de l'export SIEM
doivent faire l'objet d'une analyse d'impact si ce composant traite des données personnelles
au sens RGPD au-delà des identifiants techniques — signalement requis avant tout déploiement
traitant des utilisateurs réels, conformément au `CLAUDE.md` racine.

## Scénarios d'attaque testés

| Menace | Test | Statut |
|---|---|---|
| Événement manquant pour une action du parcours | `tests/adversarial/` — test qui compte les événements attendus (backlog L1.4) | Non écrit |
| Modification d'un événement déjà chaîné | `tests/adversarial/` — `UPDATE`/`DELETE` refusés par le rôle applicatif | Non écrit — backlog L0.6 |
| Interruption de l'audit sans alarme | `tests/adversarial/` — panne simulée du collecteur, alarme vérifiée | Non écrit |
| Chaîne rejouée avec un événement retiré | `tests/adversarial/` — `make replay` détecte le trou | Non écrit |

## Hypothèses de sécurité

- L'horloge système est synchronisée (NTP) — l'horodatage et l'ordre du chaînage en dépendent
  directement.
- Le HSM protège la clé de signature des événements ; ce composant ne vérifie pas
  l'intégrité du HSM lui-même.
- Les rôles PostgreSQL sont correctement configurés selon les migrations (backlog L0.6) — non
  encore prouvé par test à ce jour, traité comme hypothèse jusque-là.
- La file durable entre plan de données et plan d'observation existe et fonctionne — sa propre
  disponibilité n'est pas garantie par ce composant, elle est une dépendance externe.
