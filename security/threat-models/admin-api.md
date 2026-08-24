# Modèle de menaces — admin-api

**Dernière révision** : 2026-08-24 — **Déclencheur** : câblage sur `audit-collector`
(`quorum.operation`, ADR-028)

## Périmètre

Administration des politiques, identités et approbations. **Quorum sur les opérations
critiques.** C'est le plan de contrôle : tolère une indisponibilité brève (contrairement au
plan de données), mais toute compromission ici a un effet différé sur l'ensemble du système
(une politique modifiée n'a d'impact qu'à la prochaine évaluation, mais cet impact peut être
large et silencieux).

**Depuis ADR-028** : chaque vérification de quorum ayant au moins un porteur réellement vérifié
émet un `quorum.operation` par porteur distinct vers `audit-collector` (réseau normal, même
dette de TLS que partout ailleurs) — best-effort, une panne ou un refus métier sont journalisés
mais ne bloquent jamais la réponse HTTP. Rien n'est audité pour un refus avant vérification
(seuil sous le plancher, corps malformé) : sans identité établie, il n'y a personne à qui
attribuer l'événement.

## Actifs

- La capacité de modifier les politiques d'accès — équivalent fonctionnel à modifier le
  périmètre d'autorisation de tout le système sans passer par le PDP lui-même.
- La capacité de gérer le cycle de vie des identités (révocation, quorum de récupération) —
  détournée, elle permettrait soit de bloquer un utilisateur légitime, soit de faciliter la
  récupération frauduleuse d'un accès révoqué.
- Le mécanisme de quorum lui-même — c'est la seule protection contre un administrateur unique
  compromis initiant une opération critique seul.

## Entrées non fiables

| Entrée | Origine | Analyseur | Couverte par fuzzing ? |
|---|---|---|---|
| Requête de modification de politique | Administrateur authentifié, HTTP | Validation de schéma OpenAPI, puis validation Cedar statique avant tout déploiement | Non prévu — surface HTTP structurée |
| Requête de révocation/récupération d'identité | Administrateur ou porteur de quorum, HTTP | Vérification de quorum (plusieurs porteurs distincts requis) | Non prévu |
| Approbations multiples pour une opération de quorum | Plusieurs porteurs distincts | Vérification que chaque approbation provient d'un porteur réellement distinct, non réutilisable | À spécifier précisément — surface sensible, candidate à un test adversarial dédié plutôt qu'à du fuzzing |

## STRIDE

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | Un attaquant se fait passer pour un administrateur ou un porteur de quorum | Faible (authentification forte attendue, AAL3 cohérent avec les accès privilégiés) | Critique | Authentification WebAuthn AAL3 pour toute opération d'administration (cohérent avec `docs/architecture.md` : « authentification WebAuthn (AAL3 pour les accès privilégiés) ») | Dépend de la robustesse de l'authentification amont (`identity-provider`) — une faille là-bas se répercute intégralement ici |
| **T**ampering | Une politique est modifiée pour élargir un accès, en contournant la revue humaine | Faible à moyenne selon le processus de déploiement | Critique | Validation Cedar statique avant déploiement, revue humaine obligatoire hors bande (CODEOWNERS sur `policies/access/` au niveau du dépôt — mais une modification via `admin-api` en production est un chemin distinct du dépôt git, à sécuriser séparément) | **Angle mort structurel** : ce modèle suppose que les politiques passent par le dépôt versionné et revu, mais `admin-api` expose potentiellement un chemin de modification à chaud qui contournerait cette revue — à clarifier avant L2 : `admin-api` peut-il modifier une politique sans passage par CI/revue, ou seulement déclencher un déploiement d'une version déjà validée ? |
| **R**epudiation | Une opération d'administration critique est contestée (qui a initié la révocation ?) | Faible | Élevé (surtout pour les opérations à quorum, où l'attribution individuelle compte) | Chaque approbation de quorum et chaque modification produit un événement d'audit signé, portant l'identité de chaque porteur distinct | Si le mécanisme de quorum ne distingue pas correctement des porteurs collusoires d'un véritable quorum indépendant, la non-répudiation individuelle reste formellement correcte mais trompeuse sur la réalité du contrôle — risque organisationnel plus que technique, à documenter |
| **I**nformation Disclosure | Fuite de la configuration des politiques ou de la liste des identités administrées | Moyenne (surface d'administration, cible naturelle) | Moyen à élevé selon le contenu exposé | Contrôle d'accès strict, principe du moindre privilège sur les rôles d'administration | Les politiques elles-mêmes ne sont pas des secrets (elles sont versionnées en clair dans `policies/`) — le risque porte surtout sur les métadonnées d'identité, à traiter comme une donnée personnelle |
| **D**enial of Service | Un attaquant sature `admin-api` pour empêcher une révocation urgente | Faible à moyenne | Élevé si ça retarde une révocation critique (fenêtre d'exposition prolongée) | Le plan de contrôle tolère une indisponibilité brève selon l'architecture — mais une révocation urgente est justement le cas où cette tolérance est la plus dangereuse | Tension explicite entre « le plan de contrôle tolère l'indisponibilité » (conception) et « une révocation doit être immédiate » (backlog L1.3, délai < 5 s) — à trancher : la révocation passe-t-elle uniquement par `admin-api`, ou existe-t-il un chemin de révocation d'urgence isolé du reste du plan de contrôle ? Non tranché, risque résiduel explicite |
| **E**levation of Privilege | Un administrateur aux droits limités (ex. gestion d'identités seulement) parvient à modifier une politique d'accès | Faible si les rôles d'administration sont finement séparés | Critique | Séparation des rôles d'administration par domaine (politiques, identités, approbations) — à spécifier précisément lors de l'implémentation | Non encore implémenté ; la granularité réelle des rôles d'administration reste à définir, c'est une dette de conception explicite avant L2 |

## LINDDUN — volet vie privée

Traite des identités administrées (liste des principaux, leurs rôles, leur statut) — donnée
personnelle par nature (identifie des personnes). Pas de donnée biométrique. Une analyse
d'impact est requise avant tout déploiement traitant des utilisateurs réels, conformément à la
contrainte RGPD du `CLAUDE.md` racine — ce composant est probablement celui qui la déclenchera
en premier, étant la surface d'administration des identités.

## Scénarios d'attaque testés

| Menace | Test | Statut |
|---|---|---|
| Récupération à un seul porteur | `tests/adversarial/` — un seul porteur ne peut jamais déclencher une récupération (backlog L1.3) | Non écrit |
| Modification de politique sans revue | `tests/adversarial/` — chemin de modification à chaud testé contre le contournement de CI | Non écrit, dépend de la clarification de l'angle mort ci-dessus |
| Révocation retardée par saturation | `tests/adversarial/` — délai de révocation sous charge | Non écrit |
| Rôle d'administration limité élevant ses droits | `tests/adversarial/` — tentative de modification de politique par un rôle « identités seulement » | Non écrit |

## Hypothèses de sécurité

- L'authentification WebAuthn AAL3 est appliquée à toute opération d'administration critique —
  ce composant ne redéfinit pas ce niveau, il en dépend.
- Le mécanisme de quorum garantit des porteurs réellement distincts et non colludés — hypothèse
  organisationnelle autant que technique, non vérifiable uniquement par le code.
- Les politiques déployées via `admin-api` ont, d'une manière ou d'une autre, traversé la
  validation Cedar statique — le mécanisme précis (déploiement d'une version pré-validée vs.
  modification à chaud) reste à clarifier, voir STRIDE Tampering ci-dessus.
