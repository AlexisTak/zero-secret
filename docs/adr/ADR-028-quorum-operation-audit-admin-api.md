# ADR-028 — `admin-api` câblé sur `audit-collector` : un `quorum.operation` par porteur distinct

**Statut** : accepté
**Date** : 2026-08-24
**Décideurs** : responsable technique

## Contexte

Suite du câblage des producteurs Go sur `audit-collector` (ADR-026/ADR-027, `access-broker`
déjà fait). `admin-api` doit émettre `quorum.operation` après chaque vérification de quorum
(`POST /v1/critical-operations/{operation_id}/quorum`, ADR-021). Contrairement à
`policy.decided`, `quorum.operation` ne porte pas de champ `decision` — `zs_crypto::audit_seal::
EventType::requires_decision()` ne le requiert pas, aucun changement crypto nécessaire ici.

## Décision

**Problème structurant** : le contrat (`contracts/events/audit-event.schema.json`) porte un seul
champ `actor` par événement, objet unique `{subject_id, kind, ...}` — mais un quorum est par
nature porté par plusieurs porteurs distincts (`quorum.Result.DistinctSubjects`). Aucun
précédent dans ce dépôt : `EventType::QuorumOperation` existait déjà côté `zs-crypto` mais
n'était produit par aucun composant avant ce lot.

**Retenu : un événement `quorum.operation` par porteur distinct vérifié**, pas un événement
agrégé. Chaque événement porte `actor = {subject_id: <ce porteur>, kind: "human"}`,
`target = {type: "critical_operation", id: operation_id}`, `outcome` reflétant le résultat
**global** du quorum (`success` si atteint, `denied` sinon) — pas la validité de la vérification
individuelle de ce porteur, qui a toujours réussi puisqu'il apparaît dans
`DistinctSubjects`. Aucun champ `decision`.

**Alternative rejetée** : un seul événement par appel, `actor = {kind: "system", subject_id:
"admin-api"}`, porteurs listés en texte libre dans `context.justification`. Rejetée : perd
l'attribution individuelle par porteur, qui est précisément ce que le quorum est censé
garantir et tracer — un champ texte libre non structuré n'est pas rejouable de façon fiable par
un outil de vérification hors ligne.

**Émis seulement pour les porteurs réellement vérifiés** — jamais pour un refus avant
vérification (seuil sous le plancher `MinimumThreshold`, corps malformé) : sans identité
établie, il n'y a personne à qui attribuer l'événement (même principe que `policy.decided`,
ADR-027 : pas d'audit pour un refus local avant tout appel externe).

**Best-effort, comme `policy.decided`** : une panne d'`audit-collector`, ou un refus métier
(`RecordResult.Accepted = false`), sont journalisés mais ne bloquent jamais la réponse HTTP —
le quorum a déjà été évalué de façon irréversible au moment où l'audit est tenté.

## Conséquences

**Positives** — attribution individuelle préservée par porteur, cohérent avec la fonction même
du quorum. Aucun changement de contrat ni de `zs-crypto` requis.

**Négatives** — un appel `POST /quorum` avec N porteurs distincts produit N événements
d'audit, pas un seul événement "quorum operation" atomique — un futur outil de rejeu devra
regrouper ces N événements par `target.id` (`operation_id`) pour reconstituer l'opération
complète ; ils partagent le même `authority_domain` mais des `sequence` différentes,
potentiellement non consécutives si d'autres événements du même domaine s'intercalent.

**Surface d'attaque** — inchangée : `admin-api` parle uniquement à `audit-collector` (réseau
normal, même dette de TLS que partout ailleurs), jamais directement à `audit-sealer`.

## Critère de réexamen

Réexaminer si un outil de rejeu (`make replay`, non construit) peine à reconstituer une
opération de quorum depuis ses N événements — pourrait alors justifier un événement agrégé
supplémentaire, une fois la charge utile exacte instruite.
