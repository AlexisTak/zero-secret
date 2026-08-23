# ADR-017 — Parcours JIT (`access-broker`) : bibliothèque d'abord, portée réduite

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique

## Contexte

L2.3 orchestre le flux JIT : ouverture de demande, vérification des approbations (H3), appel au
PDP (L2.2), déclenchement d'émission. Trois dépendances manquent encore : `contracts/openapi/`
(aucun patron de génération Go établi pour une API HTTP dans ce dépôt), `apps/credential-issuer`
(stub vide, L2.4/H2), et un service de scellement d'audit symétrique à H3 pour `policy.decided`
(inexistant). Livrer L2.3 « en entier » aurait exigé de construire ces trois prérequis dans la
même contribution — refusé, cohérent avec le découpage déjà pratiqué en H1/H2/H3.

## Décisions

### Bibliothèque Go d'abord, pas de serveur HTTP dans ce lot

Décision validée par l'utilisateur : `apps/access-broker/internal/broker` porte la logique
testable, `main.go` reste le stub existant. Même coupe qu'`identity-provider` en L1.1
(bibliothèque WebAuthn sans serveur). `contracts/openapi/` — quand il sera défini — sera un
contrat à part entière, pas une conséquence accessoire de ce lot.

### Contexte déclaré uniquement — `Posture` et `Approval.approved_at`

Décision validée par l'utilisateur, deuxième angle mort L0.5 : aucun agent de posture de confiance
n'existe dans ce dépôt. `broker.Posture` ne distingue pas vérifié/déclaré — c'est un gap réel,
documenté en commentaire de code (`types.go`), pas un mécanisme de vérification inventé sans
instruction. Étendu par cohérence à `Approval.approved_at` : `identity.v1.VerifyAssertionResponse`
(H3) ne renvoie pas d'horodatage vérifié pour l'assertion (seulement `subject_id`/`aal`/
`auth_method`/`audit_event_id`) — l'horodatage d'approbation reste donc une valeur déclarée par
l'appelant. Rouvrir le contrat H3 pour ajouter `issued_at` vérifié était possible (PR non
fusionnée) mais volontairement écarté : ça aurait déplacé le problème sans le résoudre tant que
`Posture` reste déclarée de toute façon — traiter les deux uniformément est plus honnête qu'un
correctif partiel qui donnerait une fausse impression de rigueur.

**`Context.requested_at`** est en revanche fixé par `access-broker` lui-même (horloge système au
moment du traitement), jamais fourni par l'appelant — un appelant qui choisirait sa propre valeur
pourrait contourner la fraîcheur de posture évaluée côté PDP. Même raisonnement qu'
`AcceptancePolicy.now` (H3, ADR-016).

### Règle d'approbation universelle, provisoire

Toute demande sans au moins une approbation **vérifiée** (via H3) est refusée avant l'appel au
PDP — critère d'acceptation du backlog satisfait littéralement, mais par une règle universelle,
pas par une distinction par politique. Justifié concrètement : la seule politique réelle
aujourd'hui (`db.connect`, L2.1/ADR-014) exige déjà une approbation inconditionnellement — la
règle universelle n'est donc pas une simplification arbitraire, c'est l'état exact du seul cas qui
existe. Un mécanisme de métadonnées par politique (quelles actions exigent une approbation, et
combien) reste à concevoir quand plusieurs politiques aux exigences différentes existeront.

### Aucun test d'intégration réel avec de vrais serveurs

Contrairement à L2.2/H3 (tests réels avec de vrais clients `tonic` contre de vraies instances),
`access-broker` n'a que des tests locaux avec des doublures des interfaces gRPC générées. Raison
structurelle, pas de flemme : fabriquer une assertion `identity-assertion/v1` de test exige de
signer, et `tools/lib/check-no-direct-crypto.sh` interdit tout import crypto Go direct **sans
l'exemption de test que Rust possède** (`mod tests { ... }` — mécanisme propre à Rust, jamais
porté côté Go). Un test Go ne peut donc légitimement pas fabriquer sa propre signature de test,
même à des fins de test — la frontière crypto reste incontournable dans les deux sens. Un test
d'intégration réel nécessiterait soit une fixture signée pré-générée côté Rust et committée (angle
non retenu : une fixture figée expire au bout de sa fenêtre de validité, devenant un test cassé
plutôt qu'un signal utile), soit d'assouplir le hook (refusé : rouvrirait exactement le risque que
la règle absolue #4 ferme).

### `error` réservé aux échecs de transport, jamais à un refus métier

Même discipline que `policy-engine`/`identity-provider` (P2) : `Broker.Decide` retourne toujours
une `Decision` valide pour un refus métier, `error` seulement pour un échec réseau ou une
validation locale qui n'a même pas produit de contexte de décision exploitable.

## Conséquences

**Positives** — le flux est testé et vérifiable indépendamment de tout serveur réseau ; la
traduction vers `DecisionRequest` est stricte (P2 partout, aucun défaut permissif). La frontière
crypto Go/Rust reste tenue même dans les tests, pas seulement en production.

**Négatives** — pas d'entrée HTTP réelle : `access-broker` reste inutilisable en dehors de tests
unitaires jusqu'à ce que `contracts/openapi/` existe. La règle d'approbation universelle devra
être remplacée avant l'ajout d'une deuxième politique aux exigences différentes. Le traitement
déclaré de `Posture`/`Approval.approved_at` est un vrai gap de sécurité, pas résolu, seulement
documenté.

**Surface d'attaque** — un appelant pourrait déclarer une posture ou un horodatage d'approbation
arbitraire ; rien dans ce lot ne le détecte. Acceptable uniquement parce qu'aucun déploiement réel
ne s'appuie sur `access-broker` à ce stade.

## Critère de réexamen

Réexaminer la règle d'approbation universelle dès qu'une deuxième politique aux exigences
différentes existe. Réexaminer le traitement déclaré de la posture/de l'horodatage d'approbation
si un mécanisme de vérification de posture (agent de confiance) ou un `issued_at` vérifié côté H3
est un jour instruit. Réexaminer l'absence d'entrée HTTP à l'ouverture de `contracts/openapi/`.
