# ADR-021 — Quorum sur les opérations critiques (`admin-api`, L2.5, portée réduite)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique

## Contexte

`security/threat-models/admin-api.md` (L0.5) documente déjà, explicitement, que deux des
décisions structurantes attendues de L2.5 sont **non tranchées, à clarifier avant L2** :
- **Chemin de modification à chaud des politiques** (risque Tampering) : « `admin-api` peut-il
  modifier une politique sans passage par CI/revue, ou seulement déclencher un déploiement d'une
  version déjà validée ? »
- **Granularité des rôles d'administration** (risque EoP) : « non encore implémenté... dette de
  conception explicite avant L2 ».

Trancher ces deux questions dans cette contribution, sans instruction supplémentaire, inventerait
une politique d'autorisation non voulue — précisément ce que ce projet a refusé de faire ailleurs
(H2 : pas de mécanisme d'authentification de production inventé pour OpenBao ; H3 : pas de
distribution de clé inventée ; L2.3 : pas de distinction contexte vérifié/déclaré inventée).

## Décision de portée

L2.5 livre uniquement ce qui a un critère d'acceptation concret et déjà spécifié par le backlog :
**le quorum** (« une modification de politique par un seul administrateur est refusée... un seul
porteur ne peut jamais déclencher »). Le chargement/versionnement des politiques et la
granularité des rôles restent explicitement hors périmètre, hérités du modèle de menaces tels
quels — pas résolus silencieusement, pas improvisés.

## Décisions

### Réutilisation d'`identity-assertion/v1` via H3, jamais une nouvelle suite

Même raisonnement qu'ADR-009 (L1.3, récupération à quorum) : chaque porteur approuve en
produisant sa propre assertion `identity-assertion/v1` (comme n'importe quel principal),
`admin-api` vérifie chacune via `identity.v1.AssertionVerificationService` (H3, réel depuis cette
contribution) et compte les `subject_id` **distincts** parmi les vérifiées. Aucune ligne ajoutée
à `zs-crypto`, aucune nouvelle entrée CBOM — exactement la conséquence qu'ADR-009 revendiquait
pour L1.3.

### Plancher `MinimumThreshold = 2` imposé par le module

Même garde-fou structurel qu'`zs_webauthn::recovery::verify_quorum` : un appelant qui
configurerait `threshold = 1` par erreur ne peut pas contourner le plancher — `VerifyQuorum`
panique explicitement plutôt que d'accepter silencieusement un seuil affaibli. Panique, pas une
erreur retournée : c'est une erreur de programmation de l'appelant (configuration), pas une
condition d'exécution normale à gérer.

### Agnostique de l'opération et du rôle

`VerifyQuorum` ne sait pas quelle opération critique il protège ni qui a le droit de l'initier —
ces deux questions sont précisément les deux angles morts non tranchés. L'appelant fournit
`expectedAuthorityDomain` et la liste d'assertions ; le module ne fait que compter des porteurs
distincts vérifiés. Cette conception délibérément étroite garde le module réutilisable quel que
soit le futur système de rôles, sans figer une hypothèse non instruite.

### Deux assertions valides du même porteur ne comptent qu'une fois

Critère d'acceptation exact du backlog (« un seul porteur ne peut jamais déclencher ») : un
attaquant qui soumettrait deux assertions distinctes du même `subject_id` (rejeu, ou simplement
double signature du même porteur) n'atteint jamais le quorum — vérifié par test
(`TestUnSeulPorteurNePeutJamaisDeclencherMemeAvecPlusieursAssertions`), qui compte explicitement
les porteurs distincts plutôt que le nombre brut d'assertions valides.

### `apps/admin-api/internal/quorum`, bibliothèque d'abord

Même patron que L2.3/L2.4 : aucun contrat `access-broker`/opérateur → `admin-api` n'existe,
`main.go` reste un stub. Tests locaux avec doublure de
`identity.v1.AssertionVerificationServiceClient` — même limite structurelle que L2.3/L2.4
(`check-no-direct-crypto.sh` sans exemption de test côté Go : ce paquet ne peut pas fabriquer sa
propre assertion signée, même à des fins de test).

## Conséquences

**Positives** — le critère d'acceptation littéral du backlog est tenu et vérifié par test, pas
par lecture. Aucune nouvelle suite cryptographique, aucune nouvelle surface CBOM. Le module reste
réutilisable indépendamment de la granularité de rôles qui sera décidée plus tard.

**Négatives** — `admin-api` ne fait, dans cette contribution, strictement rien d'autre que
vérifier un quorum : pas de gestion de politique, pas de gestion d'identité, pas de rôle. Les deux
questions structurantes du modèle de menaces restent ouvertes après ce lot, comme avant.

**Surface d'attaque** — aucune nouvelle : ce module ne fait que composer une primitive déjà
vérifiée (H3) sans introduire de logique de confiance supplémentaire. Le risque résiduel
« collusion de porteurs distincts mais complices » reste hors de portée du code, comme déjà noté
par le modèle de menaces (organisationnel, pas technique).

## Critère de réexamen

Réexaminer dès que la granularité des rôles d'administration est instruite — `VerifyQuorum`
devra alors être appelé avec un contexte de rôle, pas seulement un domaine d'autorité. Réexaminer
le chemin de modification à chaud des politiques à l'ouverture réelle du versionnement de
`policy-engine` (aucune RPC de rechargement n'existe encore).
