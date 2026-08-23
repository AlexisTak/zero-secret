# ADR-020 — Émission de credential (`credential-issuer`, L2.4)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique

## Contexte

Avec H2 (client OpenBao) et H4 (signature/vérification de décision) livrés, L2.4 authentifie
réellement un ordre d'émission avant tout appel à OpenBao. `security/threat-models/
credential-issuer.md` (L0.5) documentait déjà les menaces et deux angles morts explicites :
l'ordre audit/émission, et la traduction stricte verbe/`constraints` → paramètres réels d'émission.

**Aucun contrat `access-broker → credential-issuer` n'existe** — même coupe que L2.3 :
bibliothèque d'abord (`apps/credential-issuer/internal/issuer`), pas de serveur gRPC/HTTP dans ce
lot. `main.go` reste un stub.

## Décisions

### Ordre audit/émission : réapplication de R7, pas une nouvelle règle

Le backlog demandait de reprendre le raisonnement d'ADR-010 plutôt que de le réinventer. Le
précédent directement applicable est **R7** (ADR-008/012) : identifiant généré avant, artefact
scellé le portant, événement scellé après portant l'empreinte de l'artefact réel. Appliqué ici :
`event_id` (UUIDv7) généré **avant** l'appel à OpenBao ; l'événement `credential.issued`
lui-même n'est construit qu'**après** un succès réel — un événement ne doit jamais affirmer
l'existence d'un credential qui n'a pas été réellement émis.

**Conséquence assumée**, déjà anticipée par le modèle de menaces (ligne R du tableau STRIDE) : un
crash entre le succès OpenBao et l'écriture de l'événement laisse une fenêtre de répudiation
résiduelle. Choix délibéré : « l'événement ne ment jamais sur l'existence du credential » plutôt
que l'inverse (un événement écrit avant l'appel laisserait une trace pour une émission qui n'a
peut-être pas eu lieu).

### Le risque Tampering du modèle de menaces est déjà fermé par H4

`security/threat-models/credential-issuer.md` : « si le `decision_hash` ne couvre pas un champ
pertinent (ex. le TTL...), une modification de ce champ passerait inaperçue — à vérifier
explicitement ». Confirmation, pas travail restant : le message signé `decision-seal/v1` (H4)
couvre `max_ttl`/`effect`/`reasons`/`constraints` directement, pas seulement `decision_hash` —
vérifié par les tests dédiés d'H4 (`effect_substitue_sous_un_decision_hash_valide_est_refuse`,
etc.).

### Mapping verbe → moteur OpenBao, minimal et explicite

Seul `db.connect` est instruit (seule politique réelle à ce jour, L2.1) : moteur PostgreSQL
dynamique, chemin `database/creds/{resource.id}`. Tout autre verbe → refus explicite
(`moteur_non_supporte:<verbe>`), jamais une tentative générique — cohérence directe avec le risque
EoP du modèle de menaces (traduction stricte, pas un mapping non instruit qui se déclencherait par
accident sur un futur verbe).

### `max_ttl` imposé par la décision vérifiée

Le TTL transmis à OpenBao (`IssueLease`) vient exclusivement de `DecisionResponse.max_ttl`, déjà
signé et vérifié via `VerifyDecision` — `EmissionOrder` n'a aucun champ permettant à l'appelant de
fournir une durée alternative. Vérifié par test
(`TestEmissionValideAppelleOpenBaoAvecLeTTLDeLaDecision`).

### Port `ConsumedDecisionStore`, sans implémentation — prévention de rejeu non assurée

Le modèle de menaces liste explicitement le rejeu d'un ordre d'émission (`decision_hash` déjà
consommé) comme scénario à couvrir. Sans stockage persistant (cohérent avec le scope-cut DB déjà
pratiqué en L1.1/L1.2/L1.4 — pas de câblage avant qu'un serveur en ait réellement besoin), la
prévention de rejeu **n'est pas implémentée** dans ce lot : interface documentée
(`ConsumedDecisionStore.MarkConsumed`, contrat d'atomicité explicite dans le commentaire), jamais
appelée par `Issuer.Emit`. **Un ordre rejoué serait aujourd'hui honoré une seconde fois** — gap
réel, signalé, pas silencieux.

### `credential.issued` construit, jamais scellé

Même gap que `policy.decided` en L2.3 : scellement réel exigerait un service Rust d'audit
symétrique à H3/H4, inexistant côté réseau accessible à ce composant Go. `Emit` retourne
`IssuedCredentialEvent` (portant `decision_hash`/`policy_version`/`reasons` partagés avec
`policy.decided`, comme le demande le backlog) pour qu'un futur appelant les scelle/les persiste.

### Nouvelle dépendance `github.com/google/uuid`

Génération de `event_id` (UUIDv7, R7). Justifiée (règle absolue #10) : licence BSD-3-Clause,
bibliothèque de référence de l'écosystème Go, aucune génération UUIDv7 n'existait encore nulle
part dans ce dépôt (Rust comme Go) — tous les UUIDv7 précédents étaient des littéraux de test.
**N'est pas une opération cryptographique au sens de la règle absolue #4** : la génération d'un
identifiant unique (composante aléatoire pour éviter les collisions) diffère d'une primitive de
sécurité (chiffrement, signature, dérivation de clé) — cohérent avec le traitement déjà réservé à
UUIDv7 côté `zs-crypto` (`common::EventId` ne fait que *valider* le format, jamais générer).

## Conséquences

**Positives** — `credential-issuer` authentifie réellement une décision avant tout appel à
OpenBao, comblant l'écart entre `docs/architecture.md` et l'implémentation que H4 avait ouvert.
Le mapping verbe→moteur explicite évite un mapping générique non testé. 13 tests réels (7 nouveaux
+ 6 hérités de H2), aucun réseau ni crypto fabriquée côté Go (contrainte structurelle : pas
d'exemption de test pour `check-no-direct-crypto.sh` côté Go).

**Négatives** — la prévention de rejeu n'est pas assurée (gap réel assumé). `credential.issued`
n'est pas scellé — comme `policy.decided`, un troisième service Rust d'audit (symétrique à
H3/H4) resterait à construire pour clore cette chaîne. Aucun serveur réseau : `credential-issuer`
reste inutilisable en dehors de tests unitaires jusqu'à ce qu'un contrat
`access-broker → credential-issuer` existe.

**Surface d'attaque** — un ordre d'émission rejoué serait honoré tant que
`ConsumedDecisionStore` n'a pas d'implémentation réelle branchée. mTLS toujours absent (même
limite que partout ailleurs dans ce lot).

## Critère de réexamen

Réexaminer dès qu'une implémentation réelle de `ConsumedDecisionStore` est nécessaire (première
mise en service au-delà du développement local) — la prévention de rejeu devient alors bloquante,
pas optionnelle. Réexaminer le mapping verbe→moteur à l'ajout d'une deuxième politique réelle
(PKI, SSH). Réexaminer l'absence de scellement de `credential.issued` à l'ouverture d'un service
Rust d'audit symétrique à H3/H4.
