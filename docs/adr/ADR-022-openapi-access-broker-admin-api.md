# ADR-022 — Première entrée HTTP réelle (`access-broker`, `admin-api`, `contracts/openapi/`)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique

## Contexte

`access-broker` (L2.3, ADR-017) et `admin-api` (L2.5, ADR-021) sont restées des bibliothèques
Go sans entrée réseau, faute de contrat : `main.go` était un stub dans les deux cas.
`contracts/README.md` et `docs/architecture.md` annoncent `contracts/openapi/` (OpenAPI 3.1)
depuis L0.1, mais le dossier n'existait pas — aucun outillage de génération Go pour OpenAPI dans
ce dépôt (contrairement à `buf`/protoc pour les contrats proto entre Rust et Go).

`security/threat-models/access-broker.md` documente déjà l'entrée non fiable attendue
(« Requête d'accès... Utilisateur authentifié, HTTP... Validation de schéma OpenAPI ») mais
présuppose une identité déjà prouvée, sans préciser comment elle voyage jusqu'à HTTP.

## Décisions

### Authentification par assertion `identity-assertion/v1` en en-tête, jamais un champ du corps

Le demandeur transmet son assertion (H3) dans l'en-tête `X-Identity-Assertion` (base64) ;
`access-broker` la vérifie via `identity.v1.AssertionVerificationServiceClient.VerifyAssertion`
avant toute construction de `broker.AccessRequest` — pas de nouveau mécanisme de session/jeton
inventé, même primitive que celle déjà utilisée pour les approbations (L2.3) et le quorum (L2.5).
Le champ `Principal` de la requête interne est peuplé **uniquement** depuis la réponse vérifiée
(`subject_id`, `aal`, `auth_method`), jamais depuis un champ équivalent du corps JSON — un tel
champ serait un contournement trivial de l'authentification si le corps JSON en portait un.
Refus HTTP 401 si l'assertion est absente ou invalide, avant tout appel au PDP.

### Aucune collecte incrémentale d'approbations/quorum

Chaque endpoint est synchrone et à un seul appel : le corps porte déjà toutes les assertions
réunies hors bande (approbations pour `access-broker`, porteurs pour `admin-api`). Une collecte
asynchrone réelle (porteur 1 approuve maintenant, porteur 2 plus tard) exigerait un magasin
d'état persistant — hors périmètre, même famille de coupe de portée que `ConsumedDecisionStore`
(L2.4).

### `oapi-codegen` (`github.com/oapi-codegen/oapi-codegen/v2`, Apache-2.0)

Outil de référence de l'écosystème Go pour OpenAPI 3, actif, licence permissive. Génère les
types et l'interface serveur (`std-http-server`) depuis le YAML — jamais écrits à la main,
cohérent avec l'invariant « `contracts/` source de vérité ». Choix explicite de
`std-http-server` plutôt qu'un adaptateur chi/gin/echo : aucune bibliothèque de routage
n'existe ailleurs dans ce dépôt Go, en ajouter une seule pour deux endpoints aurait été une
dépendance non justifiée. Sortie générée **dans chaque app**
(`apps/<app>/internal/httpapi/api_generated.go`), pas dans `pkg/gen` : contrairement aux types
proto partagés Rust+Go, ces types HTTP ne servent qu'à l'app Go qui les héberge. Fichiers
générés committés (même convention que `pkg/gen/`), régénérés par
`tools/generate-openapi.sh`, câblé dans `make generate` et couvert par l'extension du
détecteur `generated-up-to-date` (`tools/check-arch.sh`).

### Un seul endpoint par service, minimal

- `access-broker` : `POST /v1/access-requests` — construit un `broker.AccessRequest`
  (principal vérifié via l'en-tête, approbations du corps vérifiées comme aujourd'hui), appelle
  `Broker.Decide`, retourne la `Decision`.
- `admin-api` : `POST /v1/critical-operations/{operation_id}/quorum` — corps : liste
  d'assertions et seuil ; appelle `quorum.VerifyQuorum`, retourne le résultat.
  `operation_id` (chemin d'URL) n'est **pas** transmis à `VerifyQuorum` : le vérificateur reste
  délibérément agnostique de l'opération protégée (ADR-021, angle mort hérité du modèle de
  menaces) — `operation_id` n'est qu'une valeur de corrélation pour un futur appelant/journal,
  pas encore exploitée.

### Panique de `quorum.VerifyQuorum` récupérée en HTTP 400, jamais un crash

`VerifyQuorum` panique par construction (ADR-021) si `threshold < MinimumThreshold` — une
erreur de configuration de l'appelant, acceptable pour un appelant interne de confiance. Une
requête HTTP est non fiable : un `recover()` explicite (`verifyQuorumRecovered`) convertit
cette panique en réponse 400, jamais en crash du processus.

### Pas de TLS/mTLS dans ce lot

`http.ListenAndServe` en clair, gRPC client en clair (`insecure.NewCredentials()`) vers
`policy-engine`/`identity-provider` — même limite que partout ailleurs dans ce dépôt
(L2.2/H3/H4), signalée explicitement en commentaire dans chaque `main.go`. mTLS/SPIFFE reste
hors périmètre, aucune intégration SPIRE n'existe encore dans ce dépôt.

## Conséquences

**Positives** — `access-broker` et `admin-api` ont enfin une entrée réseau réelle, testée en
process via `net/http/httptest` avec de vrais appels HTTP (pas de simulation de requête).
L'authentification du demandeur réutilise une primitive déjà auditée (H3) sans inventer de
nouveau mécanisme. Aucune ligne ajoutée à `zs-crypto`, aucune nouvelle entrée CBOM.

**Négatives** — pas de collecte incrémentale d'approbations : un déploiement réel nécessitera un
magasin d'état persistant pour les workflows d'approbation asynchrones, non traité ici. Pas de
TLS : ce lot n'est pas déployable tel quel en production.

**Surface d'attaque** — nouvelle : deux endpoints HTTP non authentifiés au niveau transport
(pas de TLS) exposés sur le réseau. Le risque le plus direct — un appelant qui fournirait un
`Principal` forgé — est explicitement neutralisé par construction (le principal ne vient jamais
du corps JSON). Le risque de panique non récupérée sur `admin-api` est neutralisé par
`verifyQuorumRecovered`, testé (`TestSeuilInferieurAuPlancherEstRefuse400ParHTTPPasUnCrash`).

## Critère de réexamen

Réexaminer dès que L2.6 (console-web) a besoin d'une collecte incrémentale d'approbations —
introduira alors un magasin d'état persistant et probablement plusieurs appels par flux au lieu
d'un seul. Réexaminer le TLS/mTLS dès que SPIFFE/SPIRE est câblé dans ce dépôt (hors périmètre
de tout lot livré jusqu'ici).
