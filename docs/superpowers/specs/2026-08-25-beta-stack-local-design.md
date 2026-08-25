# Beta opérationnelle — jalon 1/2 : stack local complet, une commande

**Statut** : design validé section par section avec le porteur du projet, prêt pour plan
d'implémentation.
**Date** : 2026-08-25
**Décideurs** : porteur du projet.

## Décomposition

« Rendre une beta opérationnelle » couvre deux sous-projets indépendants, à traiter dans l'ordre :

1. **Ce document** — stack complet fonctionnel en local, une commande (`make up`), aucune
   infrastructure externe.
2. **Différé, hors périmètre de ce document** — packaging pour un déploiement pilote accessible à
   un tiers (établissement public volontaire, cf. `docs/Proposition_Technique_Biscuits_IA.pdf`).
   Réutilisera les images construites ici, mais implique en plus de l'hébergement réel, des
   manifestes de déploiement (quadlets/OpenTofu), et potentiellement un HSM matériel.

## Contexte

État constaté avant ce jalon :

- **Code applicatif très avancé.** L0/L1/L2 du backlog : 91/94 cases cochées. Les 8 services
  (`identity-provider`, `policy-engine`, `access-broker`, `credential-issuer`,
  `audit-collector`, `audit-sealer`, `admin-api`, `console-web`) compilent, ont des tests, et se
  configurent déjà entièrement par variables d'environnement (12-factor) — vérifié service par
  service (`ZS_ACCESS_BROKER_POLICY_ENGINE_ADDR`, `ZS_CI_OPENBAO_ADDR`, `CONSOLE_WEB_ORIGIN`,
  etc.).
- **`deploy/compose.dev.yml` ne démarre que l'infrastructure** (`postgres`, `openbao`,
  `softhsm-init`, `otel-collector`). Aucun des 8 services applicatifs n'y tourne — `make up`
  prépare le terrain, ne démarre pas le produit.
- **Aucun Dockerfile n'existe** dans le dépôt.
- **Aucune intégration SPIFFE/SPIRE** (mTLS inter-composants) n'existe — les services se font
  confiance en clair sur le réseau Podman, documenté comme limite connue dans plusieurs en-têtes
  de fichiers (`apps/access-broker/main.go`, `apps/policy-engine/src/lib.rs`).
- **Aucun endpoint `/healthz`** n'existe dans aucun service.
- Le jeton root OpenBao (mode `-dev`) est aujourd'hui récupéré manuellement dans les logs — pas
  automatisable tel quel.

## Périmètre de ce jalon

**Dedans** : conteneuriser les 8 services, étendre `compose.dev.yml` pour que `make up` démarre
tout, automatiser la propagation du jeton OpenBao, ajouter un script de fumée e2e qui prouve que
le parcours JIT fonctionne de bout en bout sur la stack conteneurisée.

**Dehors, décision explicite** :
- **SPIFFE/SPIRE / mTLS** — le réseau Podman isolé est jugé suffisant pour ce jalon local ;
  chantier séparé, potentiellement propre au jalon pilote.
- **Endpoints `/healthz` applicatifs** — des healthchecks TCP suffisent à l'ordonnancement de
  démarrage ; ajouter de vrais endpoints de santé applicatifs est une amélioration ultérieure,
  pas un prérequis.
- Packaging pilote (sous-projet 2), charge/perf, résilience/chaos, multi-hôte.

## Décision : conteneuriser plutôt qu'automatiser le mode natif

Deux approches pesées :

1. **Conteneuriser les 8 services, tout dans `compose.dev.yml` — retenue.** Réutilisable telle
   quelle pour le jalon pilote (mêmes images pour les quadlets Podman visés par `CLAUDE.md`),
   aucun travail jetable. C'est aussi ce qu'un tiers qui audite le produit attend : un système qui
   démarre, pas un mode d'emploi à 8 terminaux.
2. **Automatiser le mode natif actuel** (script qui lance les 8 binaires en arrière-plan sur
   l'hôte). Rejetée : plus rapide à livrer, mais entièrement à refaire pour le jalon pilote, et
   plus fragile que Podman pour la gestion de process/logs/arrêt.

## Architecture de conteneurisation

**Base image** : `debian:bookworm-slim` pour tous les services — SoftHSM2 s'installe proprement
via `apt` (cohérent avec `.github/workflows/ci.yml`, qui installe déjà `protobuf-compiler` de
cette façon), évite les problèmes de liaison glibc qu'une base Alpine poserait pour les binaires
Rust.

**Build Rust** (`identity-provider`, `policy-engine`, `audit-sealer`) : **un seul** Dockerfile
multi-stage à la racine du workspace, paramétré par `ARG BINARY` — build `cargo build --release
-p <bin>` par cible. Un Dockerfile séparé par binaire reconstruirait trois fois le cache de
compilation des crates partagées (`zs-crypto`, `zs-hsm`, `zs-policy`, …).

**Build Go** (`access-broker`, `credential-issuer`, `audit-collector`, `admin-api`) : même
logique — un Dockerfile paramétré par `ARG BINARY`, build depuis la racine pour profiter du cache
de modules partagé (`go.work`).

**`console-web`** : Dockerfile Node standard (`npm ci && npm run build`), sert `dist/main.js`.

**Aucun code applicatif modifié** — tous les services lisent déjà leur configuration par
variables d'environnement ; packaging pur.

## Partage du HSM (SoftHSM2) entre conteneurs

`identity-provider`, `policy-engine`, `audit-sealer` ont besoin d'un accès PKCS#11. `softhsm-init`
initialise déjà un token dans le volume nommé `zero-secret-softhsm-tokens`
(`/var/lib/softhsm/tokens`) — pattern standard SoftHSM2 pour un token partagé entre plusieurs
processus.

Pour ces trois services :
- paquet `softhsm2` installé dans leur image (fournit `/usr/lib/softhsm/libsofthsm2.so`) ;
- **même volume nommé** `zero-secret-softhsm-tokens` monté sur `/var/lib/softhsm/tokens` ;
- `ZS_HSM_MODULE=/usr/lib/softhsm/libsofthsm2.so`, `SOFTHSM2_PIN` identique à celui généré par
  `softhsm-init` (propagé via `.env.dev`, voir plus bas) ;
- `depends_on: softhsm-init` avec `condition: service_completed_successfully`.

Aucun nouveau composant HSM — extension de l'usage du volume existant.

## Câblage `compose.dev.yml`

Tout par variables d'environnement déjà supportées (noms d'hôte = noms de service Podman) :

| Service | Écoute (dans le conteneur) | Dépend de |
|---|---|---|
| `postgres`, `openbao`, `softhsm-init`, `otel-collector` | *(existants, inchangés)* | — |
| **`migrate`** *(nouveau, one-shot)* | exécute `tools/migrate.sh`, puis quitte | `postgres` |
| `identity-provider` | gRPC `:50062`, HTTP `:50063` | `postgres`, `softhsm-init` |
| `policy-engine` | gRPC `:50061` — monte `contracts/cedar/` et `policies/access/` en lecture seule | `softhsm-init` |
| `audit-sealer` | socket Unix (volume partagé avec `audit-collector`) | `softhsm-init` |
| `audit-collector` | gRPC `:50065` — `ZS_AC_POSTGRES_DSN`, `ZS_AC_AUDIT_SEALER_SOCKET` | `postgres`, `audit-sealer`, `migrate` |
| `access-broker` | HTTP `:8081` — `ZS_ACCESS_BROKER_{POLICY_ENGINE,IDENTITY_PROVIDER,CREDENTIAL_ISSUER,AUDIT_COLLECTOR}_ADDR` | les 4 services visés |
| `credential-issuer` | `ZS_CI_OPENBAO_ADDR=http://openbao:8200`, `ZS_CI_OPENBAO_TOKEN` (via `.env.dev`) | `openbao`, `audit-collector` |
| `admin-api` | HTTP `:8082` — `ZS_ADMIN_API_{IDENTITY_PROVIDER,AUDIT_COLLECTOR}_ADDR` | `postgres`, `migrate` |
| `console-web` | `:3000` — `CONSOLE_WEB_{ORIGIN,IDENTITY_PROVIDER_URL,ACCESS_BROKER_URL,ADMIN_API_URL}` | `identity-provider`, `access-broker`, `admin-api` |

**Healthchecks** : TCP (`nc -z`) sur le port d'écoute de chaque service — pas de nouvel endpoint
applicatif, suffisant pour `depends_on: condition: service_healthy`.

## Jeton OpenBao : propagation automatique

OpenBao (`-dev`) génère un jeton root aléatoire, affiché seulement dans ses logs — aujourd'hui une
étape manuelle. Pas question de le figer en dur dans le compose (règle absolue #1, déjà la
décision documentée dans le fichier existant).

**Solution, sans toucher au code applicatif** : étendre la cible `make up` du `Makefile` pour,
une fois `openbao` en bonne santé, extraire le jeton via `podman logs` et l'écrire dans
`.env.dev` — réutilise le mécanisme déjà en place (`tools/migrate.sh` y écrit déjà les mots de
passe PostgreSQL générés ; fichier gitignored, jamais redemandé). Les conteneurs applicatifs
démarrent ensuite avec `--env-file .env.dev`.

## Gestion des erreurs et démarrage

- `restart: "no"` sur tous les nouveaux services — un service qui ne démarre pas reste
  visiblement en échec (`podman-compose ps`), jamais de boucle de redémarrage qui masquerait le
  problème. Cohérent avec le principe « refus par défaut » du projet.
- Les chaînes `depends_on` (`service_healthy` / `service_completed_successfully`) garantissent
  qu'un échec de migration ou de `softhsm-init` bloque tout le reste sans état intermédiaire
  ambigu.

## Validation

**Automatisé** — nouveau `tests/e2e/full_stack_smoke.sh` (même famille que
`tests/e2e/audit_writer_refuses_delete.sh`) :
1. `make up` (stack complet) → tous les services `healthy`.
2. Appel direct à `policy-engine` (gRPC) avec une requête db-connect nominale du corpus existant
   (`policies/tests/db_connect/cases.json`) → décision `ALLOW` motivée.
3. Parcours JIT complet via `access-broker` (HTTP) → credential éphémère réellement émis par
   `credential-issuer`/OpenBao.
4. Vérification que `audit-collector` a enregistré et chaîné les événements correspondants
   (`policy.decided`, `credential.issued`).

Ne re-teste pas la cérémonie WebAuthn elle-même (déjà couverte par les tests unitaires/
intégration d'`identity-provider`) — ce script valide le câblage, pas la cryptographie déjà
prouvée ailleurs.

**Manuel, une fois, pour le sign-off** : ouverture de `http://localhost:3000` dans un navigateur,
enregistrement d'un authentificateur réel, demande d'accès de bout en bout. Seule étape qui
prouve l'expérience utilisateur, pas seulement l'API.

## Fichiers touchés (aperçu, détaillé dans le plan d'implémentation)

- `deploy/docker/rust.Dockerfile`, `deploy/docker/go.Dockerfile`, `apps/console-web/Dockerfile`
  *(nouveaux)*
- `deploy/compose.dev.yml` *(étendu — 8 services + `migrate`)*
- `Makefile` *(cible `up` étendue : propagation du jeton OpenBao)*
- `tests/e2e/full_stack_smoke.sh` *(nouveau)*
- Aucun fichier de code applicatif (`apps/*/src`, `apps/*/internal`) modifié.

## Définition de « fait »

- `make up` démarre les 8 services applicatifs + l'infrastructure, tous `healthy`, une seule
  commande, sans étape manuelle.
- `tests/e2e/full_stack_smoke.sh` passe.
- Le sign-off manuel (parcours WebAuthn réel dans un navigateur) est réalisé et confirmé.

## Hors périmètre de ce jalon (rappel)

SPIFFE/SPIRE, endpoints `/healthz` applicatifs, packaging pilote, charge/perf, résilience/chaos,
multi-hôte.
