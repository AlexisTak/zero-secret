# Suite de tests de pénétration automatisés — Phase 1

**Date** : 2026-08-25
**Statut** : approuvé (brainstorming), en cours d'implémentation
**Origine** : `penthtest.md` (mission red team) confronté à l'état réel du dépôt et à `audit.md`
(audit précédent, révision `1ef11dd`).

## Contexte

`penthtest.md` demande une suite de tests de pénétration automatisés couvrant 16 catégories
(auth, autorisation, API, injection, SSRF, uploads, rate-limit, IA, RAG, fuzzing, business logic,
secrets, régression, rapport, exécution locale, CI/CD). Une reconnaissance du dépôt a confronté
cette liste à la surface d'attaque réelle avant d'écrire le moindre test, conformément à la règle
19 de `penthtest.md` (« si une fonctionnalité n'existe pas, ne crée pas artificiellement un test
pour celle-ci »).

### Surface d'attaque confirmée

| Catégorie `penthtest.md` | Verdict | Preuve |
|---|---|---|
| Authentification | **Applicable** | Ceremony WebAuthn (`identity-provider`), session console-web |
| Autorisation | **Applicable** | `admin-api` quorum sans authn appelant (ADR-021, non testé) |
| API (fuzz structurel) | **Applicable** | 4 apps HTTP + 3 surfaces gRPC |
| Injection | **Applicable, confirmatoire** | SQL entièrement paramétrée (`audit-collector/internal/store/store.go:49,95` — `$1`…`$12`), aucune concaténation trouvée. Pas d'exploit attendu, tests de non-régression. |
| SSRF | **Hors périmètre** | Aucune URL sortante dérivée d'une entrée utilisateur (tous les clients gRPC/HTTP sortants utilisent des adresses `envOr(...)` fixes) |
| Uploads | **Hors périmètre** | Aucun `multipart`/`FormFile` dans `apps/`. Seuls des champs JSON base64 de taille fixe (attestation WebAuthn, assertions scellées) |
| Rate limiting | **Applicable — absent** | Zéro occurrence de `ratelimit`/`Limiter`/`throttle` dans `apps/` et `pkg/` |
| IA / RAG | **Hors périmètre** | Aucun LLM, agent, RAG ou vector store dans le dépôt |
| Fuzzing | **Applicable** | Décodeurs JSON de chaque handler, cible `go test -fuzz` |
| Business logic | **Applicable** | Rejeu d'assertion scellée, falsification TTL/decision_hash |
| Race conditions | **Applicable, partiellement en process** | Store de challenge WebAuthn testable sans `make up` |
| Secrets / dépendances | **Déjà couvert** | `make audit` (cargo-audit, cargo-deny, govulncheck, gitleaks) en CI (`dependency-analysis`) — pas de doublon |
| Régression | **Déjà corrigé** | `audit.md` §3.1 : panic réseau — corrigé depuis l'audit (`apps/policy-engine/src/lib.rs:124-132`), test `decision_fields_refuse_annee_hors_plage_au_lieu_de_paniquer` déjà présent et vert. Vérifié par exécution le 2026-08-25. Rien à faire. |

### Contrainte d'environnement

Le dépôt est développé pour Linux/Podman (`make up` appelle `podman-compose`, non disponible
nativement sous Windows/PowerShell sans WSL). La Phase 1 est donc conçue pour s'exécuter
entièrement **sans `make up`** : tests au niveau handler, contre le vrai code de production avec
des fakes maison (convention déjà en place dans `apps/*/internal/httpapi/handler_test.go` — pas de
`testify`, pas de framework de mock). La Phase 2 (charge réelle, race conditions cross-process,
business logic bout-en-bout) nécessite l'environnement complet et n'est pas exécutée dans cette
itération.

## Décisions actées

1. **Tiers d'exécution** : `security:quick` = handler-level uniquement, exécutable en CI sans
   infrastructure. `security:full`/`security:load` = squelette Phase 2, documenté, nécessite
   `make up`, exécution manuelle.
2. **Bug `policy-engine` (audit.md §3.1)** : **déjà corrigé et testé** dans le dépôt (constaté le
   2026-08-25, après la date de l'audit) — `apps/policy-engine/src/lib.rs:124-132` traduit déjà
   l'échec en `valid: false`, et `decision_fields_refuse_annee_hors_plage_au_lieu_de_paniquer`
   (`lib.rs:278-292`) passe (`cargo test -p policy-engine --lib`). Aucune tâche d'implémentation :
   uniquement noté dans le rapport final comme finding déjà clos, avec preuve d'exécution.
3. **Découpage** : Phase 1 = ce qui est réellement testable sans base de données ni HSM (Go via
   fakes, TypeScript via `createApp`, Rust au niveau fonction pure) + rapport + CI `security:quick`.
   Phase 2 = tout ce qui exige Postgres et/ou SoftHSM2 (`make up`), documenté comme backlog précis,
   pas comme code non vérifiable.

### Contrainte redécouverte en lisant le code : visibilité `internal/` de Go

Chaque app Go (`access-broker`, `admin-api`, `audit-collector`, `credential-issuer`) est son
**propre module** (`go.mod` séparé, cf. `go.work`), et sa logique HTTP/gRPC vit sous un chemin
`.../internal/...`. La règle de visibilité `internal` de Go s'applique par préfixe de chemin
d'import : un module externe comme un `tests/security` autonome ne peut **pas** importer
`apps/admin-api/internal/httpapi` — seul du code sous `apps/admin-api/...` le peut. Un module Go
transverse tel qu'initialement esquissé ne compilerait pas. **Correction** : les tests Go vivent
co-localisés dans le module de l'app qu'ils testent (mêmes fichiers `_test.go`, même package que
`handler_test.go` existant), pas dans un module séparé. `tests/security/` ne contient que ce qui
n'a pas besoin d'importer un `internal/` d'app : documentation, scripts shell statiques, et
l'agrégateur de rapport (qui ne lit que des fichiers JSON déjà écrits par chaque app, aucun import
Go croisé).

### Contrainte redécouverte : identity-provider (Rust) dépend d'un Postgres et d'un HSM réels

`IdentityStore`/`AuditStore` (`apps/identity-provider/src/store.rs:17-19`) enveloppent un
`sqlx::PgPool` concret — pas de trait, pas de mock possible sans base réelle. `AssertionSealer`/
`AuditSealer` scellent via HSM (même famille que `DecisionSealer` de `policy-engine`, qui exige
SoftHSM2 dans `decide_integration.rs`). Aucun test d'intégration HTTP de bout en bout sur
`identity-provider` n'est donc exécutable sans `make up` — cohérent avec l'état actuel du dépôt :
les seuls tests déjà présents dans `httpapi.rs` sont des tests de fonctions pures
(`b64_decode`, `presented_challenge_bytes`, `hex_encode`), jamais des handlers complets. Phase 1
étend ces tests purs ; le bypass de cérémonie, le rejeu de challenge et la race condition sur
`consume_challenge` (qui *seraient* le cœur naturel des catégories auth/race-conditions) passent
en Phase 2, documentés en backlog précis dans `tests/security/README.md` (fichier:ligne exacts),
pas en code Rust non exécutable/non vérifié dans cette itération.

**Conséquence sur race-conditions/** : sans cette cible, il n'existe aucun état interne à usage
unique dans les apps Go testables sans base (`admin-api`/`access-broker` ne consomment aucun jeton
à usage unique en mémoire). La catégorie race-conditions passe donc **entièrement en Phase 2**.

## Architecture

```
tests/security/                         pas de module Go — uniquement doc + scripts + agrégateur
  README.md                             périmètre, catégories exclues et pourquoi, backlog Phase 2
  report/
    aggregate/                          petit module Go autonome (aucun import internal/) qui lit
                                         les JSON écrits par chaque app et rend un résumé Markdown
    output/                             gitignored — écrit par les tests de chaque app au run
  infrastructure/
    check_compose_dev.sh                contrôle statique deploy/compose.dev.yml (pas d'import Go)
  dependencies/
    README.md                           pointe vers `make audit`, aucun code dupliqué

apps/access-broker/internal/httpapi/security_report_test.go     Finding + writer JSON (dupliqué, justifié)
apps/access-broker/internal/httpapi/security_business_logic_test.go
apps/access-broker/internal/httpapi/security_api_test.go
apps/access-broker/internal/httpapi/fuzz_test.go

apps/admin-api/internal/httpapi/security_report_test.go         Finding + writer JSON (dupliqué, justifié)
apps/admin-api/internal/httpapi/security_authorization_test.go
apps/admin-api/internal/httpapi/security_api_test.go
apps/admin-api/internal/httpapi/security_rate_limit_test.go
apps/admin-api/internal/httpapi/fuzz_test.go

apps/audit-collector/internal/collector/security_report_test.go Finding + writer JSON (dupliqué, justifié)
apps/audit-collector/internal/collector/security_injection_test.go

apps/console-web/src/security.test.ts        CSRF + session-gating (createApp + fakes, node:test)

apps/identity-provider/src/httpapi.rs        étend #[cfg(test)] mod tests existant (fonctions pures)
```

**Duplication du `Finding`/writer par module** : justifiée par le même principe déjà appliqué dans
ce dépôt (`rfc3339_from_seconds` dupliqué entre `identity-provider`/`policy-engine`, `hex_decode`
dupliqué ailleurs — règle absolue #10 : pas de nouvelle dépendance partagée sans justification).
Créer un module `pkg/zssecurity` pour ~25 lignes de struct + `json.Marshal` demanderait de modifier
le `go.mod` de 3 apps de production pour un besoin strictement limité aux tests — non retenu.

**Pas de dossiers `ssrf/`, `uploads/`, `ai/`, `rag/`** — aucune surface réelle. Documenté dans
`tests/security/README.md` pour éviter qu'ils soient rajoutés en aveugle plus tard, avec pointeur
vers ce document si la surface change (ex. un futur upload de document).

## Composants

### `security_report_test.go` (dupliqué dans chaque module Go)
Fichier de test (jamais compilé dans le binaire de production) définissant `Finding` et une
fonction d'écriture JSON, identique dans les trois modules :
```go
type Finding struct {
    ID           string
    Category     string   // auth, authorization, api, injection, business-logic, rate-limit, race-conditions, information-disclosure
    Severity     string   // CRITICAL, HIGH, MEDIUM, LOW, INFO
    Component    string   // endpoint ou composant
    Description  string
    Payload      string
    Expected     string
    Obtained     string
    Evidence     string   // fichier:ligne ou extrait de réponse
    Remediation  string
    OWASP        []string // ex. "API1:2023 BOLA", "A01:2021"
    CWE          string
    Blocking     bool     // false pour les gaps connus/acceptés (ex. absence de rate-limit)
}
```
Écrit un run complet en JSON (`tests/security/report/output/<module>.json`, gitignored) et
l'agrégateur (`tests/security/report/aggregate/`) les fusionne en un résumé Markdown lisible.
Chaque test de vulnérabilité réelle échoue normalement (`t.Fatalf`) *et* enregistre son `Finding`.
Un gap déjà connu et accepté (absence de rate-limit, gRPC sans mTLS — tous deux déjà documentés
dans l'architecture/l'audit comme limites assumées) est enregistré avec `Blocking: false` et ne
fait pas échouer le test — il est journalisé, pas masqué.

### Catégories — ce que chacune teste concrètement, et où

- **authorization/** (Phase 1, `apps/admin-api/internal/httpapi/security_authorization_test.go`) :
  `POST /v1/critical-operations/{id}/quorum` s'exécute alors qu'aucune vérification ne prouve que
  l'appelant a le droit de déclencher *cette* opération (ADR-021, `handler.go:5-8`) — deux porteurs
  quelconques, non liés à l'opération, suffisent. Test de régression HIGH, volontairement en échec
  au premier run (documente le gap réel, ne le masque pas).
- **business-logic/** (Phase 1, `apps/access-broker/internal/httpapi/security_business_logic_test.go`) :
  une assertion scellée pour `authority_domain` A ne doit jamais être acceptée par `access-broker`
  sur une requête ciblant `authority_domain` B (`ExpectedAuthorityDomain` doit être vérifié par
  `VerifyAssertion`, pas seulement transmis, `handler.go:52-55`) ; un champ `decision_hash` ou
  `max_ttl` ajouté par le client dans le corps `AccessRequestBody` (mass assignment) doit être
  silencieusement ignoré — la réponse `Decision` ne reflète que ce que `policy-engine` a signé
  (`decision.Signed`), jamais une valeur soumise par l'appelant. Note : la réutilisation d'une
  assertion valide sur plusieurs requêtes *dans sa fenêtre de validité* est un comportement voulu
  (credential éphémère à durée bornée, pas à usage unique) — testé comme cas nominal, pas comme
  vulnérabilité.
- **api/** (Phase 1, `security_api_test.go` dans `access-broker` et `admin-api`) : matrice par
  endpoint (méthode incorrecte, champ manquant, champ en trop, type incorrect, null, chaîne très
  longue, nombre négatif/énorme, JSON malformé, tableau énorme, paramètres dupliqués, Content-Type
  incorrect) — assertion qu'aucune requête ne provoque de panique et qu'aucune réponse d'erreur ne
  contient stack trace, chemin filesystem ou fragment de secret (fusionne la catégorie
  information-disclosure de `penthtest.md`).
- **injection/** (Phase 1, `apps/audit-collector/internal/collector/security_injection_test.go`) :
  payloads SQL classiques et encodés injectés dans les champs qui atteignent
  `collector.Collector.Record` (`authority_domain`, champs d'événement) via un `store.Store` faux
  qui capture les valeurs reçues — confirme qu'elles restent des paramètres opaques et n'atteignent
  jamais une construction de requête, sans avoir besoin du vrai Postgres (les requêtes réelles de
  `internal/store/store.go:49,95` sont déjà paramétrées `$1`…`$12`).
- **rate-limit/** (Phase 1, `apps/admin-api/internal/httpapi/security_rate_limit_test.go`) : rafale
  de requêtes vers `POST /v1/critical-operations/{id}/quorum` (pas d'authn appelant, cf.
  authorization/) — constat documenté (`Finding` MEDIUM, `Blocking: false`) de l'absence de
  limitation, pas un test bloquant en Phase 1.
- **fuzzing/** (Phase 1 pour le corpus de base, `make security-fuzz` pour le fuzzing natif) :
  `fuzz_test.go` dans `access-broker` et `admin-api`, décodeurs JSON des handlers, seed fixe.
- **auth/console-web** (Phase 1, `apps/console-web/src/security.test.ts`) : accès aux routes
  protégées (`/access-request`, `/quorum`) sans cookie de session → redirection `/login`
  (`server.ts:234-240`) ; contournement CSRF par flip d'`Origin`/`Sec-Fetch-Site` sur un POST
  (`server.ts:42,118-126`) — doit rester `403`.
- **auth/identity-provider** (Phase 1 partielle, étend `#[cfg(test)] mod tests` de `httpapi.rs`) :
  tampering sur `presented_challenge_bytes` (champ `challenge` de type incorrect, JSON avec champs
  supplémentaires), stricte non-permissivité de `b64_decode` (padding standard, alphabet standard,
  espaces). Le bypass de cérémonie complet, le rejeu de challenge consommé et la race condition sur
  `consume_challenge` exigent Postgres + HSM réels (§ contrainte ci-dessus) — **Phase 2**, documentés
  en backlog précis dans `tests/security/README.md` (fonction et ligne exactes de `httpapi.rs` et
  `store.rs` à cibler), pas en code non exécutable ici.
- **race-conditions/** : **entièrement Phase 2** (aucune cible testable sans base — voir
  contrainte ci-dessus). Backlog : `consume_challenge` (`store.rs`) appelé deux fois concurremment
  avec le même challenge, un seul doit réussir.
- **dependencies/** (`tests/security/dependencies/README.md`) : renvoie vers `make audit` (déjà en
  CI, job `dependency-analysis`) — aucun code dupliqué.
- **infrastructure/** (`tests/security/infrastructure/check_compose_dev.sh`) : contrôle statique de
  `deploy/compose.dev.yml` (pas de bind non-loopback, pas de conteneur privilégié hors
  `softhsm-init` déjà justifié par ADR).

### Régression `policy-engine` (audit.md §3.1) — déjà close

Constatée close le 2026-08-25 : `apps/policy-engine/src/lib.rs:124-132` traduit déjà l'échec de
`decision_fields` en `VerifyDecisionResponse { valid: false, reason: "issued_at_invalide" }`, et
`decision_fields_refuse_annee_hors_plage_au_lieu_de_paniquer` (`lib.rs:278-292`) reproduit
`i64::MAX`/`i64::MIN` et passe (`cargo test -p policy-engine --lib` → `ok`). Aucune tâche
d'implémentation ; simplement noté dans le rapport final avec preuve d'exécution.

## CI / Makefile

Nouvelles cibles, à la suite des cibles existantes. Réutilise `go-each` (macro déjà définie dans
le `Makefile`, itère sur les modules Go de `go.work`) plutôt que de dupliquer la boucle :
```
security-quick: ## Tests de sécurité handler-level + fonctions pures — CI, rapide, pas d'infra requise
	$(call go-each,go test ./... -race -run 'TestSecurity|TestFuzz')
	cargo test -p identity-provider --lib
	cd apps/console-web && npm run build && node --test "dist/**/security.test.js"
	bash tests/security/infrastructure/check_compose_dev.sh
	@cd tests/security/report/aggregate && go run . ../output

security-full: ## Suite complète contre l'environnement local — make up requis
	@echo "Phase 2 — nécessite make up (Postgres + SoftHSM2), voir tests/security/README.md"

security-fuzz: ## Fuzzing natif Go des décodeurs JSON, budget borné
	$(call go-each,go test ./... -fuzz=FuzzDecode -fuzztime=60s)
```
Les tests de sécurité sont nommés `TestSecurity*`/`FuzzDecode*` par convention (préfixe explicite)
pour que `-run 'TestSecurity|TestFuzz'` les sélectionne sans toucher aux tests fonctionnels
existants du même module lors d'une exécution CI ciblée.

`security-quick` ajouté comme job CI dans `.github/workflows/ci.yml`, parallèle à
`dependency-analysis`, `needs: [build-test]` — même runner, mêmes toolchains déjà installés,
aucune infrastructure supplémentaire (pas de Postgres/HSM requis pour ce tier).

Pas de cible `security:ai` : aucune fonctionnalité IA dans le dépôt (règle 19 de `penthtest.md`).

## Rapport final attendu (fin de l'implémentation)

Conformément à la section 20 de `penthtest.md` :
1. Surfaces d'attaque découvertes (tableau ci-dessus).
2. Tests créés, par catégorie.
3. Tests exécutables immédiatement (Phase 1) vs nécessitant configuration (Phase 2, `make up`).
4. Vulnérabilités découvertes avec sévérité et preuve (`Finding` produits par le run).
5. Recommandations de correction (déjà appliquées pour le panic `policy-engine`, documentées pour
   le reste).
6. Tests impossibles à automatiser à ce stade (ex. compromission de l'IdP — limite structurelle
   assumée par `docs/architecture.md`).
7. Prochaines étapes pour un pentest manuel (mTLS gRPC absent, charge réelle, race conditions
   cross-process).
