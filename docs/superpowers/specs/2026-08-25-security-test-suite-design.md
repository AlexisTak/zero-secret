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
3. **Découpage** : Phase 1 = scaffold + auth + authorization + api + injection (confirmatoire) +
   business-logic (partie testable en process) + race-conditions (partie testable en process) +
   rate-limit (constat documenté, non bloquant) + régression + rapport + CI `security:quick`.
   Phase 2 = tout ce qui nécessite `make up`.

## Architecture

```
tests/security/                         nouveau module Go (go.mod propre)
  go.mod                                ajouté à go.work (`use ./tests/security`)
  README.md                             périmètre, catégories exclues et pourquoi, comment lancer
  harness/                              wiring handler+fakes réutilisable, assertions communes
  report/                               struct Finding, writer JSON + Markdown
  auth/
  authorization/
  api/
  injection/
  business-logic/
  race-conditions/
  rate-limit/
  fuzzing/
  information-disclosure/
  dependencies/                         README pointant vers `make audit`, pas de code
  infrastructure/

apps/policy-engine/tests/security_regression.rs   régression du panic §3.1, avec le code Rust qu'elle teste
```

**Choix de placement** : le module Go vit sous `tests/security/` (tests transverses, conforme à
`tests/README.md`). La régression Rust vit dans `apps/policy-engine/tests/` — convention du dépôt
(« les tests unitaires vivent avec le code qu'ils testent »), pas dans le module Go transverse.

**Pas de dossiers `ssrf/`, `uploads/`, `ai/`, `rag/`** — aucune surface réelle. Documenté dans
`tests/security/README.md` pour éviter qu'ils soient rajoutés en aveugle plus tard, avec pointeur
vers ce document si la surface change (ex. un futur upload de document).

## Composants

### `harness/`
Fonctions utilitaires partagées : construction d'un handler réel avec ses dépendances remplacées
par des fakes (même pattern que `handler_test.go` existants), assertions communes (pas de panique,
pas de fuite de stack trace/chemin dans le corps de réponse, code HTTP attendu).

### `report/`
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
Écrit un run complet en JSON (`tests/security/report/output/<timestamp>.json`, gitignored) et un
résumé Markdown lisible. Chaque test de vulnérabilité réelle échoue normalement (`t.Fatalf`) *et*
enregistre son `Finding`. Un gap déjà connu et accepté (absence de rate-limit, gRPC sans mTLS —
tous deux déjà documentés dans l'architecture/l'audit comme limites assumées) est enregistré avec
`Blocking: false` et ne fait pas échouer le test — il est journalisé, pas masqué.

### Catégories — ce que chacune teste concrètement

- **auth/** : bypass de la ceremony WebAuthn (verify sans challenge préalable), rejeu de challenge
  consommé, altération de l'origine dans `client_data_json`, accès aux routes protégées de
  `console-web` (`/access-request`, `/quorum`) sans cookie de session, contournement CSRF (flip de
  `Origin`/`Sec-Fetch-Site`). L'absence d'authn transport gRPC (`identity-provider`,
  `credential-issuer`) est enregistrée en `Finding` INFO, non bloquante — limitation architecturale
  déjà documentée (mTLS/SPIFFE prévu mais non câblé), hors périmètre de correction ici.
- **authorization/** : `POST /v1/critical-operations/{id}/quorum` exécuté par un appelant qui ne
  prouve aucune habilitation à déclencher *cette* opération (ADR-021) — test de régression HIGH,
  volontairement en échec au premier run (documente le gap réel, ne le masque pas).
  `registration/challenge` acceptant un `subject_id` arbitraire — test confirmant l'énumération
  possible.
- **api/** : matrice par endpoint (méthode incorrecte, champ manquant, champ en trop, type
  incorrect, null, chaîne très longue, nombre négatif/énorme, JSON malformé, tableau énorme,
  paramètres dupliqués, Content-Type incorrect) — assertion qu'aucune requête ne provoque de
  panique et qu'aucune réponse d'erreur ne contient stack trace, chemin filesystem ou fragment de
  secret (fusionne la catégorie information-disclosure de `penthtest.md`).
- **injection/** : payloads SQL classiques et encodés injectés dans les champs qui atteignent
  `audit-collector` (`authority_domain`, champs d'événement) et dans le contexte évalué par
  `policy-engine`/Cedar — confirme le paramétrage plutôt que de chercher un exploit inexistant.
- **business-logic/** : une assertion scellée pour `authority_domain` A ne doit jamais être
  acceptée par `access-broker` sur une requête ciblant `authority_domain` B (`ExpectedAuthorityDomain`
  doit être vérifié par `VerifyAssertion`, pas seulement transmis) ; un champ `decision_hash` ou
  `max_ttl` ajouté par le client dans le corps `AccessRequestBody` (mass assignment) doit être
  silencieusement ignoré — la réponse `Decision` ne doit refléter que ce que `policy-engine` a
  signé (`decision.Signed`), jamais une valeur soumise par l'appelant. Note : la réutilisation d'une
  assertion valide sur plusieurs requêtes *dans sa fenêtre de validité* est un comportement voulu
  (credential éphémère à durée bornée, pas à usage unique) — testé comme cas nominal, pas comme
  vulnérabilité.
- **race-conditions/** : deux goroutines consomment concurremment le même challenge WebAuthn — un
  seul doit réussir (testable en process, store réel, sans `make up`).
- **rate-limit/** : rafale de requêtes vers un endpoint non authentifié
  (`registration/challenge`) — constat documenté (`Finding` MEDIUM, `Blocking: false`) de
  l'absence de limitation, pas un test bloquant en Phase 1.
- **fuzzing/** : `go test -fuzz` natif par décodeur JSON, seed fixe, corpus borné, cible
  `make security-fuzz` séparée (pas dans `security-quick`).
- **dependencies/** : `README.md` renvoyant vers `make audit` (déjà en CI, job
  `dependency-analysis`) — aucun code dupliqué.
- **infrastructure/** : contrôles statiques sur `deploy/compose.dev.yml` (pas de bind non-loopback,
  pas de conteneur privilégié hors `softhsm-init` déjà justifié).

### Régression `policy-engine` (audit.md §3.1) — déjà close

Constatée close le 2026-08-25 : `apps/policy-engine/src/lib.rs:124-132` traduit déjà l'échec de
`decision_fields` en `VerifyDecisionResponse { valid: false, reason: "issued_at_invalide" }`, et
`decision_fields_refuse_annee_hors_plage_au_lieu_de_paniquer` (`lib.rs:278-292`) reproduit
`i64::MAX`/`i64::MIN` et passe (`cargo test -p policy-engine --lib` → `ok`). Aucune tâche
d'implémentation ; simplement noté dans le rapport final avec preuve d'exécution.

## CI / Makefile

Nouvelles cibles, à la suite des cibles existantes :
```
security-quick: ## Tests de sécurité handler-level — CI, rapide, pas d'infra requise
	cd tests/security && go test ./... -race

security-full: ## Suite complète contre l'environnement local — make up requis
	@echo "Phase 2 — nécessite make up, voir tests/security/README.md"

security-fuzz: ## Fuzzing natif Go des décodeurs JSON, budget borné
	cd tests/security && go test ./fuzzing/... -fuzz=. -fuzztime=60s
```
`security-quick` ajouté comme job CI dans `.github/workflows/ci.yml`, parallèle à
`dependency-analysis`, `needs: [build-test]` — même runner, mêmes toolchains déjà installés,
aucune infrastructure supplémentaire.

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
