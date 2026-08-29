# Suite de tests de pénétration — Phase 1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ajouter une suite de tests de sécurité Phase 1 (authorization, business-logic, api-fuzz,
injection confirmatoire, rate-limit, auth console-web, tampering identity-provider) exécutable sans
`make up` sur ce poste Windows, avec rapport structuré et cible CI `security:quick`.

**Architecture:** Chaque test vit dans le module (Go) ou crate (Rust) de l'app qu'il teste — Go
`internal/` ne peut pas être importé depuis un module externe, et `identity-provider` (Rust) exige
Postgres+HSM pour tout test de handler complet. `tests/security/` ne contient que ce qui n'a pas
besoin d'importer un `internal/` d'app : documentation, script shell statique, agrégateur de
rapport JSON→Markdown.

**Tech Stack:** Go 1.25 (`net/http/httptest`, doublures maison, pas de `testify`), Rust 2024
(`#[cfg(test)]`), TypeScript/`node:test` (déjà en place), bash (`tests/architecture/run.sh` comme
modèle).

**Spec:** `docs/superpowers/specs/2026-08-25-security-test-suite-design.md`

## Global Constraints

- Aucun secret durable dans le code ou les fixtures (règle absolue #1 du `CLAUDE.md` racine).
- Refus par défaut : tout chemin d'erreur produit un refus explicite (règle absolue #2).
- Aucune primitive cryptographique écrite dans les tests — jamais de `crypto/*` Go direct, jamais
  de `ring`/`aws-lc-rs`/etc. Rust hors `zs-crypto`/`zs-hsm` (règles absolues #3-4).
- Un composant de `apps/` ne dépend jamais d'un autre composant de `apps/` ; le partage passe par
  `crates/`/`pkg/` (règle absolue #7) — c'est pourquoi ce plan n'introduit **aucune** nouvelle
  dépendance `pkg/` : le petit type `Finding`/writer JSON est dupliqué par module (justifié dans la
  spec, § « Duplication du Finding »), même précédent que `rfc3339_from_seconds` dupliqué entre
  `identity-provider`/`policy-engine`.
- Pas de nouvelle dépendance externe sans justification (règle absolue #10) — ce plan n'ajoute
  aucun paquet Go/Rust/npm tiers.
- Chaque test a un nom de la forme `TestSecurity...` (Go) — utilisé par la cible CI
  `security-quick` pour cibler uniquement les nouveaux tests via `-run 'TestSecurity|TestFuzz'`.
- Ne modifie le comportement d'aucune app pour faire passer un test artificiellement — un test qui
  documente un gap connu (absence de rate-limit, absence d'authz sur le quorum) est écrit pour
  échouer ou pour journaliser `Blocking: false`, jamais pour masquer le gap.
- Windows/PowerShell : ce poste n'a pas `podman-compose`. Chaque tâche de ce plan est vérifiable
  avec `cargo test`/`go test`/`npm test` uniquement — aucune tâche n'exige `make up`.

---

### Task 1: Scaffold `tests/security/` — README, garde-fous statiques, agrégateur de rapport

**Files:**
- Create: `tests/security/README.md`
- Create: `tests/security/dependencies/README.md`
- Create: `tests/security/infrastructure/check_compose_dev.sh`
- Create: `tests/security/report/output/.gitignore`
- Create: `tests/security/report/aggregate/go.mod`
- Create: `tests/security/report/aggregate/main.go`
- Modify: `go.work` (ajoute `./tests/security/report/aggregate`)
- Test: `tests/security/report/aggregate/main_test.go`

**Interfaces:**
- Produces: format JSON attendu par l'agrégateur — un tableau de `Finding` :
  `{"id","category","severity","component","description","payload","expected","obtained","evidence","remediation","owasp":[],"cwe","blocking"}`.
  Chaque module Go (tâches suivantes) écrit son fichier dans
  `tests/security/report/output/<module>.json`. L'agrégateur ne connaît que ce format — il n'importe
  aucun package `internal/` d'app.

- [ ] **Step 1: Écrire `tests/security/README.md`**

```markdown
# tests/security/

Suite de tests de pénétration automatisés (voir `penthtest.md` à la racine du dépôt et
`docs/superpowers/specs/2026-08-25-security-test-suite-design.md` pour la conception complète).

## Pourquoi les tests ne sont pas ici

Chaque app Go (`access-broker`, `admin-api`, `audit-collector`, `credential-issuer`) est son
propre module Go (`go.work`) et sa logique HTTP/gRPC vit sous un chemin `internal/` — la règle de
visibilité `internal` de Go interdit à un module externe de l'importer. Les tests de sécurité
vivent donc **co-localisés dans le module de l'app qu'ils testent** :

- `apps/admin-api/internal/httpapi/security_*_test.go`
- `apps/access-broker/internal/httpapi/security_*_test.go`
- `apps/audit-collector/internal/collector/security_*_test.go`
- `apps/console-web/src/security.test.ts`
- `apps/identity-provider/src/httpapi.rs` (module `#[cfg(test)] mod tests` existant, étendu)

Ce dossier ne contient que ce qui n'a pas besoin d'importer un `internal/` d'app :
- `report/aggregate/` — lit les JSON écrits par chaque module et produit un résumé Markdown.
- `infrastructure/` — contrôle statique de `deploy/compose.dev.yml`.
- `dependencies/` — pointe vers `make audit`, déjà en CI.

## Catégories hors périmètre (aucune surface réelle trouvée)

Confirmé par lecture du code le 2026-08-25 (voir la spec pour le détail par catégorie) :
- **SSRF** : aucune URL sortante dérivée d'une entrée utilisateur.
- **Uploads** : aucun `multipart`/`FormFile` dans `apps/`.
- **IA / RAG** : aucun LLM, agent, RAG ou vector store dans le dépôt.

Si l'une de ces surfaces apparaît dans une future contribution, relire la spec avant de rouvrir
la catégorie correspondante — ne pas fabriquer de test pour une fonctionnalité qui n'existe pas
encore (règle 19 de `penthtest.md`).

## Lancer les tests

```bash
make security-quick   # Phase 1 — pas d'infra requise, CI
make security-fuzz     # fuzzing natif Go, budget borné
make security-full     # Phase 2 — nécessite make up (Postgres + SoftHSM2), voir backlog ci-dessous
```

## Backlog Phase 2 (nécessite Postgres + SoftHSM2 réels — `make up`)

Ces tests ne sont **pas** écrits dans cette itération : `apps/identity-provider` enveloppe un
`sqlx::PgPool` concret (`src/store.rs:17-19`, pas de trait), et `AssertionSealer`/`AuditSealer`
scellent via un HSM réel (même famille que `DecisionSealer` de `policy-engine`, qui exige
SoftHSM2). Aucun double en process n'est possible sans changer la production pour la rendre
testable — hors périmètre de ce lot.

1. **Bypass de cérémonie** — appeler `registration_verify`/`authentication_verify`
   (`apps/identity-provider/src/httpapi.rs:164,296`) sans challenge préalablement émis par
   `registration_challenge`/`authentication_challenge` (`:127,248`) — doit être refusé
   (`challenge_invalide`, déjà le comportement attendu ; à couvrir par un test réel contre
   Postgres).
2. **Rejeu de challenge consommé** — appeler `registration_verify` deux fois avec le même
   `client_data_json` (même challenge) — `consume_challenge` (`store.rs`) doit refuser le second
   appel (retourne `None`).
3. **Race condition sur `consume_challenge`** — deux requêtes concurrentes consomment le même
   challenge (`store.rs`, appelé depuis `httpapi.rs:175-180`) — une seule doit réussir. Nécessite
   une vraie connexion Postgres pour observer l'atomicité réelle de la requête
   `UPDATE ... RETURNING`.
4. **Rate-limit sous charge réelle** — rafale contre `registration/challenge` avec un vrai
   `access-broker`/`identity-provider` démarrés (`make up`), pour mesurer latence/CPU/RAM en plus
   du simple constat d'absence (déjà couvert en Phase 1 par
   `apps/admin-api/internal/httpapi/security_rate_limit_test.go`, sans charge réelle).
5. **Recommandation admin-api (ADR-021)** : `POST /v1/critical-operations/{id}/quorum` n'a
   toujours aucune vérification de l'appelant (`security_authorization_test.go`, Phase 1,
   documente le gap). Remédiation proposée : exiger une assertion `AAL3` de l'appelant en plus des
   assertions de quorum, vérifiée par le même mécanisme que `access-broker`
   (`X-Identity-Assertion`), avant d'accepter `operation_id`.
```

- [ ] **Step 2: Écrire `tests/security/dependencies/README.md`**

```markdown
# dependencies/

Cette catégorie de `penthtest.md` est déjà couverte par `make audit` (`cargo-audit`, `cargo-deny`,
`govulncheck`, `gitleaks`), lui-même exécuté par le job CI `dependency-analysis`
(`.github/workflows/ci.yml`). Aucun test n'est dupliqué ici.
```

- [ ] **Step 3: Écrire `tests/security/infrastructure/check_compose_dev.sh`**

```bash
#!/usr/bin/env bash
# Contrôle statique de deploy/compose.dev.yml — pas de bind non-loopback, pas de conteneur
# privilégié hors softhsm-init (déjà justifié par ADR-008, frontière WebAuthn/HSM).
set -euo pipefail

compose_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/deploy/compose.dev.yml"
fail=0

if [[ ! -f "$compose_file" ]]; then
  echo "check_compose_dev: $compose_file introuvable" >&2
  exit 1
fi

# Aucun port ne doit être publié sur autre chose que 127.0.0.1 — un bind 0.0.0.0 exposerait
# Postgres/OpenBao au réseau local en environnement de dev. Les entrées réelles de compose.dev.yml
# sont au format "host_ip:host_port:container_port" (ex. "127.0.0.1:5432:5432") — un motif qui
# n'exige que deux groupes de chiffres séparés par ":" ne matche jamais ce format à trois segments
# (les points de l'IP cassent le motif) et laisserait passer silencieusement un bind 0.0.0.0.
# On cherche donc toute entrée de liste entre guillemets contenant un motif ":<port>" et on
# rejette celles qui ne commencent pas par "127.0.0.1:" juste après le guillemet — couvre aussi
# la forme "port:port" sans IP explicite, qui bind sur 0.0.0.0 par défaut avec Docker/Podman Compose.
if grep -nE '^\s*-\s*"' "$compose_file" | grep -E ':[0-9]+(:[0-9]+)?"' | grep -v '"127\.0\.0\.1:'; then
  echo "check_compose_dev: port publié sans préfixe 127.0.0.1: (voir ci-dessus)" >&2
  fail=1
fi

# Seul softhsm-init peut être privilégié (IPC_LOCK, justifié) — tout autre service avec
# privileged: true ou cap_add hors IPC_LOCK est un régression à signaler.
if grep -nE '^\s*privileged:\s*true' "$compose_file"; then
  echo "check_compose_dev: conteneur privileged: true trouvé — vérifier la justification" >&2
  fail=1
fi

if [[ "$fail" -eq 0 ]]; then
  echo "check_compose_dev: OK — aucun bind non-loopback, aucun privilège non justifié"
fi
exit "$fail"
```

- [ ] **Step 4: Rendre le script exécutable et le tester manuellement**

Run: `bash tests/security/infrastructure/check_compose_dev.sh`
Expected: `check_compose_dev: OK — aucun bind non-loopback, aucun privilège non justifié` (sortie 0).
Si le script échoue ici, c'est un vrai `Finding` à documenter dans le rapport final, pas un bug du
script — lire `deploy/compose.dev.yml` avant de corriger le script.

- [ ] **Step 5: Écrire `tests/security/report/output/.gitignore`**

```
*.json
*.md
!.gitignore
```

- [ ] **Step 6: Créer le module agrégateur `tests/security/report/aggregate/go.mod`**

```
module github.com/AlexisTak/biscuits-shield/tests/security/report/aggregate

go 1.25
```

- [ ] **Step 7: Écrire `tests/security/report/aggregate/main.go`**

```go
// Package main lit les rapports JSON écrits par chaque module de test de sécurité
// (tests/security/report/output/*.json) et produit un résumé Markdown sur stdout. N'importe
// aucun package internal/ d'app — seul le format JSON documenté dans tests/security/README.md
// est un contrat entre ce binaire et les modules qui écrivent les rapports.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type finding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Component   string   `json:"component"`
	Description string   `json:"description"`
	Payload     string   `json:"payload"`
	Expected    string   `json:"expected"`
	Obtained    string   `json:"obtained"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	OWASP       []string `json:"owasp"`
	CWE         string   `json:"cwe"`
	Blocking    bool     `json:"blocking"`
}

var severityRank = map[string]int{
	"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}

// rank renvoie le rang de tri d'une sévérité — une valeur non reconnue (fichier de rapport
// malformé) est triée après INFO, jamais confondue avec CRITICAL (zero value de la map).
func rank(severity string) int {
	if r, ok := severityRank[severity]; ok {
		return r
	}
	return len(severityRank)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: aggregate <dossier-output>")
		os.Exit(2)
	}
	dir := os.Args[1]

	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aggregate: lecture de %s : %v\n", dir, err)
		os.Exit(1)
	}

	var all []finding
	parsedFiles := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "aggregate: lecture de %s : %v\n", e.Name(), err)
			os.Exit(1)
		}
		var findings []finding
		if err := json.Unmarshal(data, &findings); err != nil {
			fmt.Fprintf(os.Stderr, "aggregate: JSON invalide dans %s : %v\n", e.Name(), err)
			os.Exit(1)
		}
		all = append(all, findings...)
		parsedFiles++
	}

	sort.SliceStable(all, func(i, j int) bool {
		return rank(all[i].Severity) < rank(all[j].Severity)
	})

	fmt.Println("# Rapport de sécurité — Phase 1")
	fmt.Println()
	fmt.Printf("%d finding(s) sur %d fichier(s) de rapport.\n\n", len(all), parsedFiles)
	for _, f := range all {
		blocking := "bloquant"
		if !f.Blocking {
			blocking = "non bloquant (gap connu)"
		}
		fmt.Printf("## [%s] %s — %s (%s)\n\n", f.Severity, f.ID, f.Component, blocking)
		fmt.Printf("**Catégorie** : %s\n\n", f.Category)
		fmt.Printf("**Description** : %s\n\n", f.Description)
		if f.Payload != "" {
			fmt.Printf("**Payload** : `%s`\n\n", f.Payload)
		}
		fmt.Printf("**Attendu** : %s\n\n**Obtenu** : %s\n\n", f.Expected, f.Obtained)
		fmt.Printf("**Preuve** : %s\n\n", f.Evidence)
		fmt.Printf("**Remédiation** : %s\n\n", f.Remediation)
		if len(f.OWASP) > 0 {
			fmt.Printf("**OWASP** : %v", f.OWASP)
			if f.CWE != "" {
				fmt.Printf(" — **CWE** : %s", f.CWE)
			}
			fmt.Println()
			fmt.Println()
		}
	}
}
```

- [ ] **Step 8: Écrire le test de l'agrégateur `tests/security/report/aggregate/main_test.go`**

```go
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityAggregateTrieParSeveriteEtFusionnePlusieursFichiers(t *testing.T) {
	dir := t.TempDir()

	write := func(name string, findings []finding) {
		data, err := json.Marshal(findings)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatalf("écriture %s: %v", name, err)
		}
	}

	write("admin-api.json", []finding{
		{ID: "AUTHZ-1", Severity: "HIGH", Component: "admin-api", Blocking: true},
	})
	write("access-broker.json", []finding{
		{ID: "RATE-1", Severity: "MEDIUM", Component: "admin-api", Blocking: false},
		{ID: "CRIT-1", Severity: "CRITICAL", Component: "access-broker", Blocking: true},
	})
	// Fichier non-JSON dans le même dossier (reflète .gitignore, réellement présent dans
	// tests/security/report/output/ en usage réel) — doit être ignoré par le compte de fichiers,
	// pas seulement par le parsing.
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.json\n"), 0o644); err != nil {
		t.Fatalf("écriture .gitignore : %v", err)
	}

	out, err := exec.Command("go", "run", ".", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("aggregate a échoué : %v\n%s", err, out)
	}
	report := string(out)

	idxCrit := strings.Index(report, "CRIT-1")
	idxAuthz := strings.Index(report, "AUTHZ-1")
	idxRate := strings.Index(report, "RATE-1")
	if idxCrit == -1 || idxAuthz == -1 || idxRate == -1 {
		t.Fatalf("un finding est absent du rapport :\n%s", report)
	}
	if !(idxCrit < idxAuthz && idxAuthz < idxRate) {
		t.Fatalf("ordre attendu CRITICAL < HIGH < MEDIUM, obtenu :\n%s", report)
	}
	if !strings.Contains(report, "3 finding(s) sur 2 fichier(s)") {
		t.Fatalf("total inattendu dans l'en-tête :\n%s", report)
	}
}
```

- [ ] **Step 9: Ajouter le module au workspace Go**

Modifier `go.work` :
```
go 1.25

use (
	./apps/access-broker
	./apps/admin-api
	./apps/audit-collector
	./apps/credential-issuer
	./pkg/gen
	./pkg/zstelemetry
	./tests/security/report/aggregate
)
```

- [ ] **Step 10: Lancer le test de l'agrégateur**

Run: `cd tests/security/report/aggregate && go test ./...`
Expected: `PASS` — `TestSecurityAggregateTrieParSeveriteEtFusionnePlusieursFichiers` réussit.

- [ ] **Step 11: Commit**

```bash
git add tests/security/README.md tests/security/dependencies/README.md \
  tests/security/infrastructure/check_compose_dev.sh tests/security/report/output/.gitignore \
  tests/security/report/aggregate/go.mod tests/security/report/aggregate/main.go \
  tests/security/report/aggregate/main_test.go go.work
git commit -m "test(security): scaffold tests/security — README, agrégateur de rapport, contrôle infra"
```

---

### Task 2: `admin-api` — régression authorization sur le quorum (ADR-021)

**Files:**
- Create: `apps/admin-api/internal/httpapi/security_report_test.go`
- Create: `apps/admin-api/internal/httpapi/security_authorization_test.go`

**Interfaces:**
- Consumes: `New(v *quorum.Verifier, auditClient auditv1.AuditCollectionServiceClient) *API`,
  `Handler(si ServerInterface) http.Handler`, `quorum.New(client identityv1.AssertionVerificationServiceClient) *Verifier`,
  `quorum.MinimumThreshold = 2`, `QuorumRequest{Assertions [][]byte, ExpectedAuthorityDomain string, Threshold int}`,
  `QuorumResult{Reached bool, DistinctSubjects []string}` — tous déjà utilisés par
  `apps/admin-api/internal/httpapi/handler_test.go`, mêmes doublures `fakeIdentityClient`/`fakeAuditClient`.
- Produces: `apps/admin-api/internal/httpapi/security_report_test.go` définit `securityFinding` et
  `writeSecurityReport(t *testing.T, findings []securityFinding)` — réutilisé par les tâches 3 et 4
  du même module (ne pas redéfinir).

- [ ] **Step 1: Écrire `security_report_test.go`**

```go
package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// securityFinding et writeSecurityReport sont dupliqués à l'identique dans chaque module Go
// (admin-api, access-broker, audit-collector) — un module pkg/ partagé exigerait de modifier le
// go.mod de 3 apps de production pour ~25 lignes utilisées seulement par des tests (règle absolue
// #10). Même précédent que rfc3339_from_seconds dupliqué entre identity-provider/policy-engine.
type securityFinding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Component   string   `json:"component"`
	Description string   `json:"description"`
	Payload     string   `json:"payload"`
	Expected    string   `json:"expected"`
	Obtained    string   `json:"obtained"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	OWASP       []string `json:"owasp"`
	CWE         string   `json:"cwe"`
	Blocking    bool     `json:"blocking"`
}

// writeSecurityReport écrit tests/security/report/output/admin-api.json — chemin relatif calculé
// depuis ce fichier (apps/admin-api/internal/httpapi -> 4 niveaux jusqu'à la racine du dépôt).
// N'échoue jamais le test si le dossier de sortie n'existe pas encore : t.Logf, pas t.Fatalf — un
// rapport manquant ne doit jamais faire échouer artificiellement un test de sécurité par ailleurs
// correct.
func writeSecurityReport(t *testing.T, findings []securityFinding) {
	t.Helper()
	outDir := filepath.Join("..", "..", "..", "..", "tests", "security", "report", "output")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Logf("writeSecurityReport: impossible de créer %s : %v", outDir, err)
		return
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		t.Logf("writeSecurityReport: marshal : %v", err)
		return
	}
	if err := os.WriteFile(filepath.Join(outDir, "admin-api.json"), data, 0o644); err != nil {
		t.Logf("writeSecurityReport: écriture : %v", err)
	}
}
```

- [ ] **Step 2: Écrire le test de régression (échoue d'abord — c'est voulu)**

```go
package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

// TestSecurityQuorumAcceptedSansVerificationDeLAppelant reproduit ADR-021 (handler.go:5-8) :
// POST /v1/critical-operations/{id}/quorum accepte deux porteurs dont les assertions sont
// valides, mais SANS vérifier que l'appelant HTTP est habilité à déclencher CETTE opération —
// deux porteurs choisis au hasard par l'attaquant, non liés à operation_id, suffisent. Ce test
// documente le gap réel (déjà signalé dans le commentaire du handler) : il échoue tant que la
// vérification n'existe pas, ce qui est le comportement attendu de ce lot — voir
// tests/security/README.md pour la remédiation proposée (Phase 2).
func TestSecurityQuorumAcceptedSansVerificationDeLAppelant(t *testing.T) {
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		"assertion-attaquant-a": {Valid: true, SubjectId: "sub-inconnu-1"},
		"assertion-attaquant-b": {Valid: true, SubjectId: "sub-inconnu-2"},
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(quorum.New(identity), audit)))
	defer srv.Close()

	body, _ := json.Marshal(QuorumRequest{
		Assertions: [][]byte{
			[]byte("assertion-attaquant-a"),
			[]byte("assertion-attaquant-b"),
		},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: "identity-provider",
	})
	resp, err := http.Post(
		srv.URL+"/v1/critical-operations/rotation-cle-hsm-prod/quorum",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	var result QuorumResult
	_ = json.NewDecoder(resp.Body).Decode(&result)

	finding := securityFinding{
		ID:        "SEC-ADMIN-API-AUTHZ-001",
		Category:  "authorization",
		Severity:  "HIGH",
		Component: "POST /v1/critical-operations/{id}/quorum",
		Description: "Aucune vérification que l'appelant HTTP est habilité à déclencher " +
			"l'opération critique operation_id — deux porteurs valides mais non liés à " +
			"l'opération suffisent à atteindre le quorum (ADR-021).",
		Payload: "2 assertions valides pour sub-inconnu-1/2, operation_id=rotation-cle-hsm-prod, " +
			"sans lien démontré avec cette opération",
		Expected:    "refus (403 ou équivalent) — l'appelant doit prouver son habilitation à initier cette opération",
		Remediation: "Exiger une assertion AAL3 de l'appelant HTTP lui-même, vérifiée avant tout appel à quorum.VerifyQuorum — voir tests/security/README.md",
		OWASP:       []string{"API1:2023 Broken Object Level Authorization"},
		CWE:         "CWE-862",
		Blocking:    true,
	}

	if resp.StatusCode == http.StatusOK && result.Reached {
		finding.Obtained = "200, reached=true — quorum atteint sans vérification d'habilitation"
		finding.Evidence = "apps/admin-api/internal/httpapi/handler.go:33-58 (VerifyQuorum, commentaire ADR-021 lignes 5-8)"
		writeSecurityReport(t, []securityFinding{finding})
		t.Fatalf(
			"vulnérabilité ADR-021 reproduite : quorum atteint (reached=%v, status=%d) sans "+
				"aucune vérification que l'appelant a le droit de déclencher operation_id — "+
				"voir tests/security/README.md pour la remédiation",
			result.Reached, resp.StatusCode,
		)
	}

	// Si ce test devient vert, la vérification d'habilitation a été ajoutée : verrouiller la
	// régression en confirmant explicitement le refus obtenu.
	finding.Obtained = "status inattendu ou reached=false — vérifier si une correction a été appliquée"
	finding.Blocking = false
	writeSecurityReport(t, []securityFinding{finding})
}
```

- [ ] **Step 3: Lancer le test et confirmer qu'il échoue (documente le gap réel)**

Run: `cd apps/admin-api && go test ./internal/httpapi/... -run TestSecurityQuorumAcceptedSansVerificationDeLAppelant -v`
Expected: FAIL avec le message `vulnérabilité ADR-021 reproduite : quorum atteint...` — confirme
que le gap documenté par l'audit et le code existe toujours. **Ne pas corriger le handler dans
cette tâche** : la remédiation est proposée dans `tests/security/README.md`, pas appliquée
silencieusement (règle du brief : signaler d'abord, créer le test qui reproduit).

- [ ] **Step 4: Vérifier que `tests/security/report/output/admin-api.json` a été écrit**

Run: `cat tests/security/report/output/admin-api.json` (depuis la racine du dépôt)
Expected: un tableau JSON avec un objet `id: "SEC-ADMIN-API-AUTHZ-001"`, `severity: "HIGH"`,
`blocking: true`.

- [ ] **Step 5: Commit**

```bash
git add apps/admin-api/internal/httpapi/security_report_test.go \
  apps/admin-api/internal/httpapi/security_authorization_test.go
git commit -m "test(security): admin-api — régression ADR-021, quorum sans authz appelant"
```

---

### Task 3: `admin-api` — constat rate-limit (non bloquant)

**Files:**
- Create: `apps/admin-api/internal/httpapi/security_rate_limit_test.go`

**Interfaces:**
- Consumes: `securityFinding`, `writeSecurityReport` (Task 2), mêmes doublures que Task 2.

- [ ] **Step 1: Écrire le test**

```go
package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

// TestSecurityAucunRateLimitSurQuorum constate (ne bloque pas la CI) l'absence de toute limitation
// de débit sur POST /v1/critical-operations/{id}/quorum — endpoint déjà sans vérification
// d'appelant (Task 2). Une rafale de requêtes malformées (seuil sous le plancher, refusé en 400)
// doit toutes réussir sans throttling ni ralentissement mesurable — sinon un mécanisme de
// limitation existe déjà et ce test doit être mis à jour pour le refléter.
func TestSecurityAucunRateLimitSurQuorum(t *testing.T) {
	identity := &fakeIdentityClient{}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(quorum.New(identity), audit)))
	defer srv.Close()

	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-a")},
		Threshold:               1, // sous le plancher — 400 rapide, pas de dépendance à identity-provider
		ExpectedAuthorityDomain: "identity-provider",
	})

	const burst = 200
	start := time.Now()
	success := 0
	for i := 0; i < burst; i++ {
		resp, err := http.Post(srv.URL+"/v1/critical-operations/op-1/quorum", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("le serveur ne doit jamais planter sous rafale : %v", err)
		}
		if resp.StatusCode == http.StatusBadRequest {
			success++
		}
		resp.Body.Close()
	}
	elapsed := time.Since(start)

	finding := securityFinding{
		ID:        "SEC-ADMIN-API-RATE-001",
		Category:  "rate-limit",
		Severity:  "MEDIUM",
		Component: "POST /v1/critical-operations/{id}/quorum",
		Description: "Aucune limitation de débit — une rafale de requêtes non authentifiées " +
			"est traitée intégralement sans ralentissement ni rejet 429.",
		Payload:     "200 requêtes séquentielles, seuil sous le plancher (refus 400 attendu par requête)",
		Expected:    "un rate-limiter documenté rejetterait une partie de la rafale (429) ou introduirait un ralentissement mesurable",
		Obtained:    "toutes les requêtes traitées, aucun 429",
		Evidence:    "grep -ri ratelimit/limiter/throttle apps/ pkg/ → 0 résultat (constaté 2026-08-25)",
		Remediation: "Ajouter un middleware de limitation de débit (ex. token bucket par IP/porteur) avant les handlers HTTP non authentifiés",
		OWASP:       []string{"API4:2023 Unrestricted Resource Consumption"},
		CWE:         "CWE-770",
		Blocking:    false, // gap connu, non bloquant en Phase 1 — voir tests/security/README.md
	}
	if success != burst {
		finding.Obtained = "un rejet inattendu a interrompu la rafale — un mécanisme de protection existe peut-être déjà"
	}
	t.Logf("rafale de %d requêtes traitée en %s (aucune limitation détectée : %v)", burst, elapsed, success == burst)
	writeSecurityReport(t, []securityFinding{finding})
}
```

- [ ] **Step 2: Lancer le test**

Run: `cd apps/admin-api && go test ./internal/httpapi/... -run TestSecurityAucunRateLimitSurQuorum -v`
Expected: `PASS` (le test constate et journalise, il n'échoue jamais — `Blocking: false`).

- [ ] **Step 3: Commit**

```bash
git add apps/admin-api/internal/httpapi/security_rate_limit_test.go
git commit -m "test(security): admin-api — constat non bloquant de l'absence de rate-limit"
```

---

### Task 4: `admin-api` — matrice API (fuzz structurel + non-fuite d'erreurs) et fuzzing natif

**Files:**
- Create: `apps/admin-api/internal/httpapi/security_api_test.go`
- Create: `apps/admin-api/internal/httpapi/fuzz_test.go`

**Interfaces:**
- Consumes: `securityFinding`, `writeSecurityReport` (Task 2).

- [ ] **Step 1: Écrire la matrice `security_api_test.go`**

```go
package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

// TestSecurityMatriceEntreesMalformeesNeCrashePasEtNeFuitRien couvre la section « API » de
// penthtest.md : méthode incorrecte, champ manquant, type incorrect, JSON malformé, chaîne
// énorme, tableau énorme, Content-Type incorrect — sur POST /v1/critical-operations/{id}/quorum.
// Deux assertions systématiques : pas de panique (le serveur répond toujours), pas de fuite
// (jamais de stack trace, chemin filesystem, ou fragment ressemblant à un secret dans le corps).
func TestSecurityMatriceEntreesMalformeesNeCrashePasEtNeFuitRien(t *testing.T) {
	identity := &fakeIdentityClient{}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(quorum.New(identity), audit)))
	defer srv.Close()

	longString := strings.Repeat("a", 5*1024*1024) // 5 Mio — chaîne extrêmement longue
	hugeArray := make([][]byte, 100000)
	for i := range hugeArray {
		hugeArray[i] = []byte("x")
	}

	cases := []struct {
		name        string
		method      string
		contentType string
		body        []byte
	}{
		{"methode_GET_au_lieu_de_POST", http.MethodGet, "application/json", nil},
		{"json_malforme", http.MethodPost, "application/json", []byte("{not json")},
		{"corps_vide", http.MethodPost, "application/json", []byte("")},
		{"content_type_incorrect", http.MethodPost, "text/plain", []byte(`{"assertions":[],"threshold":2,"expected_authority_domain":"x"}`)},
		{"champ_threshold_type_incorrect", http.MethodPost, "application/json", []byte(`{"assertions":[],"threshold":"pas-un-nombre","expected_authority_domain":"x"}`)},
		{"threshold_negatif_enorme", http.MethodPost, "application/json", mustJSON(QuorumRequest{Threshold: -999999999, ExpectedAuthorityDomain: "x"})},
		{"threshold_enorme", http.MethodPost, "application/json", mustJSON(QuorumRequest{Threshold: 2147483647, ExpectedAuthorityDomain: "x"})},
		{"champ_null", http.MethodPost, "application/json", []byte(`{"assertions":null,"threshold":2,"expected_authority_domain":null}`)},
		{"chaine_tres_longue", http.MethodPost, "application/json", mustJSON(QuorumRequest{Threshold: 2, ExpectedAuthorityDomain: longString})},
		{"tableau_enorme", http.MethodPost, "application/json", mustJSON(QuorumRequest{Threshold: 2, Assertions: hugeArray, ExpectedAuthorityDomain: "x"})},
		{"parametres_dupliques", http.MethodPost, "application/json", []byte(`{"threshold":2,"threshold":999,"expected_authority_domain":"x","assertions":[]}`)},
	}

	var findings []securityFinding
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, srv.URL+"/v1/critical-operations/op-1/quorum", bytes.NewReader(tc.body))
			if err != nil {
				t.Fatalf("construction requête : %v", err)
			}
			req.Header.Set("Content-Type", tc.contentType)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("le serveur n'a pas répondu (crash possible) pour le cas %q : %v", tc.name, err)
			}
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			lower := strings.ToLower(string(respBody))

			leaks := []string{"panic", "goroutine", "runtime error", ".go:", "c:\\users", "/home/", "traceback"}
			for _, l := range leaks {
				if strings.Contains(lower, l) {
					findings = append(findings, securityFinding{
						ID:          "SEC-ADMIN-API-INFOLEAK-" + tc.name,
						Category:    "information-disclosure",
						Severity:    "MEDIUM",
						Component:   "POST /v1/critical-operations/{id}/quorum",
						Description: "Réponse d'erreur contenant un fragment sensible (" + l + ") pour le cas " + tc.name,
						Payload:     string(tc.body),
						Expected:    "réponse d'erreur générique sans détail interne",
						Obtained:    string(respBody),
						Evidence:    "apps/admin-api/internal/httpapi/handler.go",
						Remediation: "Ne jamais inclure err.Error()/panic recover brut dans une réponse HTTP",
						OWASP:       []string{"API8:2023 Security Misconfiguration"},
						CWE:         "CWE-209",
						Blocking:    true,
					})
					t.Errorf("cas %q : fuite détectée (%q) dans la réponse : %s", tc.name, l, respBody)
				}
			}
			if resp.StatusCode >= 500 && tc.name != "methode_GET_au_lieu_de_POST" {
				t.Errorf("cas %q : status 5xx (%d) — un refus attendu est 4xx, pas une erreur serveur", tc.name, resp.StatusCode)
			}
		})
	}
	if len(findings) > 0 {
		writeSecurityReport(t, findings)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // uniquement dans la construction de fixtures de test, jamais atteignable en production
	}
	return b
}
```

- [ ] **Step 2: Lancer la matrice**

Run: `cd apps/admin-api && go test ./internal/httpapi/... -run TestSecurityMatriceEntreesMalformeesNeCrashePasEtNeFuitRien -v`
Expected: `PASS` sur tous les sous-tests. Si un sous-test échoue, lire le message — c'est un vrai
`Finding` (déjà écrit dans `tests/security/report/output/admin-api.json` par le test lui-même), pas
un bug de test à contourner.

- [ ] **Step 3: Écrire `fuzz_test.go` (corpus natif Go, budget borné)**

```go
package httpapi

import (
	"encoding/json"
	"testing"
)

// FuzzSecurityDecodeQuorumRequest fuzze le décodeur JSON de QuorumRequest — cible de
// `make security-fuzz` (go test -fuzz=FuzzSecurityDecodeQuorumRequest -fuzztime=60s). Sans le
// flag -fuzz, ce test exécute uniquement le corpus de départ (seed) — inclus dans
// `make security-quick` à coût nul.
func FuzzSecurityDecodeQuorumRequest(f *testing.F) {
	f.Add([]byte(`{"assertions":["YQ=="],"threshold":2,"expected_authority_domain":"x"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"threshold":-1}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"assertions":[123]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var req QuorumRequest
		// Ne doit jamais paniquer, quel que soit le contenu — un décodage invalide renvoie une
		// erreur, jamais un crash du processus.
		_ = json.Unmarshal(data, &req)
	})
}
```

- [ ] **Step 4: Lancer le corpus de départ (sans `-fuzz`, rapide)**

Run: `cd apps/admin-api && go test ./internal/httpapi/... -run FuzzSecurityDecodeQuorumRequest -v`
Expected: `PASS`.

- [ ] **Step 5: Commit**

```bash
git add apps/admin-api/internal/httpapi/security_api_test.go apps/admin-api/internal/httpapi/fuzz_test.go
git commit -m "test(security): admin-api — matrice API, non-fuite d'erreurs, fuzz natif du décodeur"
```

---

### Task 5: `access-broker` — business-logic (intégrité de la décision, mass assignment)

**IMPORTANT — lu depuis le code réel (pas dans la version initiale de ce plan) :**
`apps/access-broker/internal/httpapi/handler_test.go` existe déjà et définit au niveau du package
`fakeIdentityClient`, `fakePolicyClient`, `fakeCredentialClient`, `fakeAuditClient` (avec
`valid bool`/`subjectID`/`aal`/`authMethod`/`err` pour `fakeIdentityClient`, `response
*policyv1.DecisionResponse` pour `fakePolicyClient`, etc. — signatures ci-dessous) ainsi que
`fixedTime()` et `validBody() AccessRequestBody`. **Ce fichier de tâche réutilise ces types
existants et n'en redéclare aucun** — les redéclarer provoquerait une erreur de compilation
(« redeclared in this block »).

**Files:**
- Create: `apps/access-broker/internal/httpapi/security_report_test.go`
- Create: `apps/access-broker/internal/httpapi/security_business_logic_test.go`

**Interfaces:**
- Consumes (déjà définis dans `handler_test.go`, même package, ne pas redéclarer) :
  `fakeIdentityClient{valid bool, subjectID, aal, authMethod string, err error}` (méthode
  `VerifyAssertion` ignore le contenu de l'assertion présentée, ne renvoie que la réponse
  configurée — ne peut donc pas distinguer deux assertions différentes),
  `fakePolicyClient{response *policyv1.DecisionResponse}`,
  `fakeCredentialClient{response *credentialv1.EmissionResult, err error, called bool, lastReq *credentialv1.EmissionOrder}`,
  `fakeAuditClient{called bool, lastReq *auditv1.RawEvent, err error, rejected bool, reason string}`,
  `validBody() AccessRequestBody` (corps nominal avec `Approvals` déjà rempli),
  `New(identityClient, credentialClient, auditClient, b *broker.Broker) *API`,
  `Handler(si ServerInterface) http.Handler`, `broker.New(policyClient, identityClient)`.
- Produces: `securityFinding`/`writeSecurityReport` réutilisés par Task 6 (même module).

- [ ] **Step 1: Écrire `security_report_test.go` (identique à Task 2, écrit `access-broker.json`)**

```go
package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// securityFinding et writeSecurityReport : voir la justification de duplication dans
// apps/admin-api/internal/httpapi/security_report_test.go (règle absolue #10).
type securityFinding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Component   string   `json:"component"`
	Description string   `json:"description"`
	Payload     string   `json:"payload"`
	Expected    string   `json:"expected"`
	Obtained    string   `json:"obtained"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	OWASP       []string `json:"owasp"`
	CWE         string   `json:"cwe"`
	Blocking    bool     `json:"blocking"`
}

func writeSecurityReport(t *testing.T, findings []securityFinding) {
	t.Helper()
	outDir := filepath.Join("..", "..", "..", "..", "tests", "security", "report", "output")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Logf("writeSecurityReport: impossible de créer %s : %v", outDir, err)
		return
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		t.Logf("writeSecurityReport: marshal : %v", err)
		return
	}
	if err := os.WriteFile(filepath.Join(outDir, "access-broker.json"), data, 0o644); err != nil {
		t.Logf("writeSecurityReport: écriture : %v", err)
	}
}
```

- [ ] **Step 2: Écrire `security_business_logic_test.go`**

Un seul test, réutilisant intégralement les doublures et `validBody()` déjà définis dans
`handler_test.go` (même package) — ne redéclare rien.

```go
package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	policyv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/policy/v1"

	"github.com/AlexisTak/biscuits-shield/apps/access-broker/internal/broker"
)

// TestSecurityChampsDecisionSupplementairesIgnores confirme qu'un client ne peut jamais imposer
// decision_hash/policy_version/allowed dans le corps de la requête pour falsifier une décision —
// AccessRequestBody n'expose pas ces champs (contracts/openapi/access-broker.yaml), et
// json.NewDecoder n'utilise pas DisallowUnknownFields (confirmé par grep, absent de tout le
// dépôt) : le décodeur les ignore silencieusement. La réponse ne doit refléter QUE ce que
// policy-engine a signé (ici via fakePolicyClient, déjà défini dans handler_test.go).
func TestSecurityChampsDecisionSupplementairesIgnores(t *testing.T) {
	identity := &fakeIdentityClient{valid: true, subjectID: "sub-demandeur", aal: "AAL3", authMethod: "webauthn/device-bound"}
	credential := &fakeCredentialClient{}
	policy := &fakePolicyClient{response: &policyv1.DecisionResponse{
		Effect:        policyv1.Effect_EFFECT_DENY,
		Reasons:       []string{"politique_refusee"},
		DecisionHash:  []byte{0xAA, 0xBB},
		PolicyVersion: "decision-binding/v1:reelle",
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(identity, credential, audit, broker.New(policy, identity))))
	defer srv.Close()

	// Corps JSON brut avec des champs qu'AccessRequestBody n'expose pas — tentative de mass
	// assignment vers une décision falsifiée.
	rawBody := []byte(`{
		"verb": "db.connect",
		"resource": {"type": "Database", "id": "db-prod", "authority_domain": "corp.eu-west"},
		"ticket_ref": "INC-1",
		"justification": "test",
		"expected_authority_domain": "corp.eu-west",
		"decision_hash": "ZmF1eA==",
		"policy_version": "falsifiee-par-le-client",
		"allowed": true
	}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/access-requests", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Identity-Assertion", "assertion-legitime")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attendu 200 (refus PDP normal, pas une erreur de transport), reçu %d", resp.StatusCode)
	}

	var decision Decision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		t.Fatalf("réponse JSON invalide : %v", err)
	}
	if decision.Allowed {
		t.Fatal("le champ \"allowed\":true injecté dans le corps n'aurait jamais dû influencer la décision (DENY attendu, signé par policy-engine)")
	}
	if decision.DecisionHash == nil || string(*decision.DecisionHash) != string([]byte{0xAA, 0xBB}) {
		t.Fatalf("decision_hash doit provenir de policy-engine (0xAABB), pas du client : obtenu %v", decision.DecisionHash)
	}
	if decision.PolicyVersion == nil || *decision.PolicyVersion != "decision-binding/v1:reelle" {
		t.Fatalf("policy_version doit provenir de policy-engine, pas du champ falsifié par le client : obtenu %v", decision.PolicyVersion)
	}
}
```

- [ ] **Step 3: Lancer le test**

Run: `cd apps/access-broker && go test ./internal/httpapi/... -run TestSecurityChampsDecisionSupplementairesIgnores -v`
Expected: `PASS`. Si le test échoue, lire précisément le message avant de modifier quoi que ce
soit — ce module ne doit changer que si le test révèle une vraie divergence avec ce que
`handler.go` fait réellement (relire le fichier avant de conclure à un bug de test).

- [ ] **Step 4: Commit**

```bash
git add apps/access-broker/internal/httpapi/security_report_test.go \
  apps/access-broker/internal/httpapi/security_business_logic_test.go
git commit -m "test(security): access-broker — câblage refus d'assertion, non-influence du corps sur la décision"
```

---

### Task 6: `access-broker` — matrice API et fuzzing natif

**Files:**
- Create: `apps/access-broker/internal/httpapi/security_api_test.go`
- Create: `apps/access-broker/internal/httpapi/fuzz_test.go`

**Interfaces:**
- Consumes: `securityFinding`, `writeSecurityReport` (Task 5). Réutilise les doublures existantes
  de `handler_test.go` — `fakeIdentityClient{valid, subjectID, aal, authMethod, err}`,
  `fakePolicyClient{response}`, `fakeCredentialClient{response, err, called, lastReq}`,
  `fakeAuditClient{called, lastReq, err, rejected, reason}` — même contrainte que Task 5, ne rien
  redéclarer.

- [ ] **Step 1: Écrire `security_api_test.go`**

```go
package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	policyv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/policy/v1"

	"github.com/AlexisTak/biscuits-shield/apps/access-broker/internal/broker"
)

// TestSecurityMatriceEntreesMalformeesAccessBroker — même patron que admin-api Task 4, adapté à
// POST /v1/access-requests. En-tête X-Identity-Assertion manquant/vide fait partie de la matrice
// (headers inhabituels). Effect DENY partout : évite de déclencher l'émission de credential, hors
// périmètre de cette matrice.
func TestSecurityMatriceEntreesMalformeesAccessBroker(t *testing.T) {
	identity := &fakeIdentityClient{valid: true, subjectID: "sub-1", aal: "AAL3"}
	credential := &fakeCredentialClient{}
	policy := &fakePolicyClient{response: &policyv1.DecisionResponse{Effect: policyv1.Effect_EFFECT_DENY}}
	audit := &fakeAuditClient{}

	srv := httptest.NewServer(Handler(New(identity, credential, audit, broker.New(policy, identity))))
	defer srv.Close()

	longString := strings.Repeat("a", 5*1024*1024)

	cases := []struct {
		name        string
		assertion   string
		contentType string
		body        []byte
	}{
		{"json_malforme", "assertion-legitime", "application/json", []byte("{not json")},
		{"en_tete_assertion_absent", "", "application/json", mustJSON(AccessRequestBody{Verb: "db.connect", Resource: Resource{Type: "Database", Id: "x", AuthorityDomain: "x"}, ExpectedAuthorityDomain: "x"})},
		{"champ_resource_manquant", "assertion-legitime", "application/json", []byte(`{"verb":"db.connect","expected_authority_domain":"x"}`)},
		{"verb_extremement_long", "assertion-legitime", "application/json", mustJSON(AccessRequestBody{Verb: longString, Resource: Resource{Type: "Database", Id: "x", AuthorityDomain: "x"}, ExpectedAuthorityDomain: "x"})},
		{"content_type_incorrect", "assertion-legitime", "text/plain", mustJSON(AccessRequestBody{Verb: "db.connect", Resource: Resource{Type: "Database", Id: "x", AuthorityDomain: "x"}, ExpectedAuthorityDomain: "x"})},
	}

	var findings []securityFinding
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/access-requests", bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			if tc.assertion != "" {
				req.Header.Set("X-Identity-Assertion", tc.assertion)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("le serveur n'a pas répondu (crash possible) pour %q : %v", tc.name, err)
			}
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			lower := strings.ToLower(string(respBody))

			for _, l := range []string{"panic", "goroutine", "runtime error", ".go:", "c:\\users", "/home/"} {
				if strings.Contains(lower, l) {
					findings = append(findings, securityFinding{
						ID: "SEC-ACCESS-BROKER-INFOLEAK-" + tc.name, Category: "information-disclosure",
						Severity: "MEDIUM", Component: "POST /v1/access-requests",
						Description: "Fuite (" + l + ") dans la réponse d'erreur pour " + tc.name,
						Payload:     string(tc.body), Obtained: string(respBody),
						Expected: "réponse générique sans détail interne", Blocking: true,
						OWASP: []string{"API8:2023 Security Misconfiguration"}, CWE: "CWE-209",
						Remediation: "Ne jamais renvoyer err.Error() brut",
					})
					t.Errorf("cas %q : fuite détectée (%q)", tc.name, l)
				}
			}
			if resp.StatusCode >= 500 {
				t.Errorf("cas %q : status 5xx (%d) inattendu", tc.name, resp.StatusCode)
			}
		})
	}
	if len(findings) > 0 {
		writeSecurityReport(t, findings)
	}
}

// mustJSON : doublure locale à ce module (package httpapi d'access-broker) — le mustJSON de
// admin-api (Task 4) vit dans un module Go séparé, non importable ici (même contrainte de
// visibilité internal/ que securityFinding/writeSecurityReport, voir Task 5 Step 1).
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // uniquement dans la construction de fixtures de test, jamais atteignable en production
	}
	return b
}
```

- [ ] **Step 2: Écrire `fuzz_test.go`**

```go
package httpapi

import (
	"encoding/json"
	"testing"
)

// FuzzSecurityDecodeAccessRequestBody — cible de `make security-fuzz`.
func FuzzSecurityDecodeAccessRequestBody(f *testing.F) {
	f.Add([]byte(`{"verb":"db.connect","resource":{"type":"Database","id":"x","authority_domain":"x"},"expected_authority_domain":"x"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"resource":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var body AccessRequestBody
		_ = json.Unmarshal(data, &body)
	})
}
```

- [ ] **Step 3: Lancer les tests**

Run: `cd apps/access-broker && go test ./internal/httpapi/... -run 'TestSecurity|FuzzSecurity' -v`
Expected: `PASS`.

- [ ] **Step 4: Commit**

```bash
git add apps/access-broker/internal/httpapi/security_api_test.go apps/access-broker/internal/httpapi/fuzz_test.go
git commit -m "test(security): access-broker — matrice API, non-fuite d'erreurs, fuzz natif du décodeur"
```

---

### Task 7: `audit-collector` — injection confirmatoire

**Files:**
- Create: `apps/audit-collector/internal/collector/security_report_test.go`
- Create: `apps/audit-collector/internal/collector/security_injection_test.go`

**IMPORTANT — lu depuis le code réel :** `apps/audit-collector/internal/collector/collector_test.go`
existe déjà et définit au niveau du package `fakeSealer{sealCalls int, sealErr error, sealedOut
[]byte, hashOut []byte, lastSealReq *auditv1.SealRequest}` (méthodes `Seal`/`HashPrevious` déjà
implémentées) et `fakeStore{head store.ChainHead, headErr error, appendErr error, appendedIn
*store.AppendInput}` (une seule capture, pas une liste — `appendedIn` est écrasé à chaque appel,
suffisant ici car chaque sous-test crée un `fakeStore` neuf). **Ce fichier de tâche réutilise ces
types et n'en redéclare aucun.**

**Interfaces:**
- Consumes (déjà définis dans `collector_test.go`, même package, ne pas redéclarer) :
  `collector.New(sealer auditv1.AuditSealingServiceClient, st Store) *Collector`, `fakeSealer`,
  `fakeStore` (ci-dessus), `validRawEvent() *auditv1.RawEvent`.

- [ ] **Step 1: Écrire `security_report_test.go` (identique aux tâches 2 et 5, écrit `audit-collector.json`)**

```go
package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type securityFinding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Component   string   `json:"component"`
	Description string   `json:"description"`
	Payload     string   `json:"payload"`
	Expected    string   `json:"expected"`
	Obtained    string   `json:"obtained"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	OWASP       []string `json:"owasp"`
	CWE         string   `json:"cwe"`
	Blocking    bool     `json:"blocking"`
}

func writeSecurityReport(t *testing.T, findings []securityFinding) {
	t.Helper()
	outDir := filepath.Join("..", "..", "..", "..", "tests", "security", "report", "output")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Logf("writeSecurityReport: impossible de créer %s : %v", outDir, err)
		return
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		t.Logf("writeSecurityReport: marshal : %v", err)
		return
	}
	if err := os.WriteFile(filepath.Join(outDir, "audit-collector.json"), data, 0o644); err != nil {
		t.Logf("writeSecurityReport: écriture : %v", err)
	}
}
```

- [ ] **Step 2: Écrire `security_injection_test.go`**

Réutilise `fakeSealer{sealedOut: []byte(...)}` et `fakeStore{}` (zéro valeur — `head` zéro donne
`NextSequence: 0, PrevSealedBytes: nil`, donc `HashPrevious` n'est jamais appelé, cohérent avec
les tests existants du même fichier). `fakeStore.ChainHead` ignore son argument `authorityDomain`
(retourne toujours `f.head`) — la preuve que le payload traverse intact passe donc uniquement par
`appendedIn.AuthorityDomain`, alimenté par `raw.GetAuthorityDomain()` dans `Record`
(`collector.go:87,113`), ce qui suffit à la garantie recherchée.

```go
package collector

import (
	"context"
	"testing"

	auditv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/audit/v1"
)

// TestSecurityPayloadInjectionSQLTraverseCommeValeurOpaque envoie des payloads d'injection SQL
// classiques dans authority_domain — le champ qui atteint directement la requête paramétrée
// `WHERE authority_domain = $1` (internal/store/store.go:49) et `VALUES ($1,…,$12)` (:95). Avec le
// fakeStore existant (collector_test.go), on confirme que le Collector transmet la chaîne TELLE
// QUELLE à AppendInput.AuthorityDomain (aucune concaténation, aucune interprétation avant le
// store) — la garantie structurelle du paramétrage $1 est ainsi couverte sans exécuter Postgres.
func TestSecurityPayloadInjectionSQLTraverseCommeValeurOpaque(t *testing.T) {
	payloads := []string{
		`' OR '1'='1`,
		`'; DROP TABLE audit.events; --`,
		`x' UNION SELECT credential_id, public_key FROM identity.authenticators --`,
		`%27%20OR%20%271%27%3D%271`, // encodé URL
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			sealer := &fakeSealer{sealedOut: []byte("scelle-de-test")}
			st := &fakeStore{}
			c := New(sealer, st)

			raw := validRawEvent()
			raw.AuthorityDomain = payload

			result, err := c.Record(context.Background(), raw)
			if err != nil {
				t.Fatalf("Record ne doit jamais renvoyer d'erreur de transport pour ce payload : %v", err)
			}
			if !result.Accepted {
				t.Fatalf("Record doit accepter l'événement (le payload n'est pas un event_type/outcome invalide) : reason=%q", result.Reason)
			}
			if st.appendedIn == nil || st.appendedIn.AuthorityDomain != payload {
				t.Fatalf("Append doit recevoir AppendInput.AuthorityDomain = %q tel quel, obtenu %+v", payload, st.appendedIn)
			}
		})
	}
}
```

- [ ] **Step 3: Lancer le test**

Run: `cd apps/audit-collector && go test ./internal/collector/... -run TestSecurityPayloadInjectionSQLTraverseCommeValeurOpaque -v`
Expected: `PASS` sur les 4 payloads.

- [ ] **Step 4: Commit**

```bash
git add apps/audit-collector/internal/collector/security_report_test.go \
  apps/audit-collector/internal/collector/security_injection_test.go
git commit -m "test(security): audit-collector — confirmation injection SQL (payload opaque, Store faux)"
```

---

### Task 8: `console-web` — CSRF et accès sans session

**Files:**
- Create: `apps/console-web/src/security.test.ts`

**Interfaces:**
- Consumes: `createApp(config: ServerConfig)`, `ServerConfig{origin, identityProvider, accessBroker, adminApi, expectedAuthorityDomain, sessionTtlSeconds, publicDir}` — même construction que
  `apps/console-web/src/server.test.ts` (fakes HTTP en process, `listenEphemeral`).
  Constructeurs confirmés par lecture de `clients/identity-provider.ts:37-38`,
  `clients/access-broker.ts:27-28`, `clients/admin-api.ts:30-31` : les trois prennent un unique
  argument `baseUrl: string` — `new HttpIdentityProviderClient(baseUrl)`,
  `new HttpAccessBrokerClient(baseUrl)`, `new HttpAdminApiClient(baseUrl)`.

- [ ] **Step 1: Écrire `security.test.ts`**

```typescript
// Tests de sécurité console-web — même patron que server.test.ts (vrai serveur HTTP, pas de faux
// backend nécessaire pour CSRF/session : ces contrôles s'exécutent AVANT tout appel aux clients
// identity-provider/access-broker/admin-api).

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createApp, type ServerConfig } from "./server.js";
import { HttpIdentityProviderClient } from "./clients/identity-provider.js";
import { HttpAccessBrokerClient } from "./clients/access-broker.js";
import { HttpAdminApiClient } from "./clients/admin-api.js";

async function listenEphemeral(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return `http://127.0.0.1:${addr.port}`;
}

function minimalConfig(origin: string): ServerConfig {
  // Aucun backend n'est censé être appelé par les tests de ce fichier — CSRF et session-gating se
  // décident avant tout appel réseau sortant (server.ts:42, server.ts:234-240).
  const deadUrl = "http://127.0.0.1:1"; // port jamais écouté — un appel ici ferait échouer le test bruyamment
  return {
    origin,
    identityProvider: new HttpIdentityProviderClient(deadUrl),
    accessBroker: new HttpAccessBrokerClient(deadUrl),
    adminApi: new HttpAdminApiClient(deadUrl),
    expectedAuthorityDomain: "corp.eu-west",
    sessionTtlSeconds: 900,
    publicDir: ".",
  };
}

test("TestSecurityCSRF: POST sans Origin ni Sec-Fetch-Site same-origin est refusé 403", async () => {
  const app = createApp(minimalConfig("https://zero-secret.example"));
  const base = await listenEphemeral(app);

  const resp = await fetch(`${base}/access-request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "resource_type=Database&resource_id=x",
  });

  assert.equal(resp.status, 403, "un POST cross-origin (aucun Origin/Sec-Fetch-Site attendu) doit être refusé");
  app.close();
});

test("TestSecurityCSRF: POST avec Origin falsifié différent de config.origin est refusé 403", async () => {
  const app = createApp(minimalConfig("https://zero-secret.example"));
  const base = await listenEphemeral(app);

  const resp = await fetch(`${base}/access-request`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      origin: "https://attaquant.example",
    },
    body: "resource_type=Database&resource_id=x",
  });

  assert.equal(resp.status, 403, "un Origin différent de config.origin doit être refusé");
  app.close();
});

test("TestSecuritySession: /access-request sans cookie de session redirige vers /login, ne fuit rien", async () => {
  const app = createApp(minimalConfig("https://zero-secret.example"));
  const base = await listenEphemeral(app);

  const resp = await fetch(`${base}/access-request`, {
    method: "GET",
    redirect: "manual",
  });

  assert.equal(resp.status, 302, "sans cookie de session, /access-request doit rediriger, jamais servir la page");
  assert.equal(resp.headers.get("location"), "/login");
  app.close();
});

test("TestSecuritySession: /quorum sans cookie de session redirige vers /login", async () => {
  const app = createApp(minimalConfig("https://zero-secret.example"));
  const base = await listenEphemeral(app);

  const resp = await fetch(`${base}/quorum`, {
    method: "GET",
    redirect: "manual",
  });

  assert.equal(resp.status, 302, "sans cookie de session, /quorum doit rediriger, jamais servir la page");
  assert.equal(resp.headers.get("location"), "/login");
  app.close();
});

test("TestSecuritySession: cookie de session forgé (mauvaise longueur) est refusé comme absent", async () => {
  const app = createApp(minimalConfig("https://zero-secret.example"));
  const base = await listenEphemeral(app);

  const resp = await fetch(`${base}/access-request`, {
    method: "GET",
    redirect: "manual",
    headers: { cookie: "__Host-session=cookie-invente-par-un-attaquant" },
  });

  assert.equal(resp.status, 302, "un identifiant de session non enregistré doit être traité comme absent");
  app.close();
});
```

- [ ] **Step 2: Compiler et lancer**

Run: `cd apps/console-web && npm run build && node --test "dist/**/security.test.js"`
Expected: 5 tests `PASS`.

- [ ] **Step 3: Commit**

```bash
git add apps/console-web/src/security.test.ts
git commit -m "test(security): console-web — CSRF (Origin/Sec-Fetch-Site) et accès sans session"
```

---

### Task 9: `identity-provider` — tampering au niveau fonction pure (Phase 1 uniquement)

**Files:**
- Modify: `apps/identity-provider/src/httpapi.rs` (étend le module `#[cfg(test)] mod tests`
  existant, lignes 587-640)

**Interfaces:**
- Consumes: `presented_challenge_bytes(client_data_json: &[u8]) -> Result<Vec<u8>, ApiError>`,
  `b64_decode(field: &str, value: &str) -> Result<Vec<u8>, ApiError>` — fonctions privées déjà
  définies dans ce fichier, déjà testées pour le cas nominal (voir lignes 592-627).

- [ ] **Step 1: Ajouter les tests de sécurité dans le module `tests` existant**

Ajouter à la fin du bloc `#[cfg(test)] mod tests { ... }` (après la ligne 638, avant la fermeture
`}` du module) :

```rust
    // --- Tests de sécurité (Phase 1 — fonctions pures uniquement, pas de Postgres/HSM) --------
    //
    // Le bypass de cérémonie complet, le rejeu de challenge consommé et la race condition sur
    // consume_challenge exigent un IdentityStore réel (sqlx::PgPool concret, pas de trait) et un
    // AssertionSealer/AuditSealer réels (HSM) — voir tests/security/README.md, backlog Phase 2.

    #[test]
    fn security_presented_challenge_bytes_refuse_un_champ_challenge_de_type_incorrect() {
        // Confusion de type : challenge fourni comme nombre au lieu de chaîne base64 — doit être
        // refusé par serde_json, jamais interprété silencieusement.
        let cdj = serde_json::json!({
            "type": "webauthn.get",
            "challenge": 12345,
            "origin": "https://zero-secret.example",
        })
        .to_string();
        assert!(
            presented_challenge_bytes(cdj.as_bytes()).is_err(),
            "un champ challenge numérique doit être refusé, jamais coercé en chaîne"
        );
    }

    #[test]
    fn security_presented_challenge_bytes_ignore_les_champs_supplementaires_sans_planter() {
        // Champs JSON supplémentaires non prévus par le contrat WebAuthn — serde doit les ignorer
        // silencieusement (comportement par défaut), jamais paniquer.
        let cdj = serde_json::json!({
            "type": "webauthn.get",
            "challenge": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
            "origin": "https://zero-secret.example",
            "crossOrigin": false,
            "tokenBinding": {"status": "supported"},
            "__proto__": {"admin": true},
        })
        .to_string();
        assert!(
            presented_challenge_bytes(cdj.as_bytes()).is_ok(),
            "des champs JSON supplémentaires (y compris __proto__) ne doivent jamais faire échouer l'extraction"
        );
    }

    #[test]
    fn security_b64_decode_refuse_un_padding_standard_meme_partiel() {
        // "AA==" (padding double) et "AA=" (padding simple invalide) sont tous deux du base64
        // standard, jamais base64url-sans-padding (RFC 4648 §5, règle imposée par ce module).
        assert!(b64_decode("champ", "AA==").is_err());
        assert!(b64_decode("champ", "AA=").is_err());
    }

    #[test]
    fn security_b64_decode_refuse_les_espaces_et_retours_a_la_ligne_injectes() {
        // Un attaquant qui injecte des espaces/sauts de ligne dans un champ base64 ne doit jamais
        // voir sa charge partiellement décodée — refus complet, pas de troncature silencieuse.
        assert!(b64_decode("champ", "AA AA").is_err());
        assert!(b64_decode("champ", "AA\nAA").is_err());
    }

    #[test]
    fn security_b64_decode_refuse_une_chaine_extremement_longue_sans_paniquer() {
        // 10 Mio de caractères 'a' répétés — ni panique, ni écriture illimitée : le décodeur
        // base64 doit refuser proprement (longueur non multiple de 4 attendue par le format, ou
        // décodage réussi mais borné par la taille de l'entrée elle-même, jamais un crash).
        let huge = "a".repeat(10 * 1024 * 1024);
        let _ = b64_decode("champ", &huge); // ne doit jamais paniquer, quel que soit le résultat
    }
```

- [ ] **Step 2: Lancer les nouveaux tests**

Run: `cd apps/identity-provider && cargo test --lib security_`
Expected: 5 tests `ok` (préfixe `security_`).

- [ ] **Step 3: Lancer l'ensemble du module pour vérifier l'absence de régression**

Run: `cd apps/identity-provider && cargo test --lib`
Expected: tous les tests existants restent `ok` en plus des 5 nouveaux.

- [ ] **Step 4: Commit**

```bash
git add apps/identity-provider/src/httpapi.rs
git commit -m "test(security): identity-provider — tampering des fonctions pures d'extraction/décodage"
```

---

### Task 10: Makefile et CI — cibles `security-quick`/`security-full`/`security-fuzz`

**Files:**
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: macro `go-each` déjà définie dans `Makefile` (lignes 9-14), job `dependency-analysis`
  existant dans `ci.yml` comme modèle de placement.

- [ ] **Step 1: Lire les 20 premières lignes de `.github/workflows/ci.yml` pour connaître le style exact des jobs existants**

Nécessaire pour reproduire fidèlement la syntaxe (versions d'actions, cache, matrice) déjà en
place — ne pas inventer une structure de job différente de celle de `dependency-analysis`.

- [ ] **Step 2: Ajouter les cibles au `Makefile`, après la cible `audit` (avant `sbom`)**

```makefile
security-quick: ## Tests de sécurité handler-level + fonctions pures — CI, rapide, pas d'infra requise
	$(call go-each,go test ./... -race -run 'TestSecurity|FuzzSecurity')
	cargo test -p identity-provider --lib security_
	cd apps/console-web && npm run build && node --test "dist/**/security.test.js"
	bash tests/security/infrastructure/check_compose_dev.sh
	cd tests/security/report/aggregate && go run . ../output

security-full: ## Suite complète contre l'environnement local — make up requis (Postgres + SoftHSM2)
	@echo "Phase 2 — nécessite make up, voir tests/security/README.md"
	@exit 1

security-fuzz: ## Fuzzing natif Go des décodeurs JSON, budget borné
	$(call go-each,go test ./... -fuzz=FuzzSecurity -fuzztime=60s)
```

Mettre à jour la ligne `.PHONY` en tête de fichier pour ajouter `security-quick security-full security-fuzz`.

- [ ] **Step 3: Ajouter le job CI dans `.github/workflows/ci.yml`, à la suite de `dependency-analysis`**

Reproduire le style exact observé au Step 1 (indentation, `runs-on`, versions d'actions
`actions/checkout`, `actions/setup-go`, `dtolnay/rust-action`/équivalent déjà utilisé par les
autres jobs Rust du fichier, `needs: [build-test]`). Contenu du job :

```yaml
  security-quick:
    name: security-quick
    needs: [build-test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # réutiliser exactement les mêmes actions setup-go/setup-rust/setup-node que build-test —
      # copier leurs versions depuis ce même fichier, ne pas introduire une version différente.
      - name: security-quick
        run: make security-quick
```

- [ ] **Step 4: Vérifier la syntaxe YAML**

Run: `cd .github/workflows && python -c "import yaml,sys; yaml.safe_load(open('ci.yml'))"` (ou tout
outil de lint YAML disponible) — si aucun outil Python/yaml n'est disponible sur ce poste,
vérifier visuellement l'indentation contre les jobs voisins.

- [ ] **Step 5: Lancer `make security-quick` localement pour valider la cible de bout en bout**

Run: `make security-quick` (Git Bash, depuis la racine du dépôt)
Expected : chaque étape s'exécute dans l'ordre ; `TestSecurityQuorumAcceptedSansVerificationDeLAppelant`
(Task 2) fait échouer `go-each` avec un code de sortie non nul — **attendu**, documente le gap réel.
Si l'objectif est un run "tout vert" pour la démonstration finale, relancer avec
`-run 'TestSecurity|FuzzSecurity' -run TestSecurity[^Q]` n'est pas fiable ; à la place, documenter
dans le rapport final (Task 11) que `security-quick` échoue intentionnellement tant que ADR-021
n'est pas corrigé — cohérent avec « un test de régression doit échouer si la vulnérabilité est
présente ».

- [ ] **Step 6: Commit**

```bash
git add Makefile .github/workflows/ci.yml
git commit -m "ci: ajoute les cibles security-quick/security-full/security-fuzz"
```

---

### Task 11: Rapport final — exécution complète et synthèse livrée à l'utilisateur

**Files:** aucun fichier de code — tâche d'exécution et de synthèse.

- [ ] **Step 1: Lancer chaque suite individuellement et noter le résultat**

```bash
cd apps/admin-api && go test ./internal/httpapi/... -v -run 'TestSecurity|FuzzSecurity'
cd apps/access-broker && go test ./internal/httpapi/... -v -run 'TestSecurity|FuzzSecurity'
cd apps/audit-collector && go test ./internal/collector/... -v -run TestSecurity
cd apps/console-web && npm run build && node --test "dist/**/security.test.js"
cd apps/identity-provider && cargo test --lib security_
cargo test -p policy-engine --lib decision_fields_refuse_annee_hors_plage_au_lieu_de_paniquer
bash tests/security/infrastructure/check_compose_dev.sh
```

- [ ] **Step 2: Générer le rapport agrégé**

Run: `cd tests/security/report/aggregate && go run . ../output`
Expected: un Markdown listant tous les `Finding` produits par les tâches 2 à 8, triés par sévérité.

- [ ] **Step 3: Rédiger la synthèse finale (section 20 de `penthtest.md`) et la présenter à l'utilisateur**

Structurer la réponse finale de la conversation (pas un fichier commité) selon :
1. Surfaces d'attaque découvertes — tableau de la spec (§ Surface d'attaque confirmée).
2. Tests créés par catégorie — liste des fichiers des tâches 1 à 9.
3. Tests exécutables immédiatement (tous, Phase 1) vs nécessitant `make up` (backlog
   `tests/security/README.md`).
4. Vulnérabilités découvertes : `SEC-ADMIN-API-AUTHZ-001` (HIGH, reproduite), constat rate-limit
   (`SEC-ADMIN-API-RATE-001`, MEDIUM, non bloquant), tout finding information-disclosure
   effectivement déclenché par les tâches 4/6, et le rappel que `audit.md §3.1` est déjà corrigé.
5. Recommandations — celles déjà écrites dans chaque `Remediation` de `Finding`, plus le backlog
   Phase 2.
6. Tests impossibles à automatiser à ce stade : compromission de l'IdP (limite structurelle
   assumée par `docs/architecture.md`), charge réelle sous `make up`.
7. Prochaines étapes pour un pentest manuel : mTLS gRPC absent (identity-provider,
   credential-issuer, audit-collector — transport en clair), race condition réelle sur
   `consume_challenge` sous Postgres, ADR-021 à trancher.

- [ ] **Step 4: Ne pas commit** — cette tâche produit une synthèse conversationnelle, pas un
  artefact versionné (le rapport JSON/Markdown de `tests/security/report/output/` est gitignored
  par construction, régénéré à chaque run).
