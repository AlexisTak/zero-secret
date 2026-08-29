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

	// Le code de sortie 1 est attendu ici : les fixtures contiennent des findings bloquants, et
	// l agregateur porte desormais la decision bloquante (voir
	// TestSecurityAggregateSortEnErreurSiFindingBloquant). Seule la sortie Markdown est verifiee.
	out, _ := exec.Command("go", "run", ".", dir).CombinedOutput()
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

// TestSecurityAggregateSortEnErreurSiFindingBloquant verrouille le contrat de code de sortie :
// c est lui, et non un grep sur la mise en forme du JSON, qui fait echouer make security-quick.
// Sans ce test, un passage de MarshalIndent a Marshal (ou un changement d indentation) pourrait
// neutraliser silencieusement le portail bloquant.
func TestSecurityAggregateSortEnErreurSiFindingBloquant(t *testing.T) {
	cas := []struct {
		nom      string
		findings []finding
		veutCode int
	}{
		{"aucun finding", nil, 0},
		{"finding non bloquant", []finding{{ID: "RATE-1", Severity: "MEDIUM", Blocking: false}}, 0},
		{"finding bloquant", []finding{{ID: "AUTHZ-1", Severity: "HIGH", Blocking: true}}, 1},
		{"melange", []finding{{ID: "RATE-1", Blocking: false}, {ID: "AUTHZ-1", Blocking: true}}, 1},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			dir := t.TempDir()
			data, err := json.Marshal(c.findings)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "module.json"), data, 0o644); err != nil {
				t.Fatalf("ecriture: %v", err)
			}

			cmd := exec.Command("go", "run", ".", dir)
			out, err := cmd.CombinedOutput()
			code := cmd.ProcessState.ExitCode()
			if code != c.veutCode {
				t.Fatalf("code de sortie attendu %d, obtenu %d (err=%v) :\n%s", c.veutCode, code, err, out)
			}
		})
	}
}
