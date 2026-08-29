package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
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

// securityReportMu sérialise les écritures : voir admin-api pour le détail.
var securityReportMu sync.Mutex

// writeSecurityReport fusionne findings dans tests/security/report/output/audit-collector.json.
// Fusion par ID plutôt qu'écrasement, et t.Logf plutôt que t.Fatalf sur erreur d'E/S — voir
// apps/admin-api/internal/httpapi/security_report_test.go pour la justification complète.
func writeSecurityReport(t *testing.T, findings []securityFinding) {
	t.Helper()
	securityReportMu.Lock()
	defer securityReportMu.Unlock()

	outDir, ok := securityReportDir(t)
	if !ok {
		return
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Logf("writeSecurityReport: impossible de créer %s : %v", outDir, err)
		return
	}
	outFile := filepath.Join(outDir, "audit-collector.json")

	var merged []securityFinding
	if existing, err := os.ReadFile(outFile); err == nil {
		if err := json.Unmarshal(existing, &merged); err != nil {
			t.Logf("writeSecurityReport: %s illisible, rapport réinitialisé : %v", outFile, err)
			merged = nil
		}
	}

	index := make(map[string]int, len(merged))
	for i, f := range merged {
		index[f.ID] = i
	}
	for _, f := range findings {
		if i, ok := index[f.ID]; ok {
			merged[i] = f
			continue
		}
		index[f.ID] = len(merged)
		merged = append(merged, f)
	}

	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		t.Logf("writeSecurityReport: marshal : %v", err)
		return
	}
	if err := os.WriteFile(outFile, data, 0o644); err != nil {
		t.Logf("writeSecurityReport: écriture : %v", err)
	}
}

// securityReportDir resout le dossier de rapport a partir de la racine du depot, identifiee par la
// presence de go.work en remontant depuis le repertoire courant.
//
// La version precedente comptait quatre ".." depuis le paquet : un deplacement du paquet d un seul
// niveau aurait fait creer silencieusement une arborescence tests/security/report/output HORS du
// depot, sans qu aucun test ne le signale. Ici, une racine introuvable est un echec explicite du
// test (t.Errorf) — refus par defaut plutot qu ecriture au mauvais endroit.
func securityReportDir(t *testing.T) (string, bool) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("securityReportDir: repertoire courant illisible : %v", err)
		return "", false
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return filepath.Join(dir, "tests", "security", "report", "output"), true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Errorf("securityReportDir: racine du depot introuvable (aucun go.work en remontant) — rapport non ecrit")
			return "", false
		}
		dir = parent
	}
}
