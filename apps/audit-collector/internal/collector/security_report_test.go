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

	outDir := filepath.Join("..", "..", "..", "..", "tests", "security", "report", "output")
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
