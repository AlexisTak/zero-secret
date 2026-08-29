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
