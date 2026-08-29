package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
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

// securityReportMu sérialise les écritures du rapport : plusieurs fichiers de test du même paquet
// (authorization, rate-limit, matrice API) écrivent le même fichier. Aucun de ces tests n'appelle
// t.Parallel() aujourd'hui, mais un ajout futur transformerait sinon la séquence lecture/fusion/
// écriture en course sur le système de fichiers.
var securityReportMu sync.Mutex

// writeSecurityReport fusionne findings dans tests/security/report/output/admin-api.json — chemin
// relatif calculé depuis ce fichier (apps/admin-api/internal/httpapi -> 4 niveaux jusqu'à la
// racine du dépôt).
//
// La fusion se fait par ID et non par écrasement : les tests de sécurité de ce paquet sont
// répartis sur plusieurs fichiers, et Go les exécute dans l'ordre alphabétique des fichiers — une
// simple écriture ferait perdre au rapport final tous les findings sauf ceux du dernier fichier
// exécuté, y compris un finding bloquant. Un ID déjà présent est remplacé (idempotent quand un
// test est relancé seul via -run), un ID nouveau est ajouté à la fin.
//
// N'échoue jamais le test sur une erreur d'E/S : t.Logf, pas t.Fatalf — un rapport manquant ou un
// fichier existant illisible ne doit jamais faire échouer artificiellement un test de sécurité
// par ailleurs correct, ni empêcher d'écrire les findings du run courant.
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
	outFile := filepath.Join(outDir, "admin-api.json")

	var merged []securityFinding
	if existing, err := os.ReadFile(outFile); err == nil {
		if err := json.Unmarshal(existing, &merged); err != nil {
			// Rapport précédent corrompu ou tronqué : on repart d'un rapport vide plutôt que de
			// perdre les findings du run courant.
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
