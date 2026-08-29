package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

// TestSecurityMatriceEntreesMalformeesNeCrashePasEtNeFuitRien couvre la section « API » de
// penthtest.md : méthode incorrecte, champ manquant, type incorrect, JSON malformé, chaîne
// énorme, tableau énorme, Content-Type incorrect — sur POST /v1/critical-operations/{id}/quorum.
// Deux assertions systématiques : pas de panique (le serveur répond toujours), pas de fuite
// (jamais de stack trace, chemin filesystem, ou fragment ressemblant à un secret dans le corps).
func TestSecurityMatriceEntreesMalformeesNeCrashePasEtNeFuitRien(t *testing.T) {
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		assertionAppelantValide: reponseAppelantValide(),
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(NewHandler(New(quorum.New(identity), identity, audit, domaineDeTest)))
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
			// L'appelant est authentifie sur toute la matrice : on teste la robustesse du handler
			// lui-meme, pas le refus d'authentification deja couvert par le test d'autorisation.
			req.Header.Set("X-Identity-Assertion", base64.StdEncoding.EncodeToString([]byte(assertionAppelantValide)))

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("le serveur n'a pas répondu (crash possible) pour le cas %q : %v", tc.name, err)
			}
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			lower := strings.ToLower(string(respBody))

			// string(rune(92)) est la barre oblique inverse : un chemin Windows fuité commence par
			// c:\\users. Elle est construite plutot qu ecrite en litteral pour rester lisible
			// sans double echappement.
			leaks := []string{"panic", "goroutine", "runtime error", ".go:", "c:" + string(rune(92)) + "users", "/home/", "traceback"}
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
