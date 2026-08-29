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

			// string(rune(92)) est la barre oblique inverse : un chemin Windows fuité commence par
			// c:\users. Elle est construite plutôt qu'écrite en littéral pour rester lisible sans
			// double échappement.
			for _, l := range []string{"panic", "goroutine", "runtime error", ".go:", "c:" + string(rune(92)) + "users", "/home/"} {
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
