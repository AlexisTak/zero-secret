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

	// approvals est obligatoire : sans au moins une approbation verifiee, broker.Decide refuse
	// localement (approbation_verifiee_absente, internal/broker/broker.go:64) AVANT de consulter le
	// PDP — la reponse n aurait alors ni decision_hash ni policy_version a comparer, et le test ne
	// prouverait rien sur la non-influence du corps.
	// Corps JSON brut avec des champs qu'AccessRequestBody n'expose pas — tentative de mass
	// assignment vers une décision falsifiée.
	rawBody := []byte(`{
		"verb": "db.connect",
		"resource": {"type": "Database", "id": "db-prod", "authority_domain": "corp.eu-west"},
		"ticket_ref": "INC-1",
		"justification": "test",
		"expected_authority_domain": "corp.eu-west",
		"approvals": [{"assertion": "YXBwcm9iYXRpb24=", "approved_at": "2026-08-23T10:00:00Z"}],
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
		t.Fatal(`le champ "allowed":true injecté dans le corps n'aurait jamais dû influencer la décision (DENY attendu, signé par policy-engine)`)
	}
	if decision.DecisionHash == nil || string(*decision.DecisionHash) != string([]byte{0xAA, 0xBB}) {
		t.Fatalf("decision_hash doit provenir de policy-engine (0xAABB), pas du client : obtenu %v", decision.DecisionHash)
	}
	if decision.PolicyVersion == nil || *decision.PolicyVersion != "decision-binding/v1:reelle" {
		t.Fatalf("policy_version doit provenir de policy-engine, pas du champ falsifié par le client : obtenu %v", decision.PolicyVersion)
	}
}
