package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"

	identityv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/identity/v1"
	policyv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/policy/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/access-broker/internal/broker"
)

// Doublures locales — même patron que internal/broker (aucune crypto fabriquée côté Go).

type fakeIdentityClient struct {
	identityv1.AssertionVerificationServiceClient
	valid      bool
	subjectID  string
	aal        string
	authMethod string
	err        error
}

func (f *fakeIdentityClient) VerifyAssertion(ctx context.Context, in *identityv1.VerifyAssertionRequest, opts ...grpc.CallOption) (*identityv1.VerifyAssertionResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	if !f.valid {
		return &identityv1.VerifyAssertionResponse{Valid: false, Reason: "signature_invalide"}, nil
	}
	return &identityv1.VerifyAssertionResponse{Valid: true, SubjectId: f.subjectID, Aal: f.aal, AuthMethod: f.authMethod}, nil
}

type fakePolicyClient struct {
	policyv1.PolicyDecisionServiceClient
	response *policyv1.DecisionResponse
}

func (f *fakePolicyClient) Decide(ctx context.Context, in *policyv1.DecisionRequest, opts ...grpc.CallOption) (*policyv1.DecisionResponse, error) {
	return f.response, nil
}

func fixedTime() time.Time {
	return time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)
}

func validBody() AccessRequestBody {
	return AccessRequestBody{
		Verb: "db.connect",
		Resource: Resource{
			Type:            "Database",
			Id:              "db-billing-prod",
			AuthorityDomain: "corp.eu-west",
		},
		TicketRef:               "INC-1",
		Justification:           "correctif",
		ExpectedAuthorityDomain: "corp.eu-west",
		Approvals: &[]Approval{
			{Assertion: []byte("approbation"), ApprovedAt: fixedTime()},
		},
	}
}

func TestAssertionDuDemandeurAbsenteEstRefuseeSans401(t *testing.T) {
	identity := &fakeIdentityClient{}
	policy := &fakePolicyClient{}
	srv := httptest.NewServer(Handler(New(identity, broker.New(policy, identity))))
	defer srv.Close()

	body, _ := json.Marshal(validBody())
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/access-requests", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Pas d'en-tête X-Identity-Assertion.

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attendu 400 (en-tête requis manquant), reçu %d", resp.StatusCode)
	}
}

func TestAssertionDuDemandeurInvalideEstRefusee401AvantAppelAuPDP(t *testing.T) {
	identity := &fakeIdentityClient{valid: false}
	policy := &fakePolicyClient{}
	srv := httptest.NewServer(Handler(New(identity, broker.New(policy, identity))))
	defer srv.Close()

	body, _ := json.Marshal(validBody())
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/access-requests", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Identity-Assertion", base64.StdEncoding.EncodeToString([]byte("assertion-du-demandeur")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("attendu 401, reçu %d", resp.StatusCode)
	}

	var errResp Error
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Reason == "" {
		t.Fatal("attendu une raison de refus explicite")
	}
}

func TestRequeteValideRetourneLaDecisionDuPDP(t *testing.T) {
	identity := &fakeIdentityClient{valid: true, subjectID: "sub-demandeur", aal: "AAL3", authMethod: "webauthn/device-bound"}
	policy := &fakePolicyClient{response: &policyv1.DecisionResponse{
		Effect:       policyv1.Effect_EFFECT_ALLOW,
		Reasons:      []string{"db-connect-production"},
		DecisionHash: []byte{0x01, 0x02},
	}}
	srv := httptest.NewServer(Handler(New(identity, broker.New(policy, identity))))
	defer srv.Close()

	body, _ := json.Marshal(validBody())
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/access-requests", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Identity-Assertion", base64.StdEncoding.EncodeToString([]byte("assertion-du-demandeur")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attendu 200, reçu %d", resp.StatusCode)
	}

	var decision Decision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		t.Fatalf("réponse JSON invalide : %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("attendu autorisé, raisons : %v", decision.Reasons)
	}
	if len(decision.Reasons) != 1 || decision.Reasons[0] != "db-connect-production" {
		t.Fatalf("raisons inattendues : %v", decision.Reasons)
	}
}

func TestCorpsMalformeEstRefuse400(t *testing.T) {
	identity := &fakeIdentityClient{valid: true, subjectID: "sub-demandeur"}
	policy := &fakePolicyClient{}
	srv := httptest.NewServer(Handler(New(identity, broker.New(policy, identity))))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/access-requests", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Identity-Assertion", base64.StdEncoding.EncodeToString([]byte("assertion-du-demandeur")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attendu 400, reçu %d", resp.StatusCode)
	}
}
