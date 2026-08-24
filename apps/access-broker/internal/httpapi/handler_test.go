package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"

	auditv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/audit/v1"
	credentialv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/credential/v1"
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

type fakeCredentialClient struct {
	credentialv1.CredentialIssuanceServiceClient
	response *credentialv1.EmissionResult
	err      error
	called   bool
	lastReq  *credentialv1.EmissionOrder
}

func (f *fakeCredentialClient) Emit(ctx context.Context, in *credentialv1.EmissionOrder, opts ...grpc.CallOption) (*credentialv1.EmissionResult, error) {
	f.called = true
	f.lastReq = in
	if f.err != nil {
		return nil, f.err
	}
	return f.response, nil
}

type fakeAuditClient struct {
	auditv1.AuditCollectionServiceClient
	called  bool
	lastReq *auditv1.RawEvent
	err     error
}

func (f *fakeAuditClient) Record(ctx context.Context, in *auditv1.RawEvent, opts ...grpc.CallOption) (*auditv1.RecordResult, error) {
	f.called = true
	f.lastReq = in
	if f.err != nil {
		return nil, f.err
	}
	return &auditv1.RecordResult{Accepted: true, EventId: "evt-1", Sequence: 0}, nil
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
	credential := &fakeCredentialClient{}
	policy := &fakePolicyClient{}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(identity, credential, audit, broker.New(policy, identity))))
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
	credential := &fakeCredentialClient{}
	policy := &fakePolicyClient{}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(identity, credential, audit, broker.New(policy, identity))))
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
	credential := &fakeCredentialClient{response: &credentialv1.EmissionResult{
		Allowed: true,
		LeaseId: "database/creds/readonly/abc123",
	}}
	policy := &fakePolicyClient{response: &policyv1.DecisionResponse{
		Effect:       policyv1.Effect_EFFECT_ALLOW,
		Reasons:      []string{"db-connect-production"},
		DecisionHash: []byte{0x01, 0x02},
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(identity, credential, audit, broker.New(policy, identity))))
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
	if !credential.called {
		t.Fatal("credential-issuer aurait dû être appelé pour une décision ALLOW")
	}
	if decision.LeaseId == nil || *decision.LeaseId != "database/creds/readonly/abc123" {
		t.Fatalf("lease_id inattendu : %v", decision.LeaseId)
	}
	if !audit.called {
		t.Fatal("policy.decided aurait dû être envoyé à audit-collector (PDP consulté)")
	}
	if audit.lastReq.Outcome != "success" {
		t.Fatalf("outcome inattendu : %s", audit.lastReq.Outcome)
	}
	if audit.lastReq.Decision == nil || audit.lastReq.Decision.RequestId == "" {
		t.Fatal("decision.request_id attendu, non vide")
	}
	if len(audit.lastReq.Decision.DecisionHash) == 0 {
		t.Fatal("decision.decision_hash attendu")
	}
}

func TestEmissionEchoueeNinvalidePasLaDecisionMaisOmetLeBail(t *testing.T) {
	identity := &fakeIdentityClient{valid: true, subjectID: "sub-demandeur"}
	credential := &fakeCredentialClient{err: errors.New("openbao indisponible")}
	policy := &fakePolicyClient{response: &policyv1.DecisionResponse{
		Effect:       policyv1.Effect_EFFECT_ALLOW,
		Reasons:      []string{"db-connect-production"},
		DecisionHash: []byte{0x01, 0x02},
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(identity, credential, audit, broker.New(policy, identity))))
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
		t.Fatalf("un échec d'émission ne doit jamais invalider la décision : attendu 200, reçu %d", resp.StatusCode)
	}

	var decision Decision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		t.Fatalf("réponse JSON invalide : %v", err)
	}
	if !decision.Allowed {
		t.Fatal("attendu autorisé malgré l'échec d'émission")
	}
	if decision.LeaseId != nil {
		t.Fatalf("lease_id ne doit pas être présent quand l'émission a échoué, reçu : %v", *decision.LeaseId)
	}
}

func TestEmissionNestJamaisDeclencheeSurUnRefus(t *testing.T) {
	identity := &fakeIdentityClient{valid: true, subjectID: "sub-demandeur"}
	credential := &fakeCredentialClient{}
	policy := &fakePolicyClient{response: &policyv1.DecisionResponse{
		Effect:  policyv1.Effect_EFFECT_DENY,
		Reasons: []string{"politique_refusee"},
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(identity, credential, audit, broker.New(policy, identity))))
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

	if credential.called {
		t.Fatal("credential-issuer ne doit jamais être appelé pour une décision refusée")
	}
	if !audit.called {
		t.Fatal("policy.decided doit être audité même sur un refus du PDP (ADR-027)")
	}
	if audit.lastReq.Outcome != "denied" {
		t.Fatalf("outcome inattendu : %s", audit.lastReq.Outcome)
	}
}

func TestPolicyDecidedNestJamaisEnvoyeSurUnRefusLocalAvantLePDP(t *testing.T) {
	identity := &fakeIdentityClient{valid: true, subjectID: "sub-demandeur"}
	credential := &fakeCredentialClient{}
	policy := &fakePolicyClient{response: &policyv1.DecisionResponse{Effect: policyv1.Effect_EFFECT_ALLOW}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(identity, credential, audit, broker.New(policy, identity))))
	defer srv.Close()

	longBody := validBody()
	longBody.Justification = string(make([]byte, broker.MaxJustificationLength+1))

	body, _ := json.Marshal(longBody)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/access-requests", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Identity-Assertion", base64.StdEncoding.EncodeToString([]byte("assertion-du-demandeur")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	if audit.called {
		t.Fatal("un refus local avant tout appel au PDP n'a pas de décision à auditer")
	}
}

func TestEchecDauditCollectorNinvalidePasLaReponseHTTP(t *testing.T) {
	identity := &fakeIdentityClient{valid: true, subjectID: "sub-demandeur"}
	credential := &fakeCredentialClient{response: &credentialv1.EmissionResult{Allowed: true, LeaseId: "lease-1"}}
	policy := &fakePolicyClient{response: &policyv1.DecisionResponse{
		Effect:       policyv1.Effect_EFFECT_ALLOW,
		Reasons:      []string{"db-connect-production"},
		DecisionHash: []byte{0x01, 0x02},
	}}
	audit := &fakeAuditClient{err: errors.New("audit-collector indisponible")}
	srv := httptest.NewServer(Handler(New(identity, credential, audit, broker.New(policy, identity))))
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
		t.Fatalf("une panne d'audit-collector ne doit jamais invalider la réponse HTTP : attendu 200, reçu %d", resp.StatusCode)
	}
	if !audit.called {
		t.Fatal("audit-collector aurait dû être appelé (même si sa réponse échoue)")
	}
}

func TestCorpsMalformeEstRefuse400(t *testing.T) {
	identity := &fakeIdentityClient{valid: true, subjectID: "sub-demandeur"}
	credential := &fakeCredentialClient{}
	policy := &fakePolicyClient{}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(identity, credential, audit, broker.New(policy, identity))))
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
