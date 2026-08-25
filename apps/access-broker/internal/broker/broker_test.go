package broker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"
	policyv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/policy/v1"
)

// fakePolicyClient / fakeIdentityClient : doublures locales, aucun réseau. Un test Go ne peut ni
// ne doit fabriquer de matériel cryptographique lui-même (tools/lib/check-no-direct-crypto.sh
// interdit tout import crypto Go direct, sans exemption de test — contrairement à Rust) : un test
// d'intégration réel (vrais serveurs policy-engine/identity-provider, vraie assertion signée)
// n'est donc pas faisable depuis ce module sans violer cette frontière. Documenté ici plutôt
// qu'improvisé — voir ADR-017.

type fakePolicyClient struct {
	// Interface complète embarquée (champ anonyme) : ce double n'implémente que Decide() ci-
	// dessous, mais reste compatible avec toute méthode ajoutée plus tard à l'interface générée
	// (ex. VerifyDecision, H4) sans que ce fichier n'ait besoin d'être mis à jour à chaque fois —
	// régression réelle découverte à la fusion du lot L2 (ce test compilait seul mais plus une
	// fois assemblé avec H4 dans le même module resolution) ; même patron déjà utilisé dans
	// apps/credential-issuer/internal/issuer (L2.4).
	policyv1.PolicyDecisionServiceClient
	response *policyv1.DecisionResponse
	err      error
	called   bool
	lastReq  *policyv1.DecisionRequest
}

func (f *fakePolicyClient) Decide(ctx context.Context, in *policyv1.DecisionRequest, opts ...grpc.CallOption) (*policyv1.DecisionResponse, error) {
	f.called = true
	f.lastReq = in
	if f.err != nil {
		return nil, f.err
	}
	return f.response, nil
}

type fakeIdentityClient struct {
	// responses est consommée dans l'ordre des appels — un test par approbation attendue.
	responses []*identityv1.VerifyAssertionResponse
	err       error
	callCount int
}

func (f *fakeIdentityClient) VerifyAssertion(ctx context.Context, in *identityv1.VerifyAssertionRequest, opts ...grpc.CallOption) (*identityv1.VerifyAssertionResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	resp := f.responses[f.callCount]
	f.callCount++
	return resp, nil
}

func validRequest() AccessRequest {
	return AccessRequest{
		RequestID: "req-1",
		Principal: Principal{
			SubjectID:       "sub-1",
			AAL:             "AAL3",
			AuthMethod:      "webauthn/device-bound",
			AuthenticatedAt: time.Now(),
			AuthorityDomain: "corp.eu-west",
		},
		Verb: "db.connect",
		Resource: Resource{
			Type:            "Database",
			ID:              "db-billing-prod",
			AuthorityDomain: "corp.eu-west",
			Attributes:      map[string]string{"environment": "production"},
		},
		TicketRef:               "INC-1",
		Justification:           "correctif",
		ExpectedAuthorityDomain: "identity-provider",
		Approvals: []RawApproval{
			{Assertion: []byte("assertion-de-test"), ApprovedAt: time.Now()},
		},
	}
}

func TestJustificationTropLongueEstRefuseeAvantToutAppelReseau(t *testing.T) {
	policyClient := &fakePolicyClient{}
	identityClient := &fakeIdentityClient{}
	b := New(policyClient, identityClient)

	req := validRequest()
	req.Justification = strings.Repeat("a", MaxJustificationLength+1)

	decision, err := b.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if decision.Allowed {
		t.Fatal("attendu refusé")
	}
	if len(decision.Reasons) != 1 || decision.Reasons[0] != "justification_trop_longue" {
		t.Fatalf("raison inattendue : %v", decision.Reasons)
	}
	if policyClient.called {
		t.Fatal("le PDP ne doit jamais être appelé pour ce refus")
	}
}

func TestAucuneApprobationVerifieeEstRefuseeAvantAppelAuPDP(t *testing.T) {
	policyClient := &fakePolicyClient{}
	identityClient := &fakeIdentityClient{
		responses: []*identityv1.VerifyAssertionResponse{
			{Valid: false, Reason: "signature_invalide"},
		},
	}
	b := New(policyClient, identityClient)

	decision, err := b.Decide(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if decision.Allowed {
		t.Fatal("attendu refusé")
	}
	if len(decision.Reasons) != 1 || decision.Reasons[0] != "approbation_verifiee_absente" {
		t.Fatalf("raison inattendue : %v", decision.Reasons)
	}
	if policyClient.called {
		t.Fatal("le PDP ne doit jamais être appelé sans approbation vérifiée")
	}
}

func TestDemandeSansApprobationFournieEstRefuseeAvantAppelAuPDP(t *testing.T) {
	policyClient := &fakePolicyClient{}
	identityClient := &fakeIdentityClient{}
	b := New(policyClient, identityClient)

	req := validRequest()
	req.Approvals = nil

	decision, err := b.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if decision.Allowed {
		t.Fatal("attendu refusé")
	}
	if policyClient.called {
		t.Fatal("le PDP ne doit jamais être appelé sans approbation")
	}
}

func TestApprobationValideDeclencheReellementLappelAuPDP(t *testing.T) {
	policyClient := &fakePolicyClient{
		response: &policyv1.DecisionResponse{
			Effect:        policyv1.Effect_EFFECT_ALLOW,
			Reasons:       []string{"db-connect-production"},
			DecisionHash:  []byte{0x01, 0x02},
			PolicyVersion: "decision-binding/v1:abc",
		},
	}
	identityClient := &fakeIdentityClient{
		responses: []*identityv1.VerifyAssertionResponse{
			{Valid: true, SubjectId: "sub-approbateur", Aal: "AAL3"},
		},
	}
	b := New(policyClient, identityClient)

	decision, err := b.Decide(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !policyClient.called {
		t.Fatal("le PDP aurait dû être appelé")
	}
	if !decision.Allowed {
		t.Fatalf("attendu autorisé, raisons : %v", decision.Reasons)
	}
	if len(decision.Reasons) != 1 || decision.Reasons[0] != "db-connect-production" {
		t.Fatalf("raisons inattendues : %v", decision.Reasons)
	}
	if string(decision.DecisionHash) != "\x01\x02" {
		t.Fatalf("decision_hash inattendu : %v", decision.DecisionHash)
	}
	if decision.PolicyVersion != "decision-binding/v1:abc" {
		t.Fatalf("policy_version inattendue : %s", decision.PolicyVersion)
	}

	// L'approbation transmise au PDP porte le subject_id VÉRIFIÉ par identity-provider, jamais
	// une valeur déclarée par l'appelant.
	if len(policyClient.lastReq.Context.Approvals) != 1 {
		t.Fatalf("nombre d'approbations transmises inattendu : %d", len(policyClient.lastReq.Context.Approvals))
	}
	if policyClient.lastReq.Context.Approvals[0].ApproverId != "sub-approbateur" {
		t.Fatalf("approver_id inattendu : %s", policyClient.lastReq.Context.Approvals[0].ApproverId)
	}
}

func TestApprobationInvalideEstIgnoreeSansAnnulerLesAutres(t *testing.T) {
	policyClient := &fakePolicyClient{
		response: &policyv1.DecisionResponse{Effect: policyv1.Effect_EFFECT_ALLOW},
	}
	identityClient := &fakeIdentityClient{
		responses: []*identityv1.VerifyAssertionResponse{
			{Valid: false, Reason: "signature_invalide"},
			{Valid: true, SubjectId: "sub-2", Aal: "AAL3"},
		},
	}
	b := New(policyClient, identityClient)

	req := validRequest()
	req.Approvals = []RawApproval{
		{Assertion: []byte("invalide"), ApprovedAt: time.Now()},
		{Assertion: []byte("valide"), ApprovedAt: time.Now()},
	}

	decision, err := b.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !policyClient.called {
		t.Fatal("une approbation valide suffit à atteindre le PDP")
	}
	if len(policyClient.lastReq.Context.Approvals) != 1 {
		t.Fatalf("seule l'approbation valide doit être transmise, reçu : %d", len(policyClient.lastReq.Context.Approvals))
	}
	_ = decision
}

func TestChampRequisAbsentEstRefuse(t *testing.T) {
	policyClient := &fakePolicyClient{}
	identityClient := &fakeIdentityClient{}
	b := New(policyClient, identityClient)

	req := validRequest()
	req.Principal.SubjectID = ""

	decision, err := b.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if decision.Allowed {
		t.Fatal("attendu refusé")
	}
	if policyClient.called {
		t.Fatal("le PDP ne doit jamais être appelé")
	}
}

func TestEchecDeTransportEstUneErreurGoPasUnRefusMetier(t *testing.T) {
	policyClient := &fakePolicyClient{}
	identityClient := &fakeIdentityClient{err: errors.New("connexion refusée")}
	b := New(policyClient, identityClient)

	_, err := b.Decide(context.Background(), validRequest())
	if err == nil {
		t.Fatal("attendu une erreur de transport, pas une Decision")
	}
}
