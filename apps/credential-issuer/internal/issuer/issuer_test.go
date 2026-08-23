package issuer

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	durationpb "google.golang.org/protobuf/types/known/durationpb"

	policyv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/policy/v1"
)

// fakePolicyClient satisfait policyv1.PolicyDecisionServiceClient — seule VerifyDecision est
// utilisée par ce paquet ; les autres méthodes de l'interface ne sont jamais appelées ici.
type fakePolicyClient struct {
	policyv1.PolicyDecisionServiceClient
	verifyResp *policyv1.VerifyDecisionResponse
	verifyErr  error
	called     bool
}

func (f *fakePolicyClient) VerifyDecision(ctx context.Context, in *policyv1.VerifyDecisionRequest, opts ...grpc.CallOption) (*policyv1.VerifyDecisionResponse, error) {
	f.called = true
	if f.verifyErr != nil {
		return nil, f.verifyErr
	}
	return f.verifyResp, nil
}

type fakeLeaseIssuer struct {
	lease      Lease
	issueErr   error
	called     bool
	lastPath   string
	lastParams map[string]any
	revokeErr  error
}

func (f *fakeLeaseIssuer) IssueLease(ctx context.Context, path string, params map[string]any) (Lease, error) {
	f.called = true
	f.lastPath = path
	f.lastParams = params
	if f.issueErr != nil {
		return Lease{}, f.issueErr
	}
	return f.lease, nil
}

func (f *fakeLeaseIssuer) Revoke(ctx context.Context, leaseID string) error {
	return f.revokeErr
}

func validOrder() EmissionOrder {
	return EmissionOrder{
		Verb:            "db.connect",
		ResourceType:    "Database",
		ResourceID:      "db-billing-prod",
		AuthorityDomain: "corp.eu-west",
		Decision: &policyv1.DecisionResponse{
			Effect:                 policyv1.Effect_EFFECT_ALLOW,
			Reasons:                []string{"db-connect-production"},
			MaxTtl:                 durationpb.New(900 * time.Second),
			DecisionHash:           []byte{0xAB, 0xCD},
			PolicyVersion:          "decision-binding/v1:abc",
			DecisionSignature:      []byte{0x01},
			DecisionSignatureKeyId: "key-1",
		},
	}
}

func TestDecisionAbsenteEstRefuseeAvantToutAppel(t *testing.T) {
	policyClient := &fakePolicyClient{}
	leases := &fakeLeaseIssuer{}
	iss := New(policyClient, leases)

	result, err := iss.Emit(context.Background(), EmissionOrder{})
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if result.Allowed {
		t.Fatal("attendu refusé")
	}
	if policyClient.called || leases.called {
		t.Fatal("aucun appel réseau ne doit avoir lieu sans décision")
	}
}

func TestDecisionInvalideEstRefuseeAvantAppelOpenBao(t *testing.T) {
	policyClient := &fakePolicyClient{
		verifyResp: &policyv1.VerifyDecisionResponse{Valid: false, Reason: "signature_invalide"},
	}
	leases := &fakeLeaseIssuer{}
	iss := New(policyClient, leases)

	result, err := iss.Emit(context.Background(), validOrder())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if result.Allowed {
		t.Fatal("attendu refusé")
	}
	if !policyClient.called {
		t.Fatal("la décision aurait dû être vérifiée")
	}
	if leases.called {
		t.Fatal("OpenBao ne doit jamais être appelé sans décision valide")
	}
}

func TestEffectDenyEstRefuseSansAppelOpenBao(t *testing.T) {
	policyClient := &fakePolicyClient{verifyResp: &policyv1.VerifyDecisionResponse{Valid: true}}
	leases := &fakeLeaseIssuer{}
	iss := New(policyClient, leases)

	order := validOrder()
	order.Decision.Effect = policyv1.Effect_EFFECT_DENY

	result, err := iss.Emit(context.Background(), order)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if result.Allowed {
		t.Fatal("attendu refusé")
	}
	if leases.called {
		t.Fatal("OpenBao ne doit jamais être appelé pour une décision DENY")
	}
}

func TestVerbeNonSupporteEstRefuse(t *testing.T) {
	policyClient := &fakePolicyClient{verifyResp: &policyv1.VerifyDecisionResponse{Valid: true}}
	leases := &fakeLeaseIssuer{}
	iss := New(policyClient, leases)

	order := validOrder()
	order.Verb = "ssh.session"

	result, err := iss.Emit(context.Background(), order)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if result.Allowed {
		t.Fatal("attendu refusé")
	}
	if leases.called {
		t.Fatal("OpenBao ne doit jamais être appelé pour un verbe non supporté")
	}
}

func TestEmissionValideAppelleOpenBaoAvecLeTTLDeLaDecision(t *testing.T) {
	policyClient := &fakePolicyClient{verifyResp: &policyv1.VerifyDecisionResponse{Valid: true}}
	leases := &fakeLeaseIssuer{lease: Lease{ID: "database/creds/readonly/abc123", LeaseDuration: 900 * time.Second}}
	iss := New(policyClient, leases)

	result, err := iss.Emit(context.Background(), validOrder())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !result.Allowed {
		t.Fatalf("attendu autorisé, raisons : %v", result.Reasons)
	}
	if !leases.called {
		t.Fatal("OpenBao aurait dû être appelé")
	}
	if leases.lastPath != "database/creds/db-billing-prod" {
		t.Fatalf("chemin OpenBao inattendu : %s", leases.lastPath)
	}
	if leases.lastParams["ttl_seconds"] != int64(900) {
		t.Fatalf("TTL transmis inattendu : %v (attendu celui de la décision, jamais une valeur alternative)", leases.lastParams["ttl_seconds"])
	}
	if result.LeaseID != "database/creds/readonly/abc123" {
		t.Fatalf("LeaseID inattendu : %s", result.LeaseID)
	}
	if result.Event.EventID == "" {
		t.Fatal("l'identifiant d'événement (R7) doit être généré")
	}
	if string(result.Event.DecisionHash) != "\xAB\xCD" {
		t.Fatalf("decision_hash de l'événement inattendu : %v", result.Event.DecisionHash)
	}
	if result.Event.GrantedTTLSeconds != 900 {
		t.Fatalf("granted_ttl_seconds inattendu : %d", result.Event.GrantedTTLSeconds)
	}
}

func TestEchecOpenBaoEstUneErreurGoPasUnRefusMetier(t *testing.T) {
	policyClient := &fakePolicyClient{verifyResp: &policyv1.VerifyDecisionResponse{Valid: true}}
	leases := &fakeLeaseIssuer{issueErr: errors.New("openbao indisponible")}
	iss := New(policyClient, leases)

	_, err := iss.Emit(context.Background(), validOrder())
	if err == nil {
		t.Fatal("attendu une erreur de transport, pas une Decision")
	}
}

func TestRevokePropageLerreurDuClientOpenBao(t *testing.T) {
	policyClient := &fakePolicyClient{}
	wantErr := errors.New("openbao indisponible")
	leases := &fakeLeaseIssuer{revokeErr: wantErr}
	iss := New(policyClient, leases)

	if err := iss.Revoke(context.Background(), "some-lease"); !errors.Is(err, wantErr) {
		t.Fatalf("attendu %v, reçu %v", wantErr, err)
	}
}
