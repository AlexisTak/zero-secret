package grpcapi

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	durationpb "google.golang.org/protobuf/types/known/durationpb"

	credentialv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/credential/v1"
	policyv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/policy/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/credential-issuer/internal/issuer"
)

// Doublures locales — même patron que internal/issuer (aucune crypto fabriquée côté Go).

type fakePolicyClient struct {
	policyv1.PolicyDecisionServiceClient
	verifyResp *policyv1.VerifyDecisionResponse
}

func (f *fakePolicyClient) VerifyDecision(ctx context.Context, in *policyv1.VerifyDecisionRequest, opts ...grpc.CallOption) (*policyv1.VerifyDecisionResponse, error) {
	return f.verifyResp, nil
}

type fakeLeaseIssuer struct {
	lease issuer.Lease
}

func (f *fakeLeaseIssuer) IssueLease(ctx context.Context, path string, params map[string]any) (issuer.Lease, error) {
	return f.lease, nil
}

func (f *fakeLeaseIssuer) Revoke(ctx context.Context, leaseID string) error {
	return nil
}

// startServer démarre un vrai serveur gRPC sur un port éphémère et retourne un client réel
// connecté dessus — round-trip réseau réel, seules les dépendances en aval (policy-engine,
// OpenBao) sont doublées.
func startServer(t *testing.T, iss *issuer.Issuer) credentialv1.CredentialIssuanceServiceClient {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("liaison : %v", err)
	}
	server := grpc.NewServer()
	credentialv1.RegisterCredentialIssuanceServiceServer(server, New(iss))
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("connexion client : %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return credentialv1.NewCredentialIssuanceServiceClient(conn)
}

func validOrder() *credentialv1.EmissionOrder {
	return &credentialv1.EmissionOrder{
		Verb:            "db.connect",
		ResourceType:    "Database",
		ResourceId:      "db-billing-prod",
		AuthorityDomain: "corp.eu-west",
		Decision: &policyv1.DecisionResponse{
			Effect:       policyv1.Effect_EFFECT_ALLOW,
			Reasons:      []string{"db-connect-production"},
			MaxTtl:       durationpb.New(900 * time.Second),
			DecisionHash: []byte{0xAB, 0xCD},
		},
	}
}

func TestEmissionValideRetourneLeBailViaLeReseau(t *testing.T) {
	policyClient := &fakePolicyClient{verifyResp: &policyv1.VerifyDecisionResponse{Valid: true}}
	leases := &fakeLeaseIssuer{lease: issuer.Lease{ID: "database/creds/readonly/abc123", LeaseDuration: 900 * time.Second}}
	iss := issuer.New(policyClient, leases, issuer.NewInMemoryConsumedDecisionStore())
	client := startServer(t, iss)

	resp, err := client.Emit(context.Background(), validOrder())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("attendu autorisé, raisons : %v", resp.Reasons)
	}
	if resp.LeaseId != "database/creds/readonly/abc123" {
		t.Fatalf("lease_id inattendu : %s", resp.LeaseId)
	}
	if resp.LeaseDuration.AsDuration() != 900*time.Second {
		t.Fatalf("lease_duration inattendue : %v", resp.LeaseDuration.AsDuration())
	}
}

func TestDecisionInvalideEstRefuseeSansErreurGRPC(t *testing.T) {
	policyClient := &fakePolicyClient{verifyResp: &policyv1.VerifyDecisionResponse{Valid: false, Reason: "signature_invalide"}}
	leases := &fakeLeaseIssuer{}
	iss := issuer.New(policyClient, leases, issuer.NewInMemoryConsumedDecisionStore())
	client := startServer(t, iss)

	resp, err := client.Emit(context.Background(), validOrder())
	if err != nil {
		t.Fatalf("un refus métier ne doit jamais être une erreur gRPC : %v", err)
	}
	if resp.Allowed {
		t.Fatal("attendu refusé")
	}
}

func TestRejeuDeLaMemeDecisionEstRefuseViaLeReseau(t *testing.T) {
	policyClient := &fakePolicyClient{verifyResp: &policyv1.VerifyDecisionResponse{Valid: true}}
	leases := &fakeLeaseIssuer{lease: issuer.Lease{ID: "lease-1", LeaseDuration: time.Minute}}
	iss := issuer.New(policyClient, leases, issuer.NewInMemoryConsumedDecisionStore())
	client := startServer(t, iss)

	first, err := client.Emit(context.Background(), validOrder())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !first.Allowed {
		t.Fatalf("attendu autorisé au premier appel, raisons : %v", first.Reasons)
	}

	second, err := client.Emit(context.Background(), validOrder())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if second.Allowed {
		t.Fatal("le rejeu de la même décision ne doit jamais réussir")
	}
}

func TestRevokePropageAuClientOpenBao(t *testing.T) {
	policyClient := &fakePolicyClient{}
	leases := &fakeLeaseIssuer{}
	iss := issuer.New(policyClient, leases, issuer.NewInMemoryConsumedDecisionStore())
	client := startServer(t, iss)

	if _, err := client.Revoke(context.Background(), &credentialv1.RevokeRequest{LeaseId: "lease-1"}); err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
}
