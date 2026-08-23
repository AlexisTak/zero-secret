package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"

	identityv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/identity/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/admin-api/internal/quorum"
)

type fakeIdentityClient struct {
	identityv1.AssertionVerificationServiceClient
	responses map[string]*identityv1.VerifyAssertionResponse
}

func (f *fakeIdentityClient) VerifyAssertion(ctx context.Context, in *identityv1.VerifyAssertionRequest, opts ...grpc.CallOption) (*identityv1.VerifyAssertionResponse, error) {
	if resp, ok := f.responses[string(in.Assertion)]; ok {
		return resp, nil
	}
	return &identityv1.VerifyAssertionResponse{Valid: false, Reason: "assertion_de_test_inconnue"}, nil
}

func TestDeuxPorteursDistinctsAtteignentLeQuorumViaHTTP(t *testing.T) {
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		"assertion-a": {Valid: true, SubjectId: "sub-1"},
		"assertion-b": {Valid: true, SubjectId: "sub-2"},
	}}
	srv := httptest.NewServer(Handler(New(quorum.New(identity))))
	defer srv.Close()

	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-a"), []byte("assertion-b")},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: "identity-provider",
	})
	resp, err := http.Post(srv.URL+"/v1/critical-operations/op-1/quorum", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attendu 200, reçu %d", resp.StatusCode)
	}

	var result QuorumResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("réponse JSON invalide : %v", err)
	}
	if !result.Reached {
		t.Fatal("attendu quorum atteint")
	}
	if len(result.DistinctSubjects) != 2 {
		t.Fatalf("attendu 2 porteurs distincts, reçu %d", len(result.DistinctSubjects))
	}
}

func TestUnSeulPorteurEstRefuseViaHTTP(t *testing.T) {
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		"assertion-a": {Valid: true, SubjectId: "sub-1"},
	}}
	srv := httptest.NewServer(Handler(New(quorum.New(identity))))
	defer srv.Close()

	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-a")},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: "identity-provider",
	})
	resp, err := http.Post(srv.URL+"/v1/critical-operations/op-1/quorum", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attendu 200 (le quorum non atteint n'est pas une erreur), reçu %d", resp.StatusCode)
	}

	var result QuorumResult
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result.Reached {
		t.Fatal("un seul porteur ne doit jamais atteindre le quorum")
	}
}

func TestSeuilInferieurAuPlancherEstRefuse400ParHTTPPasUnCrash(t *testing.T) {
	identity := &fakeIdentityClient{}
	srv := httptest.NewServer(Handler(New(quorum.New(identity))))
	defer srv.Close()

	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-a")},
		Threshold:               1, // sous le plancher — quorum.VerifyQuorum panique en interne
		ExpectedAuthorityDomain: "identity-provider",
	})
	resp, err := http.Post(srv.URL+"/v1/critical-operations/op-1/quorum", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("le serveur ne doit jamais planter sur cette requête : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attendu 400, reçu %d", resp.StatusCode)
	}

	// Le serveur doit rester utilisable après ce refus — vérifié en renvoyant une requête valide.
	body2, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-a")},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: "identity-provider",
	})
	resp2, err := http.Post(srv.URL+"/v1/critical-operations/op-1/quorum", "application/json", bytes.NewReader(body2))
	if err != nil {
		t.Fatalf("le serveur devrait toujours répondre après le refus précédent : %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("attendu 200 après récupération, reçu %d", resp2.StatusCode)
	}
}

func TestCorpsMalformeEstRefuse400(t *testing.T) {
	identity := &fakeIdentityClient{}
	srv := httptest.NewServer(Handler(New(quorum.New(identity))))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/critical-operations/op-1/quorum", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attendu 400, reçu %d", resp.StatusCode)
	}
}
