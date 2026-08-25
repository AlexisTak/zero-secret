package quorum

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"
)

// fakeClient répond selon l'octet de l'assertion (convention de test simple : assertion[0]
// identifie le porteur simulé) — pas de crypto fabriquée côté Go, cohérent avec la limite
// structurelle déjà documentée en L2.3/L2.4.
type fakeClient struct {
	// responses[assertionKey] -> réponse à retourner pour cette assertion.
	responses map[string]*identityv1.VerifyAssertionResponse
	err       error
	callCount int
}

func (f *fakeClient) VerifyAssertion(ctx context.Context, in *identityv1.VerifyAssertionRequest, opts ...grpc.CallOption) (*identityv1.VerifyAssertionResponse, error) {
	f.callCount++
	if f.err != nil {
		return nil, f.err
	}
	resp, ok := f.responses[string(in.Assertion)]
	if !ok {
		return &identityv1.VerifyAssertionResponse{Valid: false, Reason: "assertion_de_test_inconnue"}, nil
	}
	return resp, nil
}

func TestUnSeulPorteurNePeutJamaisDeclencherMemeAvecPlusieursAssertions(t *testing.T) {
	// Critère d'acceptation exact du backlog : deux assertions du MÊME subject_id (rejouées ou
	// simplement soumises deux fois) n'atteignent jamais le quorum.
	client := &fakeClient{
		responses: map[string]*identityv1.VerifyAssertionResponse{
			"assertion-a": {Valid: true, SubjectId: "sub-1"},
			"assertion-b": {Valid: true, SubjectId: "sub-1"}, // même porteur, assertion distincte
		},
	}
	v := New(client)

	result, err := v.VerifyQuorum(context.Background(), "identity-provider",
		[][]byte{[]byte("assertion-a"), []byte("assertion-b")}, MinimumThreshold)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if result.Reached {
		t.Fatal("un seul porteur ne doit jamais atteindre le quorum")
	}
	if len(result.DistinctSubjects) != 1 {
		t.Fatalf("attendu 1 porteur distinct, reçu %d", len(result.DistinctSubjects))
	}
}

func TestDeuxPorteursDistinctsAtteignentLeQuorum(t *testing.T) {
	client := &fakeClient{
		responses: map[string]*identityv1.VerifyAssertionResponse{
			"assertion-a": {Valid: true, SubjectId: "sub-1"},
			"assertion-b": {Valid: true, SubjectId: "sub-2"},
		},
	}
	v := New(client)

	result, err := v.VerifyQuorum(context.Background(), "identity-provider",
		[][]byte{[]byte("assertion-a"), []byte("assertion-b")}, MinimumThreshold)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !result.Reached {
		t.Fatal("deux porteurs distincts vérifiés doivent atteindre le quorum")
	}
	if len(result.DistinctSubjects) != 2 {
		t.Fatalf("attendu 2 porteurs distincts, reçu %d", len(result.DistinctSubjects))
	}
}

func TestAssertionInvalideEstIgnoreeSansAnnulerLesAutres(t *testing.T) {
	client := &fakeClient{
		responses: map[string]*identityv1.VerifyAssertionResponse{
			"assertion-a": {Valid: true, SubjectId: "sub-1"},
			"assertion-b": {Valid: true, SubjectId: "sub-2"},
			"assertion-c": {Valid: false, Reason: "signature_invalide"},
		},
	}
	v := New(client)

	result, err := v.VerifyQuorum(context.Background(), "identity-provider",
		[][]byte{[]byte("assertion-a"), []byte("assertion-b"), []byte("assertion-c")}, MinimumThreshold)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if !result.Reached {
		t.Fatal("les deux porteurs valides suffisent malgré l'assertion invalide")
	}
	if len(result.DistinctSubjects) != 2 {
		t.Fatalf("attendu 2 porteurs distincts, reçu %d", len(result.DistinctSubjects))
	}
}

func TestQuorumInsuffisantEstRefuse(t *testing.T) {
	client := &fakeClient{
		responses: map[string]*identityv1.VerifyAssertionResponse{
			"assertion-a": {Valid: true, SubjectId: "sub-1"},
		},
	}
	v := New(client)

	result, err := v.VerifyQuorum(context.Background(), "identity-provider",
		[][]byte{[]byte("assertion-a")}, MinimumThreshold)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if result.Reached {
		t.Fatal("un seul porteur ne doit jamais atteindre un seuil de 2")
	}
}

func TestSeuilInferieurAuPlancherPanique(t *testing.T) {
	client := &fakeClient{}
	v := New(client)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("attendu une panique pour threshold < MinimumThreshold")
		}
	}()
	_, _ = v.VerifyQuorum(context.Background(), "identity-provider", nil, 1)
}

func TestEchecDeTransportEstUneErreurGoPasUnRefusMetier(t *testing.T) {
	client := &fakeClient{err: errors.New("connexion refusée")}
	v := New(client)

	_, err := v.VerifyQuorum(context.Background(), "identity-provider", [][]byte{[]byte("assertion-a")}, MinimumThreshold)
	if err == nil {
		t.Fatal("attendu une erreur de transport, pas un Result")
	}
}
