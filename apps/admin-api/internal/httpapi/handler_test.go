package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"

	auditv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/audit/v1"
	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
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

type fakeAuditClient struct {
	auditv1.AuditCollectionServiceClient
	reqs []*auditv1.RawEvent
}

func (f *fakeAuditClient) Record(ctx context.Context, in *auditv1.RawEvent, opts ...grpc.CallOption) (*auditv1.RecordResult, error) {
	f.reqs = append(f.reqs, in)
	return &auditv1.RecordResult{Accepted: true, EventId: "evt-1"}, nil
}

func TestDeuxPorteursDistinctsAtteignentLeQuorumViaHTTP(t *testing.T) {
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		assertionAppelantValide: reponseAppelantValide(),
		"assertion-a":           {Valid: true, SubjectId: "sub-1"},
		"assertion-b":           {Valid: true, SubjectId: "sub-2"},
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(NewHandler(New(quorum.New(identity), identity, audit, domaineDeTest)))
	defer srv.Close()

	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-a"), []byte("assertion-b")},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: "identity-provider",
	})
	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, body)
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
	// 2 porteurs + 1 initiateur : depuis ADR-035, l'appelant qui declenche l'operation est audite
	// lui aussi, avec le meme type d'evenement (le schema n'a qu'un champ actor, le modifier
	// casserait la verifiabilite de l'historique). Sans cet evenement, le journal dirait QUI a
	// approuve mais jamais QUI a declenche.
	if len(audit.reqs) != 3 {
		t.Fatalf("attendu un quorum.operation par porteur distinct (2) plus un pour l'initiateur, reçu %d", len(audit.reqs))
	}
	for _, req := range audit.reqs {
		if req.EventType != "quorum.operation" {
			t.Fatalf("event_type inattendu : %s", req.EventType)
		}
		if req.Outcome != "success" {
			t.Fatalf("outcome inattendu : %s", req.Outcome)
		}
		if req.Target == nil || req.Target.Id != "op-1" {
			t.Fatalf("target.id inattendu : %v", req.Target)
		}
		// sub-initiateur est l'appelant qui a declenche l'operation (ADR-035) ; sub-1/sub-2 sont
		// les porteurs. Les trois evenements portent le meme type et la meme cible, seul l'acteur
		// change — c'est ce qui permet de reconstituer qui a demande et qui a approuve.
		if req.Actor == nil || (req.Actor.SubjectId != "sub-1" && req.Actor.SubjectId != "sub-2" && req.Actor.SubjectId != "sub-initiateur") {
			t.Fatalf("actor.subject_id inattendu : %v", req.Actor)
		}
	}
}

func TestUnSeulPorteurEstRefuseViaHTTP(t *testing.T) {
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		assertionAppelantValide: reponseAppelantValide(),
		"assertion-a":           {Valid: true, SubjectId: "sub-1"},
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(NewHandler(New(quorum.New(identity), identity, audit, domaineDeTest)))
	defer srv.Close()

	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-a")},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: "identity-provider",
	})
	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, body)
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
	// 1 porteur verifie + 1 initiateur (ADR-035) — l'initiateur est audite meme quand le quorum
	// est refuse : une tentative de declenchement est un fait a tracer autant qu'un succes.
	if len(audit.reqs) != 2 {
		t.Fatalf("attendu un quorum.operation pour le porteur vérifié plus un pour l'initiateur (même quorum non atteint), reçu %d", len(audit.reqs))
	}
	if audit.reqs[0].Outcome != "denied" {
		t.Fatalf("outcome inattendu : %s (le quorum global n'est pas atteint)", audit.reqs[0].Outcome)
	}
}

func TestSeuilInferieurAuPlancherEstRefuse400ParHTTPPasUnCrash(t *testing.T) {
	// L'appelant doit etre verifiable meme ici : depuis ADR-035, l'authentification precede
	// l'evaluation du seuil, donc un appelant inconnu renverrait 401 avant que le plancher
	// de quorum ne soit atteint — ce n'est pas ce que ce test mesure.
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		assertionAppelantValide: reponseAppelantValide(),
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(NewHandler(New(quorum.New(identity), identity, audit, domaineDeTest)))
	defer srv.Close()

	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-a")},
		Threshold:               1, // sous le plancher — quorum.VerifyQuorum panique en interne
		ExpectedAuthorityDomain: "identity-provider",
	})
	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, body)
	if err != nil {
		t.Fatalf("le serveur ne doit jamais planter sur cette requête : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attendu 400, reçu %d", resp.StatusCode)
	}
	// Propriete verifiee ISOLEMENT, avant le second appel : un refus survenu avant toute
	// evaluation du quorum ne produit AUCUN evenement. La verifier seulement sur le total agrege
	// des deux appels laisserait passer un audit emis a tort sur ce chemin.
	if len(audit.reqs) != 0 {
		t.Fatalf("aucun quorum.operation attendu pour un refus avant évaluation, reçu %d", len(audit.reqs))
	}

	// Le serveur doit rester utilisable après ce refus — vérifié en renvoyant une requête valide.
	body2, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-a")},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: "identity-provider",
	})
	resp2, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, body2)
	if err != nil {
		t.Fatalf("le serveur devrait toujours répondre après le refus précédent : %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("attendu 200 après récupération, reçu %d", resp2.StatusCode)
	}
	// Premier appel (seuil sous le plancher) : refuse avant toute evaluation, aucun evenement.
	// Second appel (seuil valide) : aucun porteur n'est verifiable ("assertion-a" n'a pas de
	// reponse configuree), mais l'initiateur, lui, a bien ete authentifie — son evenement est
	// emis. Une tentative de declenchement par un appelant identifie est un fait a tracer, meme
	// quand aucun porteur ne suit (ADR-035).
	if len(audit.reqs) != 1 {
		t.Fatalf("attendu le seul quorum.operation de l'initiateur (aucun porteur vérifié), reçu %d", len(audit.reqs))
	}
	if audit.reqs[0].Actor == nil || audit.reqs[0].Actor.SubjectId != "sub-initiateur" {
		t.Fatalf("le seul événement attendu est celui de l'initiateur, reçu %v", audit.reqs[0].Actor)
	}
}

func TestCorpsMalformeEstRefuse400(t *testing.T) {
	identity := &fakeIdentityClient{}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(NewHandler(New(quorum.New(identity), identity, audit, domaineDeTest)))
	defer srv.Close()

	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, []byte("{not json"))
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attendu 400, reçu %d", resp.StatusCode)
	}
}

// assertionAppelantValide est l'entree a ajouter aux doublures identity pour que l'APPELANT
// (X-Identity-Assertion, ADR-035) soit accepte. Distincte des assertions de porteurs : initiateur
// et porteur sont deux roles, et le sujet de l'initiateur n'est jamais compte dans le quorum.
// domaineDeTest est le domaine d'autorite epingle des API de test : depuis ADR-035, un corps qui
// en propose un autre est refuse en 400, le domaine n'etant plus choisi par l'appelant.
const domaineDeTest = "identity-provider"

// assertionAppelantValide est l'assertion de l'APPELANT telle que la voit le verificateur, donc
// DECODEE. postQuorum l'encode en base64 avant de la poser dans l'en-tete : depuis que le contrat
// declare le parametre en format: byte, c'est le binding genere qui la redecode, plus le handler.
const assertionAppelantValide = "assertion-appelant-aal3"

func reponseAppelantValide() *identityv1.VerifyAssertionResponse {
	return &identityv1.VerifyAssertionResponse{
		Valid:      true,
		SubjectId:  "sub-initiateur",
		Aal:        "AAL3",
		AuthMethod: "webauthn/device-bound",
	}
}

// postQuorum envoie une requete de quorum avec l'assertion d'appelant fournie. Une chaine vide
// omet l'en-tete, ce qui doit produire un refus 401 (jamais un acces anonyme).
func postQuorum(url, assertionAppelant string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if assertionAppelant != "" {
		req.Header.Set("X-Identity-Assertion", base64.StdEncoding.EncodeToString([]byte(assertionAppelant)))
	}
	return http.DefaultClient.Do(req)
}
