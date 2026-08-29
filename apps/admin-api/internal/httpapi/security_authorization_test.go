package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"

	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

// serveurQuorum monte un serveur avec la doublure identity fournie. Chaque test de ce fichier a
// besoin d'une doublure differente (appelant valide, invalide, AAL insuffisant, indisponible) :
// la construction est factorisee ici, jamais les reponses attendues.
func serveurQuorum(t *testing.T, identity identityv1.AssertionVerificationServiceClient) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(NewHandler(New(quorum.New(identity), identity, &fakeAuditClient{})))
	t.Cleanup(srv.Close)
	return srv
}

// corpsQuorumValide produit un corps dont les deux porteurs sont distincts et verifiables — seule
// l'authentification de l'appelant varie d'un test a l'autre.
func corpsQuorumValide() []byte {
	body, _ := json.Marshal(QuorumRequest{
		Assertions: [][]byte{
			[]byte("assertion-porteur-a"),
			[]byte("assertion-porteur-b"),
		},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: "identity-provider",
	})
	return body
}

// doublurePorteursValides accepte les deux porteurs, plus l'entree appelant fournie (nil pour un
// appelant inconnu du verificateur, donc refuse).
func doublurePorteursValides(appelant *identityv1.VerifyAssertionResponse) *fakeIdentityClient {
	reponses := map[string]*identityv1.VerifyAssertionResponse{
		"assertion-porteur-a": {Valid: true, SubjectId: "sub-porteur-1"},
		"assertion-porteur-b": {Valid: true, SubjectId: "sub-porteur-2"},
	}
	if appelant != nil {
		reponses[assertionAppelantValide] = appelant
	}
	return &fakeIdentityClient{responses: reponses}
}

// identityIndisponible simule une panne d'identity-provider : toute verification renvoie une
// erreur de transport.
type identityIndisponible struct {
	identityv1.AssertionVerificationServiceClient
}

func (identityIndisponible) VerifyAssertion(ctx context.Context, in *identityv1.VerifyAssertionRequest, opts ...grpc.CallOption) (*identityv1.VerifyAssertionResponse, error) {
	return nil, errors.New("identity-provider injoignable")
}

// TestSecurityQuorumExigeUnAppelantAuthentifie verrouille la correction d'ADR-021 (ADR-035) :
// avant cette correction, deux assertions de porteurs valides suffisaient a atteindre le quorum
// depuis un appelant anonyme — un attaquant qui obtenait deux assertions de porteurs, par rejeu ou
// par hameconnage, declenchait n'importe quelle operation critique sans jamais s'authentifier.
//
// Ce test etait rouge par conception tant que le handler n'exigeait rien de l'appelant ; il est
// desormais le verrou de non-regression de ce controle. Le finding SEC-ADMIN-API-AUTHZ-001 reste
// journalise en non bloquant : l'habilitation (QUEL role a le droit d'initier QUELLE operation)
// reste l'angle mort non tranche de security/threat-models/admin-api.md.
func TestSecurityQuorumExigeUnAppelantAuthentifie(t *testing.T) {
	cas := []struct {
		nom           string
		appelant      *identityv1.VerifyAssertionResponse
		enTete        string
		identity      identityv1.AssertionVerificationServiceClient
		statutAttendu int
		motifAttendu  string
	}{
		{
			nom:           "en-tete absent",
			appelant:      reponseAppelantValide(),
			enTete:        "",
			statutAttendu: http.StatusUnauthorized,
			motifAttendu:  "assertion_de_lappelant_absente",
		},
		{
			nom:           "assertion inconnue du verificateur",
			appelant:      nil, // l'entree appelant n'existe pas dans la doublure
			enTete:        assertionAppelantValide,
			statutAttendu: http.StatusUnauthorized,
			motifAttendu:  "assertion_de_lappelant_invalide",
		},
		{
			nom:           "assertion explicitement invalide",
			appelant:      &identityv1.VerifyAssertionResponse{Valid: false, Reason: "signature_invalide"},
			enTete:        assertionAppelantValide,
			statutAttendu: http.StatusUnauthorized,
			motifAttendu:  "assertion_de_lappelant_invalide",
		},
		{
			nom:           "niveau AAL2 insuffisant",
			appelant:      &identityv1.VerifyAssertionResponse{Valid: true, SubjectId: "sub-initiateur", Aal: "AAL2"},
			enTete:        assertionAppelantValide,
			statutAttendu: http.StatusForbidden,
			motifAttendu:  "niveau_dauthentification_insuffisant",
		},
		{
			nom:           "niveau AAL absent traite comme insuffisant",
			appelant:      &identityv1.VerifyAssertionResponse{Valid: true, SubjectId: "sub-initiateur"},
			enTete:        assertionAppelantValide,
			statutAttendu: http.StatusForbidden,
			motifAttendu:  "niveau_dauthentification_insuffisant",
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			srv := serveurQuorum(t, doublurePorteursValides(c.appelant))

			resp, err := postQuorum(srv.URL+"/v1/critical-operations/rotation-cle-hsm-prod/quorum", c.enTete, corpsQuorumValide())
			if err != nil {
				t.Fatalf("erreur inattendue : %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != c.statutAttendu {
				t.Fatalf("statut attendu %d, obtenu %d — le quorum ne doit jamais etre evalue pour un appelant refuse", c.statutAttendu, resp.StatusCode)
			}

			var erreur Error
			if err := json.NewDecoder(resp.Body).Decode(&erreur); err != nil {
				t.Fatalf("reponse d'erreur illisible : %v", err)
			}
			if erreur.Reason != c.motifAttendu {
				t.Fatalf("motif attendu %q, obtenu %q", c.motifAttendu, erreur.Reason)
			}
		})
	}
}

// TestSecurityQuorumRefuseSiVerificationAppelantIndisponible : refus par defaut (regle absolue
// #2). Une panne d'identity-provider ne doit jamais degrader le controle en acces libre — 502,
// jamais un quorum evalue sur un appelant non verifie.
func TestSecurityQuorumRefuseSiVerificationAppelantIndisponible(t *testing.T) {
	srv := serveurQuorum(t, identityIndisponible{})

	resp, err := postQuorum(srv.URL+"/v1/critical-operations/rotation-cle-hsm-prod/quorum", assertionAppelantValide, corpsQuorumValide())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("statut attendu 502 en cas d'indisponibilite du verificateur, obtenu %d", resp.StatusCode)
	}
}

// TestSecurityQuorumAppelantAAL3EstAccepte confirme que le controle ne casse pas le parcours
// nominal : un appelant AAL3 legitime obtient bien l'evaluation du quorum. Sans ce cas, les tests
// ci-dessus seraient satisfaits par un handler qui refuse tout le monde.
//
// Journalise SEC-ADMIN-API-AUTHZ-001 en non bloquant : la vulnerabilite d'authentification est
// fermee, l'habilitation reste ouverte.
func TestSecurityQuorumAppelantAAL3EstAccepte(t *testing.T) {
	srv := serveurQuorum(t, doublurePorteursValides(reponseAppelantValide()))

	resp, err := postQuorum(srv.URL+"/v1/critical-operations/rotation-cle-hsm-prod/quorum", assertionAppelantValide, corpsQuorumValide())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("un appelant AAL3 legitime doit obtenir 200, obtenu %d", resp.StatusCode)
	}

	var result QuorumResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("reponse illisible : %v", err)
	}
	if !result.Reached {
		t.Fatalf("quorum attendu atteint avec deux porteurs distincts, obtenu reached=false")
	}
	// L'initiateur ne doit jamais figurer parmi les porteurs comptes : sinon le quorum reel
	// tomberait a un seul porteur independant.
	for _, sujet := range result.DistinctSubjects {
		if sujet == "sub-initiateur" {
			t.Fatalf("le sujet de l'initiateur ne doit jamais etre compte dans le quorum : %v", result.DistinctSubjects)
		}
	}

	writeSecurityReport(t, []securityFinding{{
		ID:        "SEC-ADMIN-API-AUTHZ-001",
		Category:  "authorization",
		Severity:  "MEDIUM",
		Component: "POST /v1/critical-operations/{id}/quorum",
		Description: "L'appelant est desormais authentifie (assertion identity-assertion/v1, AAL3 " +
			"exige) avant toute evaluation du quorum. Reste ouvert : aucune verification que cet " +
			"appelant est HABILITE a declencher cette operation precise — la granularite des roles " +
			"reste l'angle mort non tranche d'ADR-021.",
		Payload:     "appelant AAL3 authentifie, sans lien demontre avec operation_id",
		Expected:    "a terme, refus si l'appelant n'a pas le role requis pour cette operation",
		Obtained:    "200 apres authentification de l'appelant — acces anonyme ferme, habilitation non verifiee",
		Evidence:    "apps/admin-api/internal/httpapi/handler.go (verifyCaller, ADR-035)",
		Remediation: "Trancher la granularite des roles d'administration, puis verifier l'habilitation de l'appelant sur operation_id",
		OWASP:       []string{"API1:2023 Broken Object Level Authorization"},
		CWE:         "CWE-862",
		Blocking:    false,
	}})
}
