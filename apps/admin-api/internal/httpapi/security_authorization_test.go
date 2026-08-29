package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"

	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

// serveurQuorum monte un serveur avec la doublure identity fournie. Chaque test de ce fichier a
// besoin d'une doublure differente (appelant valide, invalide, AAL insuffisant, indisponible) :
// la construction est factorisee ici, jamais les reponses attendues.
func serveurQuorum(t *testing.T, identity identityv1.AssertionVerificationServiceClient) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(NewHandler(New(quorum.New(identity), identity, &fakeAuditClient{}, domaineDeTest)))
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

// serveurQuorumAvecAudit expose la doublure d'audit, pour les tests qui verifient le journal.
func serveurQuorumAvecAudit(t *testing.T, identity identityv1.AssertionVerificationServiceClient) (*httptest.Server, *fakeAuditClient) {
	t.Helper()
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(NewHandler(New(quorum.New(identity), identity, audit, domaineDeTest)))
	t.Cleanup(srv.Close)
	return srv, audit
}

// TestSecurityInitiateurNestJamaisComptePorteur est le cas d'attaque du quorum auto-approuve :
// Alice se declare initiatrice ET place sa propre assertion parmi les porteurs, avec celle de Bob.
// Sans exclusion, DistinctSubjects = {Alice, Bob} atteint un seuil de 2 alors qu'un SEUL
// approbateur est reellement independant de celle qui declenche — la lettre du plancher
// MinimumThreshold serait respectee, son intention non.
func TestSecurityInitiateurNestJamaisComptePorteur(t *testing.T) {
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		// Meme sujet pour l'en-tete et pour l'un des porteurs : Alice joue les deux roles.
		assertionAppelantValide:   {Valid: true, SubjectId: "sub-alice", Aal: "AAL3", AuthMethod: "webauthn/device-bound"},
		"assertion-porteur-alice": {Valid: true, SubjectId: "sub-alice"},
		"assertion-porteur-b":     {Valid: true, SubjectId: "sub-porteur-2"},
	}}
	srv := serveurQuorum(t, identity)

	body, _ := json.Marshal(QuorumRequest{
		Assertions: [][]byte{
			[]byte("assertion-porteur-alice"),
			[]byte("assertion-porteur-b"),
		},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: domaineDeTest,
	})

	resp, err := postQuorum(srv.URL+"/v1/critical-operations/rotation-cle-hsm-prod/quorum", assertionAppelantValide, body)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	var result QuorumResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("reponse illisible : %v", err)
	}
	if result.Reached {
		t.Fatalf("quorum atteint avec un seul approbateur independant de l'initiatrice : %v", result.DistinctSubjects)
	}
	for _, sujet := range result.DistinctSubjects {
		if sujet == "sub-alice" {
			t.Fatalf("le sujet de l'initiatrice ne doit jamais figurer parmi les porteurs comptes : %v", result.DistinctSubjects)
		}
	}
}

// TestSecurityAssertionAppelantNonBase64EstRefusee : l'en-tete est declare base64 au contrat, comme
// les assertions du corps. Un decodage a repli (base64 sinon brut) ferait exister deux
// representations de la meme entree — confusion de requete, et journalisation contournable.
func TestSecurityAssertionAppelantNonBase64EstRefusee(t *testing.T) {
	identity := doublurePorteursValides(reponseAppelantValide())
	srv := serveurQuorum(t, identity)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/critical-operations/op-1/quorum", bytes.NewReader(corpsQuorumValide()))
	if err != nil {
		t.Fatalf("construction requete : %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Octets bruts, non encodes : exactement ce que la version precedente transmettait au
	// verificateur, et ce qu'un client conforme au contrat n'envoie jamais.
	req.Header.Set("X-Identity-Assertion", "assertion-en-clair-pas-base64!!")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("attendu 401 pour une assertion mal encodee, obtenu %d", resp.StatusCode)
	}
	var erreur Error
	if err := json.NewDecoder(resp.Body).Decode(&erreur); err != nil {
		t.Fatalf("reponse d'erreur illisible : %v", err)
	}
	if erreur.Reason != "assertion_de_lappelant_malformee" {
		t.Fatalf("motif attendu assertion_de_lappelant_malformee, obtenu %q", erreur.Reason)
	}
}

// TestSecurityDomaineDautoriteNestPasChoisiParLappelant : le domaine contre lequel les assertions
// sont verifiees vient de la configuration. Le laisser choisir par le corps rendrait le controle
// tautologique des qu'un identity-provider accepte plus d'un domaine.
func TestSecurityDomaineDautoriteNestPasChoisiParLappelant(t *testing.T) {
	srv := serveurQuorum(t, doublurePorteursValides(reponseAppelantValide()))

	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-porteur-a"), []byte("assertion-porteur-b")},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: "domaine-choisi-par-lattaquant",
	})

	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, body)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attendu 400 pour un domaine d'autorite non configure, obtenu %d", resp.StatusCode)
	}
}

// TestSecurityNombreDassertionsEstBorne : chaque assertion declenche un appel gRPC sortant. Une
// liste non bornee amplifierait une requete unique en autant d'appels vers identity-provider.
func TestSecurityNombreDassertionsEstBorne(t *testing.T) {
	srv := serveurQuorum(t, doublurePorteursValides(reponseAppelantValide()))

	trop := make([][]byte, maxAssertions+1)
	for i := range trop {
		trop[i] = []byte("assertion-porteur-a")
	}
	body, _ := json.Marshal(QuorumRequest{
		Assertions:              trop,
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: domaineDeTest,
	})

	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, body)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attendu 400 au-dela de %d assertions, obtenu %d", maxAssertions, resp.StatusCode)
	}
}

// TestSecurityCorpsNonAuthentifieEstBorne : le corps est decode avant l'authentification (le
// domaine attendu et le seuil en dependent), donc la borne doit s'appliquer a un anonyme.
func TestSecurityCorpsNonAuthentifieEstBorne(t *testing.T) {
	srv := serveurQuorum(t, doublurePorteursValides(reponseAppelantValide()))

	enorme := make([]byte, maxOctetsCorps+1024)
	for i := range enorme {
		enorme[i] = 'a'
	}
	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{enorme},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: domaineDeTest,
	})

	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, body)
	if err != nil {
		t.Fatalf("le serveur ne doit jamais planter sur un corps surdimensionne : %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("attendu 400 pour un corps au-dela de %d octets, obtenu %d", maxOctetsCorps, resp.StatusCode)
	}
}

// TestSecurityEvenementInitiateurEstDistinguableDesPorteurs : sans aal/auth_method sur l'acteur,
// les N+1 evenements d'une meme operation sont identiques en forme, et un auditeur — ou zs-replay
// (ADR-034) — compte un approbateur de trop.
func TestSecurityEvenementInitiateurEstDistinguableDesPorteurs(t *testing.T) {
	srv, audit := serveurQuorumAvecAudit(t, doublurePorteursValides(reponseAppelantValide()))

	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, corpsQuorumValide())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	var initiateurs, porteurs int
	for _, req := range audit.reqs {
		if req.Actor == nil {
			t.Fatalf("evenement sans acteur : %v", req)
		}
		if req.Actor.Aal != nil && req.Actor.AuthMethod != nil {
			initiateurs++
			if req.Actor.SubjectId != "sub-initiateur" {
				t.Fatalf("l'evenement porteur aal/auth_method doit etre celui de l'initiateur, obtenu %s", req.Actor.SubjectId)
			}
			continue
		}
		porteurs++
	}
	if initiateurs != 1 {
		t.Fatalf("attendu exactement 1 evenement d'initiateur distinguable, obtenu %d", initiateurs)
	}
	if porteurs != 2 {
		t.Fatalf("attendu 2 evenements de porteurs, obtenu %d", porteurs)
	}
}

// identityLent simule un verificateur qui accepte la connexion et ne repond jamais : il attend
// l'expiration du contexte. C'est le cas que l'erreur de transport ne couvre pas — sans echeance,
// le handler resterait bloque jusqu'a deconnexion du client, dont l'attaquant tient les deux bouts.
type identityLent struct {
	identityv1.AssertionVerificationServiceClient
}

func (identityLent) VerifyAssertion(ctx context.Context, in *identityv1.VerifyAssertionRequest, opts ...grpc.CallOption) (*identityv1.VerifyAssertionResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestSecurityVerificateurLentEstTraiteCommeUnePanne : une lenteur indistinguable d'une panne doit
// produire le meme refus qu'une panne (regle absolue #2). Sans echeance, ce test ne terminerait
// jamais dans le temps imparti au paquet.
func TestSecurityVerificateurLentEstTraiteCommeUnePanne(t *testing.T) {
	srv := serveurQuorum(t, identityLent{})

	debut := time.Now()
	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, corpsQuorumValide())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("attendu 502 sur verificateur muet, obtenu %d", resp.StatusCode)
	}
	if ecoule := time.Since(debut); ecoule > delaiTraitement {
		t.Fatalf("le refus doit survenir dans le budget de la requete (%s), obtenu %s", delaiTraitement, ecoule)
	}
}

// TestSecurityReponseDeVerificateurIncompleteEstRefusee : le contrat declare subject_id et
// auth_method presents seulement si valid = true. Une reponse valide mais incomplete est un
// verificateur qui ne respecte pas son contrat, pas une identite — l'accepter produirait un
// evenement d'audit sans acteur exploitable et une cle d'exclusion vide.
func TestSecurityReponseDeVerificateurIncompleteEstRefusee(t *testing.T) {
	cas := []struct {
		nom      string
		appelant *identityv1.VerifyAssertionResponse
	}{
		{"subject_id vide", &identityv1.VerifyAssertionResponse{Valid: true, Aal: "AAL3", AuthMethod: "webauthn/device-bound"}},
		{"auth_method vide", &identityv1.VerifyAssertionResponse{Valid: true, Aal: "AAL3", SubjectId: "sub-initiateur"}},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			srv := serveurQuorum(t, doublurePorteursValides(c.appelant))

			resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, corpsQuorumValide())
			if err != nil {
				t.Fatalf("erreur inattendue : %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("attendu 502 pour une reponse de verificateur incomplete, obtenu %d", resp.StatusCode)
			}
		})
	}
}

// TestSecurityExclusionDeLinitiateurEstAuditee : filtrer l'initiateur sans le journaliser
// effacerait la tentative d'auto-approbation. Le resultat audite serait indiscernable d'une
// requete ou l'initiateur n'aurait soumis aucune assertion de porteur, et une campagne
// d'auto-approbation deviendrait indetectable a posteriori.
func TestSecurityExclusionDeLinitiateurEstAuditee(t *testing.T) {
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		assertionAppelantValide:   {Valid: true, SubjectId: "sub-alice", Aal: "AAL3", AuthMethod: "webauthn/device-bound"},
		"assertion-porteur-alice": {Valid: true, SubjectId: "sub-alice"},
		"assertion-porteur-b":     {Valid: true, SubjectId: "sub-porteur-2"},
	}}
	srv, audit := serveurQuorumAvecAudit(t, identity)

	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-porteur-alice"), []byte("assertion-porteur-b")},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: domaineDeTest,
	})

	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, body)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	var trace bool
	for _, req := range audit.reqs {
		if req.Context != nil && req.Context.Justification != nil && *req.Context.Justification != "" {
			trace = true
		}
	}
	if !trace {
		t.Fatal("l'exclusion de l'assertion de porteur de l'initiateur doit laisser une trace au journal")
	}
}

// TestSecurityRequeteNominaleNeJournalisePasDexclusion : verrou du test precedent. Sans lui, un
// handler qui poserait la justification a chaque requete passerait aussi.
func TestSecurityRequeteNominaleNeJournalisePasDexclusion(t *testing.T) {
	srv, audit := serveurQuorumAvecAudit(t, doublurePorteursValides(reponseAppelantValide()))

	resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, corpsQuorumValide())
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	for _, req := range audit.reqs {
		if req.Context != nil && req.Context.Justification != nil {
			t.Fatalf("aucune exclusion n'a eu lieu, le journal ne doit pas en signaler une : %q", *req.Context.Justification)
		}
	}
}
