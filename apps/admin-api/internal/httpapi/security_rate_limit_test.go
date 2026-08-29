package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

// TestSecurityAucunRateLimitSurQuorum constate (ne bloque pas la CI) l'absence de toute limitation
// de débit sur POST /v1/critical-operations/{id}/quorum — endpoint déjà sans vérification
// d'appelant (Task 2). Une rafale de requêtes malformées (seuil sous le plancher, refusé en 400)
// doit toutes réussir sans throttling ni ralentissement mesurable — sinon un mécanisme de
// limitation existe déjà et ce test doit être mis à jour pour le refléter.
func TestSecurityAucunRateLimitSurQuorum(t *testing.T) {
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		assertionAppelantValide: reponseAppelantValide(),
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(NewHandler(New(quorum.New(identity), identity, audit, domaineDeTest)))
	defer srv.Close()

	body, _ := json.Marshal(QuorumRequest{
		Assertions:              [][]byte{[]byte("assertion-a")},
		Threshold:               1, // sous le plancher — 400 rapide, pas de dépendance à identity-provider
		ExpectedAuthorityDomain: "identity-provider",
	})

	const burst = 200
	start := time.Now()
	success := 0
	for i := 0; i < burst; i++ {
		resp, err := postQuorum(srv.URL+"/v1/critical-operations/op-1/quorum", assertionAppelantValide, body)
		if err != nil {
			t.Fatalf("le serveur ne doit jamais planter sous rafale : %v", err)
		}
		if resp.StatusCode == http.StatusBadRequest {
			success++
		}
		resp.Body.Close()
	}
	elapsed := time.Since(start)

	finding := securityFinding{
		ID:        "SEC-ADMIN-API-RATE-001",
		Category:  "rate-limit",
		Severity:  "MEDIUM",
		Component: "POST /v1/critical-operations/{id}/quorum",
		Description: "Aucune limitation de débit — une rafale de requêtes non authentifiées " +
			"est traitée intégralement sans ralentissement ni rejet 429.",
		Payload:     "200 requêtes séquentielles, seuil sous le plancher (refus 400 attendu par requête)",
		Expected:    "un rate-limiter documenté rejetterait une partie de la rafale (429) ou introduirait un ralentissement mesurable",
		Obtained:    "toutes les requêtes traitées, aucun 429",
		Evidence:    "grep -ri ratelimit/limiter/throttle apps/ pkg/ → 0 résultat (constaté 2026-08-25)",
		Remediation: "Ajouter un middleware de limitation de débit (ex. token bucket par IP/porteur) avant les handlers HTTP non authentifiés",
		OWASP:       []string{"API4:2023 Unrestricted Resource Consumption"},
		CWE:         "CWE-770",
		Blocking:    false, // gap connu, non bloquant en Phase 1 — voir tests/security/README.md
	}
	if success != burst {
		finding.Obtained = "un rejet inattendu a interrompu la rafale — un mécanisme de protection existe peut-être déjà"
	}
	t.Logf("rafale de %d requêtes traitée en %s (aucune limitation détectée : %v)", burst, elapsed, success == burst)
	writeSecurityReport(t, []securityFinding{finding})
}
