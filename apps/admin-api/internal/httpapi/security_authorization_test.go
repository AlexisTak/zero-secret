package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

// TestSecurityQuorumAcceptedSansVerificationDeLAppelant reproduit ADR-021 (handler.go:5-8) :
// POST /v1/critical-operations/{id}/quorum accepte deux porteurs dont les assertions sont
// valides, mais SANS vérifier que l'appelant HTTP est habilité à déclencher CETTE opération —
// deux porteurs choisis au hasard par l'attaquant, non liés à operation_id, suffisent. Ce test
// documente le gap réel (déjà signalé dans le commentaire du handler) : il échoue tant que la
// vérification n'existe pas, ce qui est le comportement attendu de ce lot — voir
// tests/security/README.md pour la remédiation proposée (Phase 2).
func TestSecurityQuorumAcceptedSansVerificationDeLAppelant(t *testing.T) {
	identity := &fakeIdentityClient{responses: map[string]*identityv1.VerifyAssertionResponse{
		"assertion-attaquant-a": {Valid: true, SubjectId: "sub-inconnu-1"},
		"assertion-attaquant-b": {Valid: true, SubjectId: "sub-inconnu-2"},
	}}
	audit := &fakeAuditClient{}
	srv := httptest.NewServer(Handler(New(quorum.New(identity), audit)))
	defer srv.Close()

	body, _ := json.Marshal(QuorumRequest{
		Assertions: [][]byte{
			[]byte("assertion-attaquant-a"),
			[]byte("assertion-attaquant-b"),
		},
		Threshold:               quorum.MinimumThreshold,
		ExpectedAuthorityDomain: "identity-provider",
	})
	resp, err := http.Post(
		srv.URL+"/v1/critical-operations/rotation-cle-hsm-prod/quorum",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	defer resp.Body.Close()

	var result QuorumResult
	_ = json.NewDecoder(resp.Body).Decode(&result)

	finding := securityFinding{
		ID:        "SEC-ADMIN-API-AUTHZ-001",
		Category:  "authorization",
		Severity:  "HIGH",
		Component: "POST /v1/critical-operations/{id}/quorum",
		Description: "Aucune vérification que l'appelant HTTP est habilité à déclencher " +
			"l'opération critique operation_id — deux porteurs valides mais non liés à " +
			"l'opération suffisent à atteindre le quorum (ADR-021).",
		Payload: "2 assertions valides pour sub-inconnu-1/2, operation_id=rotation-cle-hsm-prod, " +
			"sans lien démontré avec cette opération",
		Expected:    "refus (403 ou équivalent) — l'appelant doit prouver son habilitation à initier cette opération",
		Remediation: "Exiger une assertion AAL3 de l'appelant HTTP lui-même, vérifiée avant tout appel à quorum.VerifyQuorum — voir tests/security/README.md",
		OWASP:       []string{"API1:2023 Broken Object Level Authorization"},
		CWE:         "CWE-862",
		Blocking:    true,
	}

	if resp.StatusCode == http.StatusOK && result.Reached {
		finding.Obtained = "200, reached=true — quorum atteint sans vérification d'habilitation"
		finding.Evidence = "apps/admin-api/internal/httpapi/handler.go:33-58 (VerifyQuorum, commentaire ADR-021 lignes 5-8)"
		writeSecurityReport(t, []securityFinding{finding})
		t.Fatalf(
			"vulnérabilité ADR-021 reproduite : quorum atteint (reached=%v, status=%d) sans "+
				"aucune vérification que l'appelant a le droit de déclencher operation_id — "+
				"voir tests/security/README.md pour la remédiation",
			result.Reached, resp.StatusCode,
		)
	}

	// Si ce test devient vert, la vérification d'habilitation a été ajoutée : verrouiller la
	// régression en confirmant explicitement le refus obtenu.
	finding.Obtained = "status inattendu ou reached=false — vérifier si une correction a été appliquée"
	finding.Blocking = false
	writeSecurityReport(t, []securityFinding{finding})
}
