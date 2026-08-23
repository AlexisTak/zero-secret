// Package httpapi expose apps/access-broker/internal/broker en HTTP (contracts/openapi/
// access-broker.yaml) — première entrée réseau réelle de ce composant. api_generated.go est
// généré (DO NOT EDIT) ; ce fichier porte la logique.
//
// Authentification : le demandeur transmet son assertion identity-assertion/v1 dans l'en-tête
// X-Identity-Assertion (base64), vérifiée via identity-provider (H3) AVANT toute construction de
// broker.AccessRequest — jamais un champ "principal" accepté depuis le corps JSON, qui serait un
// contournement trivial de l'authentification.
//
// Pas de TLS dans ce lot — signalé, jamais un déploiement de production sans (même limite que
// policy-engine/identity-provider, L2.2/H3).
package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	identityv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/identity/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/access-broker/internal/broker"
)

type API struct {
	identityClient identityv1.AssertionVerificationServiceClient
	broker         *broker.Broker
}

func New(identityClient identityv1.AssertionVerificationServiceClient, b *broker.Broker) *API {
	return &API{identityClient: identityClient, broker: b}
}

func (h *API) CreateAccessRequest(w http.ResponseWriter, r *http.Request, params CreateAccessRequestParams) {
	ctx := r.Context()

	var body AccessRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "corps_de_requete_malforme")
		return
	}

	// Authentification du demandeur — jamais un champ "principal" du corps, toujours l'assertion
	// vérifiée de l'en-tête. Refus explicite avant toute construction de requête ou appel au PDP.
	verifyResp, err := h.identityClient.VerifyAssertion(ctx, &identityv1.VerifyAssertionRequest{
		Assertion:               params.XIdentityAssertion,
		ExpectedAuthorityDomain: body.ExpectedAuthorityDomain,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "verification_du_demandeur_indisponible")
		return
	}
	if !verifyResp.Valid {
		writeError(w, http.StatusUnauthorized, "assertion_du_demandeur_invalide:"+verifyResp.Reason)
		return
	}

	requestID, err := uuid.NewV7()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generation_de_lidentifiant_de_requete")
		return
	}

	req := broker.AccessRequest{
		RequestID: requestID.String(),
		Principal: broker.Principal{
			SubjectID:       verifyResp.SubjectId,
			AAL:             verifyResp.Aal,
			AuthMethod:      verifyResp.AuthMethod,
			AuthenticatedAt: time.Now().UTC(), // instant de la vérification, pas déclaré par le corps
			AuthorityDomain: body.ExpectedAuthorityDomain,
		},
		Verb: body.Verb,
		Resource: broker.Resource{
			Type:            body.Resource.Type,
			ID:              body.Resource.Id,
			AuthorityDomain: body.Resource.AuthorityDomain,
			Attributes:      attributesOrEmpty(body.Resource.Attributes),
		},
		TicketRef:               body.TicketRef,
		Justification:           body.Justification,
		ExpectedAuthorityDomain: body.ExpectedAuthorityDomain,
	}
	if body.SourceNetwork != nil {
		req.SourceNetwork = *body.SourceNetwork
	}
	if body.Posture != nil {
		req.Posture = posturefrom(*body.Posture)
	}
	if body.Approvals != nil {
		req.Approvals = make([]broker.RawApproval, 0, len(*body.Approvals))
		for _, a := range *body.Approvals {
			req.Approvals = append(req.Approvals, broker.RawApproval{Assertion: a.Assertion, ApprovedAt: a.ApprovedAt})
		}
	}

	decision, err := h.broker.Decide(ctx, req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "echec_de_transport")
		return
	}

	writeJSON(w, http.StatusOK, Decision{
		Allowed:       decision.Allowed,
		Reasons:       decision.Reasons,
		DecisionHash:  &decision.DecisionHash,
		PolicyVersion: &decision.PolicyVersion,
	})
}

func posturefrom(p Posture) broker.Posture {
	out := broker.Posture{}
	if p.Managed != nil {
		out.Managed = *p.Managed
	}
	if p.DiskEncrypted != nil {
		out.DiskEncrypted = *p.DiskEncrypted
	}
	if p.AgentVersion != nil {
		out.AgentVersion = *p.AgentVersion
	}
	if p.EvaluatedAt != nil {
		out.EvaluatedAt = *p.EvaluatedAt
	}
	return out
}

func attributesOrEmpty(m *map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return *m
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, Error{Reason: reason})
}
