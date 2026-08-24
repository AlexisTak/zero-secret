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
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	auditv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/audit/v1"
	credentialv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/credential/v1"
	identityv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/identity/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/access-broker/internal/broker"
)

type API struct {
	identityClient   identityv1.AssertionVerificationServiceClient
	credentialClient credentialv1.CredentialIssuanceServiceClient
	auditClient      auditv1.AuditCollectionServiceClient
	broker           *broker.Broker
}

func New(identityClient identityv1.AssertionVerificationServiceClient, credentialClient credentialv1.CredentialIssuanceServiceClient, auditClient auditv1.AuditCollectionServiceClient, b *broker.Broker) *API {
	return &API{identityClient: identityClient, credentialClient: credentialClient, auditClient: auditClient, broker: b}
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

	// policy.decided n'est audité que si le PDP a réellement été consulté (Signed != nil) —
	// jamais pour un refus local avant tout appel PDP (justification trop longue, champ requis
	// absent, approbation vérifiée absente) : ces refus n'ont ni decision_hash ni
	// policy_version significatifs, il n'y a pas de décision à auditer (ADR-027).
	if decision.Signed != nil {
		h.recordPolicyDecided(ctx, requestID.String(), body, verifyResp, decision)
	}

	resp := Decision{
		Allowed:       decision.Allowed,
		Reasons:       decision.Reasons,
		DecisionHash:  &decision.DecisionHash,
		PolicyVersion: &decision.PolicyVersion,
	}

	// Émission déclenchée uniquement pour une décision ALLOW (backlog L2.4 suite) — un échec
	// d'émission (OpenBao indisponible, décision déjà consommée) n'invalide jamais la décision
	// elle-même : la réponse reste 200 avec allowed=true, mais lease_id/lease_duration_seconds
	// restent absents. Le client doit distinguer "refusé" d'"autorisé mais rien n'a pu être émis"
	// (voir contracts/openapi/access-broker.yaml, Decision.lease_id).
	if decision.Allowed && decision.Signed != nil {
		emission, err := h.credentialClient.Emit(ctx, &credentialv1.EmissionOrder{
			Verb:            body.Verb,
			ResourceType:    body.Resource.Type,
			ResourceId:      body.Resource.Id,
			AuthorityDomain: body.Resource.AuthorityDomain,
			Decision:        decision.Signed,
		})
		if err == nil && emission.Allowed {
			resp.LeaseId = &emission.LeaseId
			if emission.LeaseDuration != nil {
				seconds := int(emission.LeaseDuration.AsDuration().Seconds())
				resp.LeaseDurationSeconds = &seconds
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// recordPolicyDecided envoie policy.decided à audit-collector — best-effort, une panne n'échoue
// jamais la réponse HTTP (même patron que le déclenchement d'émission ci-dessus) : la décision
// PDP a déjà eu lieu de façon irréversible au moment où l'audit est tenté, échouer toute la
// requête ici ne l'annulerait pas, seulement priverait l'appelant légitime d'une réponse déjà
// déterminée (ADR-027, cohérent avec docs/architecture.md : « une saturation de l'audit ne
// dégrade pas l'accès »). Erreur journalisée, jamais silencieuse.
func (h *API) recordPolicyDecided(ctx context.Context, requestID string, body AccessRequestBody, verifyResp *identityv1.VerifyAssertionResponse, decision broker.Decision) {
	outcome := "denied"
	if decision.Allowed {
		outcome = "success"
	}

	var grantedTTL *uint32
	if decision.Signed.MaxTtl != nil {
		seconds := uint32(decision.Signed.MaxTtl.AsDuration().Seconds())
		grantedTTL = &seconds
	}

	var decisionSignature []byte
	var decisionSignatureKeyID *string
	if len(decision.Signed.DecisionSignature) > 0 {
		decisionSignature = decision.Signed.DecisionSignature
		keyID := decision.Signed.DecisionSignatureKeyId
		decisionSignatureKeyID = &keyID
	}

	_, err := h.auditClient.Record(ctx, &auditv1.RawEvent{
		AuthorityDomain: body.ExpectedAuthorityDomain,
		EventType:       "policy.decided",
		Actor: &auditv1.Actor{
			SubjectId:  verifyResp.SubjectId,
			Kind:       "human",
			Aal:        optionalString(verifyResp.Aal),
			AuthMethod: optionalString(verifyResp.AuthMethod),
		},
		Target: &auditv1.Target{
			Type: body.Resource.Type,
			Id:   body.Resource.Id,
		},
		Outcome: outcome,
		Context: &auditv1.Context{
			SourceNetwork: optionalStringPtr(body.SourceNetwork),
			TicketRef:     optionalString(body.TicketRef),
			Justification: optionalString(body.Justification),
		},
		Decision: &auditv1.Decision{
			RequestId:              requestID,
			DecisionHash:           decision.Signed.DecisionHash,
			PolicyVersion:          decision.Signed.PolicyVersion,
			Reasons:                decision.Signed.Reasons,
			GrantedTtlSeconds:      grantedTTL,
			DecisionSignature:      decisionSignature,
			DecisionSignatureKeyId: decisionSignatureKeyID,
		},
	})
	if err != nil {
		log.Printf("access-broker: échec de l'envoi de policy.decided à audit-collector (requête %s) : %v", requestID, err)
	}
}

// optionalString omet un champ optional proto (jamais une chaîne vide présente, qui échouerait
// la validation de longueur minimale côté zs-crypto ShortText — même principe que
// contracts/openapi/access-broker.yaml : un champ optionnel absent, pas vide).
func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// optionalStringPtr applique la même règle qu'optionalString à un champ déjà optionnel côté
// contrat OpenAPI (*string) — un pointeur non nil vers une chaîne vide reste omis.
func optionalStringPtr(s *string) *string {
	if s == nil {
		return nil
	}
	return optionalString(*s)
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
