// Package grpcapi expose apps/credential-issuer/internal/issuer en gRPC
// (contracts/proto/credential/v1/emission.proto) — première entrée réseau réelle de ce
// composant. Traduction pure entre le contrat et internal/issuer, aucune logique métier ici.
//
// gRPC en clair (pas de mTLS) — jamais un déploiement de production sans (même limite que
// policy-engine/identity-provider/access-broker, L2.2/H3/L2.3).
package grpcapi

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	auditv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/audit/v1"
	credentialv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/credential/v1"

	"github.com/AlexisTak/biscuits-shield/apps/credential-issuer/internal/issuer"
)

type API struct {
	credentialv1.UnimplementedCredentialIssuanceServiceServer
	issuer      *issuer.Issuer
	auditClient auditv1.AuditCollectionServiceClient
}

func New(iss *issuer.Issuer, auditClient auditv1.AuditCollectionServiceClient) *API {
	return &API{issuer: iss, auditClient: auditClient}
}

func (a *API) Emit(ctx context.Context, req *credentialv1.EmissionOrder) (*credentialv1.EmissionResult, error) {
	result, err := a.issuer.Emit(ctx, issuer.EmissionOrder{
		Verb:            req.GetVerb(),
		ResourceType:    req.GetResourceType(),
		ResourceID:      req.GetResourceId(),
		AuthorityDomain: req.GetAuthorityDomain(),
		Decision:        req.GetDecision(),
		RequestID:       req.GetRequestId(),
		SubjectID:       req.GetSubjectId(),
		AAL:             req.GetAal(),
		AuthMethod:      req.GetAuthMethod(),
	})
	if err != nil {
		// Réservé aux échecs de transport (OpenBao indisponible, vérification de décision
		// injoignable) — un refus métier est déjà un EmissionResult{Allowed:false} normal (P2),
		// jamais transformé en erreur gRPC ici.
		return nil, status.Errorf(codes.Unavailable, "émission indisponible : %v", err)
	}

	resp := &credentialv1.EmissionResult{
		Allowed: result.Allowed,
		Reasons: result.Reasons,
		LeaseId: result.LeaseID,
	}
	if result.Allowed {
		resp.LeaseDuration = durationpb.New(result.LeaseDuration)
		// credential.issued construit seulement après un succès réel (docs/backlog.md) — jamais
		// pour un refus métier, best-effort comme policy.decided/quorum.operation (ADR-027/028).
		a.recordCredentialIssued(ctx, req.GetAuthorityDomain(), req.GetResourceType(), req.GetResourceId(), result.Event)
	}
	return resp, nil
}

func (a *API) recordCredentialIssued(ctx context.Context, authorityDomain, resourceType, resourceID string, event issuer.IssuedCredentialEvent) {
	var grantedTTL *uint32
	if event.GrantedTTLSeconds > 0 {
		seconds := uint32(event.GrantedTTLSeconds)
		grantedTTL = &seconds
	}
	var decisionSignature []byte
	var decisionSignatureKeyID *string
	if len(event.DecisionSignature) > 0 {
		decisionSignature = event.DecisionSignature
		keyID := event.DecisionSignatureKeyID
		decisionSignatureKeyID = &keyID
	}
	var aal, authMethod *string
	if event.AAL != "" {
		aal = &event.AAL
	}
	if event.AuthMethod != "" {
		authMethod = &event.AuthMethod
	}

	res, err := a.auditClient.Record(ctx, &auditv1.RawEvent{
		AuthorityDomain: authorityDomain,
		EventType:       "credential.issued",
		Actor: &auditv1.Actor{
			SubjectId:  event.SubjectID,
			Kind:       "human",
			Aal:        aal,
			AuthMethod: authMethod,
		},
		Target: &auditv1.Target{
			Type: resourceType,
			Id:   resourceID,
		},
		Outcome: "success",
		Decision: &auditv1.Decision{
			RequestId:              event.RequestID,
			DecisionHash:           event.DecisionHash,
			PolicyVersion:          event.PolicyVersion,
			Reasons:                event.Reasons,
			GrantedTtlSeconds:      grantedTTL,
			DecisionSignature:      decisionSignature,
			DecisionSignatureKeyId: decisionSignatureKeyID,
		},
	})
	if err != nil {
		log.Printf("credential-issuer: échec de l'envoi de credential.issued à audit-collector (requête %s) : %v", event.RequestID, err)
		return
	}
	if !res.Accepted {
		log.Printf("credential-issuer: credential.issued refusé par audit-collector (requête %s) : %s", event.RequestID, res.Reason)
	}
}

func (a *API) Revoke(ctx context.Context, req *credentialv1.RevokeRequest) (*credentialv1.RevokeResponse, error) {
	if err := a.issuer.Revoke(ctx, req.GetLeaseId()); err != nil {
		return nil, status.Errorf(codes.Unavailable, "révocation indisponible : %v", err)
	}
	return &credentialv1.RevokeResponse{}, nil
}
