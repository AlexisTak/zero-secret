// Package grpcapi expose apps/credential-issuer/internal/issuer en gRPC
// (contracts/proto/credential/v1/emission.proto) — première entrée réseau réelle de ce
// composant. Traduction pure entre le contrat et internal/issuer, aucune logique métier ici.
//
// gRPC en clair (pas de mTLS) — jamais un déploiement de production sans (même limite que
// policy-engine/identity-provider/access-broker, L2.2/H3/L2.3).
package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	credentialv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/credential/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/credential-issuer/internal/issuer"
)

type API struct {
	credentialv1.UnimplementedCredentialIssuanceServiceServer
	issuer *issuer.Issuer
}

func New(iss *issuer.Issuer) *API {
	return &API{issuer: iss}
}

func (a *API) Emit(ctx context.Context, req *credentialv1.EmissionOrder) (*credentialv1.EmissionResult, error) {
	result, err := a.issuer.Emit(ctx, issuer.EmissionOrder{
		Verb:            req.GetVerb(),
		ResourceType:    req.GetResourceType(),
		ResourceID:      req.GetResourceId(),
		AuthorityDomain: req.GetAuthorityDomain(),
		Decision:        req.GetDecision(),
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
	}
	return resp, nil
}

func (a *API) Revoke(ctx context.Context, req *credentialv1.RevokeRequest) (*credentialv1.RevokeResponse, error) {
	if err := a.issuer.Revoke(ctx, req.GetLeaseId()); err != nil {
		return nil, status.Errorf(codes.Unavailable, "révocation indisponible : %v", err)
	}
	return &credentialv1.RevokeResponse{}, nil
}
