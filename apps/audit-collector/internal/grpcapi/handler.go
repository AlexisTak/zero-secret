// Package grpcapi expose internal/collector en gRPC (contracts/proto/audit/v1/collection.proto)
// — première entrée réseau réelle de ce composant. Traduction pure, aucune logique métier ici.
// Câblage des producteurs (access-broker/admin-api/credential-issuer) différé, hors périmètre
// de ce lot.
package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auditv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/audit/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/audit-collector/internal/collector"
)

type API struct {
	auditv1.UnimplementedAuditCollectionServiceServer
	collector *collector.Collector
}

func New(c *collector.Collector) *API {
	return &API{collector: c}
}

func (a *API) Record(ctx context.Context, req *auditv1.RawEvent) (*auditv1.RecordResult, error) {
	result, err := a.collector.Record(ctx, req)
	if err != nil {
		// Réservé aux pannes de transport (Postgres/audit-sealer indisponibles) — un refus
		// métier est déjà un RecordResult{Accepted:false} normal, jamais transformé en erreur
		// gRPC ici (même distinction que credential-issuer.internal.grpcapi.Emit).
		return nil, status.Errorf(codes.Unavailable, "réception indisponible : %v", err)
	}

	return &auditv1.RecordResult{
		Accepted: result.Accepted,
		Reason:   result.Reason,
		EventId:  result.EventID,
		Sequence: result.Sequence,
	}, nil
}
