// Package collector orchestre la réception d'un événement d'audit brut : calcule la tête de
// chaîne (internal/store), fait sceller par audit-sealer (via UDS, contracts/proto/audit/v1/
// sealing.proto) et persiste le résultat. event_id/occurred_at sont générés ici, à la
// réception — jamais fournis par l'appelant (voir sealing.proto, docs/architecture.md).
package collector

import (
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/audit/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/audit-collector/internal/store"
)

// chainRoot est la racine de chaîne (32 octets nuls) — même convention que zs_audit::CHAIN_ROOT
// (apps/identity-provider/src/store.rs), utilisée pour le tout premier événement d'un domaine
// d'autorité.
var chainRoot = make([]byte, 32)

// Store est le sous-ensemble de *store.Store utilisé ici.
type Store interface {
	ChainHead(ctx context.Context, authorityDomain string) (store.ChainHead, error)
	Append(ctx context.Context, in store.AppendInput) error
}

type Collector struct {
	// Interface générée (auditv1.AuditSealingServiceClient) — même patron que credential-issuer
	// (internal/issuer.Issuer.policyClient) : un faux serveur AuditSealingService en process
	// suffit à substituer une dépendance réseau dans les tests, pas besoin d'une interface locale
	// supplémentaire.
	sealer auditv1.AuditSealingServiceClient
	store  Store
}

func New(sealer auditv1.AuditSealingServiceClient, st Store) *Collector {
	return &Collector{sealer: sealer, store: st}
}

// Result porte l'issue de Record — un refus métier (event_type inconnu, conflit de séquence)
// n'est jamais une erreur Go, seule une panne de transport (Postgres/audit-sealer indisponibles)
// en est une, même distinction que credential-issuer.internal.issuer.Emit face à un Effect=DENY.
type Result struct {
	Accepted bool
	Reason   string
	EventID  string
	Sequence uint64
}

func (c *Collector) Record(ctx context.Context, raw *auditv1.RawEvent) (Result, error) {
	head, err := c.store.ChainHead(ctx, raw.GetAuthorityDomain())
	if err != nil {
		return Result{}, fmt.Errorf("lecture de la tête de chaîne : %w", err)
	}

	prevHash := chainRoot
	if head.PrevSealedBytes != nil {
		hashResp, err := c.sealer.HashPrevious(ctx, &auditv1.HashPreviousRequest{SealedBytes: head.PrevSealedBytes})
		if err != nil {
			return Result{}, fmt.Errorf("hachage de l'événement précédent : %w", err)
		}
		prevHash = hashResp.GetDigest()
	}

	id, err := uuid.NewV7()
	if err != nil {
		return Result{}, fmt.Errorf("génération d'event_id : %w", err)
	}
	eventID := id.String()
	occurredAt := time.Now().UTC()

	sealResp, err := c.sealer.Seal(ctx, &auditv1.SealRequest{
		EventId:         eventID,
		Sequence:        head.NextSequence,
		PrevHash:        prevHash,
		OccurredAt:      timestamppb.New(occurredAt),
		AuthorityDomain: raw.GetAuthorityDomain(),
		EventType:       raw.GetEventType(),
		Actor:           raw.GetActor(),
		Target:          raw.GetTarget(),
		Outcome:         raw.GetOutcome(),
		Context:         raw.GetContext(),
	})
	if err != nil {
		if status.Code(err) == codes.InvalidArgument {
			// Champ non reconnu par AuditEventFields (event_type/outcome/kind/aal/...) — refus
			// métier, pas une panne de transport (audit-sealer répond, il refuse la requête).
			return Result{Accepted: false, Reason: status.Convert(err).Message()}, nil
		}
		return Result{}, fmt.Errorf("scellement indisponible : %w", err)
	}

	actorJSON, err := protoJSONMarshal.Marshal(raw.GetActor())
	if err != nil {
		return Result{}, fmt.Errorf("sérialisation de l'acteur : %w", err)
	}

	err = c.store.Append(ctx, store.AppendInput{
		EventID:         eventID,
		Sequence:        head.NextSequence,
		OccurredAt:      occurredAt.Format(time.RFC3339),
		AuthorityDomain: raw.GetAuthorityDomain(),
		EventType:       raw.GetEventType(),
		ActorJSON:       actorJSON,
		TargetJSON:      optionalProtoJSON(raw.GetTarget()),
		Outcome:         raw.GetOutcome(),
		ContextJSON:     optionalProtoJSON(raw.GetContext()),
		PrevHashHex:     hex.EncodeToString(prevHash),
		SignatureJSON:   signatureJSON(),
		SealedBytes:     sealResp.GetSealedBytes(),
	})
	if err != nil {
		// La contrainte UNIQUE (authority_domain, sequence) (migration 002) rejette un conflit
		// de concurrence comme une erreur Postgres ordinaire — jamais ré-essayé avec une nouvelle
		// séquence (seal() n'est pas idempotent, ADR-011 : un ré-essai produirait une seconde
		// signature valide sur le même (sequence, prev_hash), risque de fourche). L'événement
		// scellé mais non persisté est perdu et signalé ici, jamais re-signé silencieusement.
		return Result{}, fmt.Errorf("persistance : %w", err)
	}

	return Result{Accepted: true, EventID: eventID, Sequence: head.NextSequence}, nil
}

var protoJSONMarshal = protojson.MarshalOptions{UseProtoNames: true}

// optionalProtoJSON sérialise un message optionnel (Target/Context) — nil si le pointeur est
// nil, jamais un objet JSON vide (distinction absent/vide déjà exigée côté Rust, voir
// audit_seal.rs::champ_optionnel_absent_nest_jamais_null).
func optionalProtoJSON(m proto.Message) []byte {
	if m == nil || reflect.ValueOf(m).IsNil() {
		return nil
	}
	b, err := protoJSONMarshal.Marshal(m)
	if err != nil {
		// Ne peut arriver que sur un message mal formé côté générateur — même discipline que le
		// reste du dépôt (jamais de valeur par défaut permissive), donc panique explicite plutôt
		// qu'un JSON silencieusement vide.
		panic(fmt.Sprintf("sérialisation JSON impossible : %v", err))
	}
	return b
}

// signatureJSON reconstruit une valeur minimale pour la colonne `signature` (jsonb) — le contenu
// probant réel est `sealed_bytes`, cette valeur ne sert qu'à l'inspection humaine directe en
// base, jamais à la vérification (même principe que identity-provider/src/httpapi.rs::
// signature_json).
func signatureJSON() []byte {
	return []byte(`{"suite":"audit-seal/v1"}`)
}
