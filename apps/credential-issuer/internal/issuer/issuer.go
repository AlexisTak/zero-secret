package issuer

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	policyv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/policy/v1"
)

// Note : identity.v1 (H3, VerifyAssertion) n'est pas utilisé ici — l'approbateur a déjà été
// vérifié en amont par access-broker (L2.3) ; ce paquet ne vérifie que la décision du PDP
// (policy.v1.VerifyDecision, H4).

// LeaseIssuer est le sous-ensemble d'apps/credential-issuer/internal/openbao.Client (H2) utilisé
// ici — interface locale pour permettre des doublures de test, satisfaite structurellement par
// *openbao.Client sans import direct (évite un couplage circulaire entre les deux paquets
// internes ; openbao.Client n'a pas besoin de connaître issuer).
type LeaseIssuer interface {
	IssueLease(ctx context.Context, path string, params map[string]any) (Lease, error)
	Revoke(ctx context.Context, leaseID string) error
}

// Lease est une copie structurelle minimale d'openbao.Lease — seuls les champs consommés ici.
// Le type complet (avec Data, qui porte le secret) reste dans le paquet openbao ; ce sous-ensemble
// évite de faire transiter le secret par ce paquet quand seul l'identifiant/la durée comptent.
type Lease struct {
	ID            string
	LeaseDuration time.Duration
}

// Issuer orchestre l'émission. La vérification de décision utilise directement l'interface gRPC
// générée (policyv1.PolicyDecisionServiceClient) — même patron que access-broker (L2.3).
type Issuer struct {
	policyClient policyv1.PolicyDecisionServiceClient
	leases       LeaseIssuer
}

func New(policyClient policyv1.PolicyDecisionServiceClient, leases LeaseIssuer) *Issuer {
	return &Issuer{policyClient: policyClient, leases: leases}
}

// Emit vérifie la décision (H4), refuse tout ce qui n'est pas une décision valide et ALLOW, mappe
// le verbe vers un moteur OpenBao, impose le TTL de la décision (jamais celui de l'appelant),
// émet le bail, et construit (sans le sceller — voir types.go) l'événement credential.issued.
//
// error est réservé aux échecs de transport ou à un appel OpenBao réellement tenté et échoué —
// jamais à un refus métier (P2, même discipline que L2.2/L2.3/H3/H4) : un refus métier est un
// Result{Allowed: false}.
func (iss *Issuer) Emit(ctx context.Context, order EmissionOrder) (Result, error) {
	if order.Decision == nil {
		return Result{Allowed: false, Reasons: []string{"decision_absente"}}, nil
	}

	verifyResp, err := iss.policyClient.VerifyDecision(ctx, &policyv1.VerifyDecisionRequest{
		Decision: order.Decision,
	})
	if err != nil {
		return Result{}, fmt.Errorf("vérification de la décision : %w", err)
	}
	if !verifyResp.Valid {
		return Result{Allowed: false, Reasons: []string{"decision_invalide:" + verifyResp.Reason}}, nil
	}
	if order.Decision.Effect != policyv1.Effect_EFFECT_ALLOW {
		return Result{Allowed: false, Reasons: order.Decision.Reasons}, nil
	}

	path, err := openBaoPath(order.Verb, order.ResourceID)
	if err != nil {
		return Result{Allowed: false, Reasons: []string{err.Error()}}, nil
	}

	// R7 (ADR-008/012), réappliqué ici (backlog L2.4) : l'identifiant de l'événement est généré
	// AVANT l'appel à OpenBao — l'événement lui-même (construit ci-dessous, après le succès réel)
	// ne doit jamais affirmer l'existence d'un credential qui n'a pas été réellement émis.
	eventID, err := uuid.NewV7()
	if err != nil {
		return Result{}, fmt.Errorf("génération de l'identifiant d'événement : %w", err)
	}

	// max_ttl imposé par la décision VÉRIFIÉE (donc déjà signée par le PDP), jamais par
	// l'appelant : aucun champ d'EmissionOrder ne permet de fournir une durée alternative.
	ttlSeconds := int64(0)
	if order.Decision.MaxTtl != nil {
		ttlSeconds = order.Decision.MaxTtl.Seconds
	}

	lease, err := iss.leases.IssueLease(ctx, path, map[string]any{"ttl_seconds": ttlSeconds})
	if err != nil {
		return Result{}, fmt.Errorf("émission du bail : %w", err)
	}

	event := IssuedCredentialEvent{
		EventID:           eventID.String(),
		DecisionHash:      order.Decision.DecisionHash,
		PolicyVersion:     order.Decision.PolicyVersion,
		Reasons:           order.Decision.Reasons,
		GrantedTTLSeconds: ttlSeconds,
		LeaseID:           lease.ID,
	}

	return Result{
		Allowed:       true,
		Reasons:       order.Decision.Reasons,
		LeaseID:       lease.ID,
		LeaseDuration: lease.LeaseDuration,
		Event:         event,
	}, nil
}

// Revoke propage directement le client H2 — timeout et refus explicite déjà imposés par
// openbao.Client (ADR-018), pas de mesure réelle du délai < 5 s possible sans OpenBao réel.
func (iss *Issuer) Revoke(ctx context.Context, leaseID string) error {
	return iss.leases.Revoke(ctx, leaseID)
}

// openBaoPath mappe verbe -> moteur OpenBao, minimal et explicite (backlog L2.4, angle EoP du
// modèle de menaces) : seul db.connect est instruit à ce jour (L2.1, seule politique réelle).
// Tout autre verbe est un refus documenté, jamais une tentative générique qui masquerait un
// mapping non instruit.
func openBaoPath(verb, resourceID string) (string, error) {
	switch verb {
	case "db.connect":
		return "database/creds/" + resourceID, nil
	default:
		return "", fmt.Errorf("moteur_non_supporte:%s", verb)
	}
}
