package broker

import (
	"context"
	"fmt"
	"time"

	identityv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/identity/v1"
	policyv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/policy/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Broker orchestre le parcours JIT. Les deux dépendances sont les interfaces gRPC générées
// (policyv1.PolicyDecisionServiceClient, identityv1.AssertionVerificationServiceClient) — un
// client réel (grpc.ClientConn) les satisfait directement, un double de test aussi, sans
// wrapper supplémentaire.
type Broker struct {
	policyClient   policyv1.PolicyDecisionServiceClient
	identityClient identityv1.AssertionVerificationServiceClient
}

func New(policyClient policyv1.PolicyDecisionServiceClient, identityClient identityv1.AssertionVerificationServiceClient) *Broker {
	return &Broker{policyClient: policyClient, identityClient: identityClient}
}

// Decide exécute le parcours JIT : validation locale, vérification des approbations, appel au
// PDP. error est réservé aux échecs de transport/validation locale — jamais à un refus métier
// (P2, même discipline que policy-engine/identity-provider) : un refus métier est une Decision
// normale (Allowed: false).
func (b *Broker) Decide(ctx context.Context, req AccessRequest) (Decision, error) {
	if len(req.Justification) > MaxJustificationLength {
		return Decision{Allowed: false, Reasons: []string{"justification_trop_longue"}}, nil
	}
	if req.Principal.SubjectID == "" || req.Resource.Type == "" || req.Verb == "" {
		return Decision{Allowed: false, Reasons: []string{"champ_requis_absent"}}, nil
	}

	// Vérifie chaque approbation fournie via identity-provider (H3) — jamais directement, ADR-001.
	verifiedApprovals := make([]*policyv1.Approval, 0, len(req.Approvals))
	for _, raw := range req.Approvals {
		resp, err := b.identityClient.VerifyAssertion(ctx, &identityv1.VerifyAssertionRequest{
			Assertion:               raw.Assertion,
			ExpectedAuthorityDomain: req.ExpectedAuthorityDomain,
		})
		if err != nil {
			return Decision{}, fmt.Errorf("vérification d'approbation : %w", err)
		}
		if !resp.Valid {
			// Une approbation invalide n'annule pas les autres, mais n'est jamais comptée —
			// pas de repli silencieux sur "au moins une valide suffit à ignorer les invalides".
			continue
		}
		verifiedApprovals = append(verifiedApprovals, &policyv1.Approval{
			ApproverId: resp.SubjectId,
			ApprovedAt: timestamppb.New(raw.ApprovedAt), // déclaré, pas vérifié — voir types.go
			Signature:  raw.Assertion,
		})
	}

	// Règle provisoire, signalée (ADR-017) : toute demande exige au moins une approbation
	// vérifiée, quel que soit le verbe — pas de distinction par politique tant qu'un mécanisme
	// de métadonnées par politique n'existe pas. Refus avant tout appel au PDP.
	if len(verifiedApprovals) == 0 {
		return Decision{Allowed: false, Reasons: []string{"approbation_verifiee_absente"}}, nil
	}

	decisionReq := &policyv1.DecisionRequest{
		RequestId: req.RequestID,
		Principal: &policyv1.Principal{
			SubjectId:       req.Principal.SubjectID,
			Aal:             authLevelFromString(req.Principal.AAL),
			AuthMethod:      req.Principal.AuthMethod,
			AuthenticatedAt: timestamppb.New(req.Principal.AuthenticatedAt),
			Roles:           req.Principal.Roles,
			AuthorityDomain: req.Principal.AuthorityDomain,
		},
		Action: &policyv1.Action{Verb: req.Verb},
		Resource: &policyv1.Resource{
			Type:            req.Resource.Type,
			Id:              req.Resource.ID,
			AuthorityDomain: req.Resource.AuthorityDomain,
			Attributes:      req.Resource.Attributes,
		},
		Context: &policyv1.Context{
			// Fixé par le broker à l'instant du traitement, pas fourni par l'appelant — un
			// appelant qui choisirait sa propre valeur pourrait sinon contourner la fraîcheur de
			// posture évaluée côté PDP (même raisonnement que AcceptancePolicy.now, H3/ADR-016).
			RequestedAt:   timestamppb.New(time.Now().UTC()),
			SourceNetwork: req.SourceNetwork,
			Posture: &policyv1.DevicePosture{
				Managed:       req.Posture.Managed,
				DiskEncrypted: req.Posture.DiskEncrypted,
				AgentVersion:  req.Posture.AgentVersion,
				EvaluatedAt:   timestamppb.New(req.Posture.EvaluatedAt),
			},
			TicketRef:     req.TicketRef,
			Justification: req.Justification,
			Approvals:     verifiedApprovals,
		},
	}

	resp, err := b.policyClient.Decide(ctx, decisionReq)
	if err != nil {
		return Decision{}, fmt.Errorf("appel au PDP : %w", err)
	}

	return Decision{
		Allowed:       resp.Effect == policyv1.Effect_EFFECT_ALLOW,
		Reasons:       resp.Reasons,
		DecisionHash:  resp.DecisionHash,
		PolicyVersion: resp.PolicyVersion,
	}, nil
}

// authLevelFromString traduit "AAL1"/"AAL2"/"AAL3" ; toute autre valeur (y compris vide) devient
// AUTH_LEVEL_UNSPECIFIED — jamais interprétée comme un niveau valide (P2, cohérent avec la
// traduction déjà faite côté policy-engine/Cedar en L2.1/L2.2).
func authLevelFromString(s string) policyv1.AuthLevel {
	switch s {
	case "AAL1":
		return policyv1.AuthLevel_AUTH_LEVEL_AAL1
	case "AAL2":
		return policyv1.AuthLevel_AUTH_LEVEL_AAL2
	case "AAL3":
		return policyv1.AuthLevel_AUTH_LEVEL_AAL3
	default:
		return policyv1.AuthLevel_AUTH_LEVEL_UNSPECIFIED
	}
}
