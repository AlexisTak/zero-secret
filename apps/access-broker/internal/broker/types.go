// Package broker orchestre le parcours JIT (L2.3) : ouverture de demande, vérification des
// approbations (via identity-provider, H3), appel au PDP réel (policy-engine, L2.2). Ni le
// déclenchement d'émission (credential-issuer n'existe pas encore, L2.4/H2) ni le scellement de
// l'événement d'audit policy.decided (exigerait un service Rust symétrique à H3, non construit)
// ne sont couverts ici — voir ADR-017.
package broker

import (
	"time"

	policyv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/policy/v1"
)

// MaxJustificationLength borne Context.justification, déjà documentée dans decision.proto mais
// jamais appliquée avant cette contribution.
const MaxJustificationLength = 512

// Principal décrit l'identité prouvée à l'origine de la demande.
type Principal struct {
	SubjectID       string
	AAL             string // "AAL1" / "AAL2" / "AAL3" — toute autre valeur est refusée (P2)
	AuthMethod      string
	AuthenticatedAt time.Time
	Roles           []string
	AuthorityDomain string
}

// Resource décrit la cible de la demande. Attributes suit le contrat (ex. "environment" pour le
// type Database — contracts/cedar/README.md).
type Resource struct {
	Type            string
	ID              string
	AuthorityDomain string
	Attributes      map[string]string
}

// Posture est un contexte DÉCLARÉ, pas vérifié : aucun agent de posture de confiance n'existe
// dans ce dépôt à ce jour. Cette structure ne distingue donc pas contexte vérifié/déclaré au sens
// où l'angle mort L0.5 le pose — c'est un gap réel, documenté, pas une solution (ADR-017).
type Posture struct {
	Managed       bool
	DiskEncrypted bool
	AgentVersion  string
	EvaluatedAt   time.Time
}

// RawApproval est une approbation fournie par l'appelant, avant vérification. ApprovedAt est
// DÉCLARÉ par l'appelant : identity.v1.VerifyAssertionResponse (H3) ne renvoie pas d'horodatage
// vérifié pour l'assertion — même catégorie de gap que Posture, pas une réouverture du contrat
// H3 (ADR-017).
type RawApproval struct {
	Assertion  []byte
	ApprovedAt time.Time
}

// AccessRequest est l'entrée du parcours JIT — pas encore reçue via une API HTTP (contracts/
// openapi/ n'existe pas), construite par l'appelant de ce package pour ce lot.
type AccessRequest struct {
	RequestID               string
	Principal               Principal
	Verb                    string
	Resource                Resource
	SourceNetwork           string
	Posture                 Posture
	TicketRef               string
	Justification           string
	Approvals               []RawApproval
	ExpectedAuthorityDomain string // domaine attendu pour la vérification des approbations
}

// Decision est le résultat du parcours — jamais une erreur Go pour un refus métier (P2, même
// discipline que policy-engine/identity-provider) : un refus est une Decision normale.
type Decision struct {
	Allowed       bool
	Reasons       []string
	DecisionHash  []byte
	PolicyVersion string
	// Signed porte la DecisionResponse complète, signée (decision-seal/v1, H4), telle que reçue
	// du PDP — nil si Allowed = false (aucune décision ALLOW signée à transmettre). Un futur
	// appelant (httpapi, déclenchement d'émission vers credential-issuer, backlog L2.4 suite) en
	// a besoin en entier, pas seulement des champs déjà aplatis ci-dessus : VerifyDecision exige
	// la signature/l'horodatage de scellement, absents de cette forme réduite.
	Signed *policyv1.DecisionResponse
}
