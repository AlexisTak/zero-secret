// Package issuer orchestre l'émission de credential (L2.4) : vérifie une décision signée
// (H4, PolicyDecisionService.VerifyDecision) avant tout appel à OpenBao (H2). Ni serveur gRPC/
// HTTP ni contrat access-broker->credential-issuer n'existent encore — bibliothèque d'abord,
// même coupe que apps/access-broker/internal/broker (L2.3).
package issuer

import (
	"time"

	policyv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/policy/v1"
)

// EmissionOrder est l'entrée du parcours d'émission — pas encore reçue via un contrat réseau
// (aucun n'existe), construite par l'appelant de ce package pour ce lot. Decision porte la
// DecisionResponse complète, y compris sa signature decision-seal/v1 (H4) : c'est elle qui est
// vérifiée, jamais un champ isolé fourni séparément par l'appelant.
type EmissionOrder struct {
	Verb            string
	ResourceType    string
	ResourceID      string
	AuthorityDomain string
	Decision        *policyv1.DecisionResponse
}

// Result est la sortie d'une émission réussie — jamais retournée pour un refus (le refus est un
// Result{Allowed: false}, jamais une valeur zéro ambiguë ; voir Emit).
type Result struct {
	Allowed bool
	Reasons []string
	// LeaseID/LeaseDuration : vides si Allowed = false. Aucune donnée secrète du bail (username/
	// password OpenBao) n'est recopiée ici — un appelant qui a besoin du secret consomme
	// directement le Lease retourné par le client OpenBao (H2), ce type ne le duplique jamais
	// pour ne pas multiplier les emplacements où un secret pourrait fuiter par log.
	LeaseID       string
	LeaseDuration time.Duration
	Event         IssuedCredentialEvent
}

// IssuedCredentialEvent porte les champs de credential.issued (contracts/events/
// audit-event.schema.json) — construit ici, PAS scellé : un service Rust d'audit symétrique à
// H3/H4 (audit_seal) n'existe pas encore côté réseau accessible à ce composant Go. Un futur
// appelant scelle/persiste ces champs. request_id/decision_hash/policy_version/reasons partagés
// avec policy.decided (backlog L2.4 : « permet de relier les deux événements sans dénormaliser
// la décision »).
type IssuedCredentialEvent struct {
	EventID           string // UUIDv7 généré AVANT l'appel OpenBao (R7, ADR-008/012) — voir Emit
	DecisionHash      []byte
	PolicyVersion     string
	Reasons           []string
	GrantedTTLSeconds int64
	LeaseID           string
}

// ConsumedDecisionStore est le port de prévention de rejeu (« decision_hash déjà consommé »,
// security/threat-models/credential-issuer.md). Implémentation en mémoire fournie
// (consumed_decisions.go) — ce lot rend credential-issuer réellement accessible en réseau, ce
// qui rend le rejeu réellement exploitable (une décision ALLOW signée rejouée deux fois
// émettrait deux credentials pour une seule autorisation) : fermer ce trou n'est plus une
// coupe de portée légitime à ce stade (voir ADR de ce lot).
type ConsumedDecisionStore interface {
	// MarkConsumed doit être atomique : deux appels concurrents avec le même decisionHash ne
	// doivent jamais réussir tous les deux (contrat que toute implémentation future doit tenir).
	MarkConsumed(decisionHash []byte) (alreadyConsumed bool, err error)
}
