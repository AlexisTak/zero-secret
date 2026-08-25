// Package quorum vérifie qu'une opération critique d'administration est portée par plusieurs
// porteurs réellement distincts (L2.5) — réutilise identity-assertion/v1 via le service de
// vérification H3, jamais une nouvelle suite cryptographique (même raisonnement qu'ADR-009,
// L1.3 : chaque porteur approuve via sa propre cérémonie d'authentification, le quorum se réduit
// à compter des approbations déjà vérifiées, avec la garantie que chacune vient d'un porteur
// distinct).
//
// Agnostique de l'opération et du rôle : ce paquet ne sait pas QUELLE opération critique il
// protège (politique, approbateur, identité) ni QUI a le droit de l'initier — la granularité des
// rôles d'administration et le chemin de modification à chaud des politiques sont deux angles
// morts explicitement non tranchés par security/threat-models/admin-api.md (L0.5), hérités ici
// tels quels, pas improvisés (voir ADR-021).
package quorum

import (
	"context"
	"fmt"

	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"
)

// MinimumThreshold est le plancher imposé par ce module, non contournable par un paramètre
// d'appel — même garde-fou structurel qu'zs_webauthn::recovery::verify_quorum (ADR-009) : un
// appelant qui configurerait threshold = 1 par erreur est refusé par construction.
const MinimumThreshold = 2

// Result est la sortie d'une vérification de quorum — jamais une erreur Go pour un quorum non
// atteint (P2, même discipline que L2.2/L2.3/L2.4/H3/H4) : un refus métier est un
// Result{Reached: false}.
type Result struct {
	Reached          bool
	DistinctSubjects []string // porteurs vérifiés distincts ayant contribué — jamais dupliqué
}

// Verifier vérifie chaque assertion via identity.v1.AssertionVerificationService (H3).
type Verifier struct {
	client identityv1.AssertionVerificationServiceClient
}

func New(client identityv1.AssertionVerificationServiceClient) *Verifier {
	return &Verifier{client: client}
}

// VerifyQuorum vérifie `assertions` (chacune une assertion identity-assertion/v1 scellée) et
// détermine si `threshold` porteurs DISTINCTS ont été vérifiés avec succès. Une assertion
// invalide est ignorée sans annuler les autres (même patron que L2.3 pour les approbations) —
// mais deux assertions valides du MÊME subject_id ne comptent qu'une fois : le critère
// d'acceptation du backlog (« un seul porteur ne peut jamais déclencher ») porte sur des porteurs
// distincts, pas sur un nombre brut d'assertions.
//
// threshold < MinimumThreshold est une erreur de configuration de l'appelant, jamais un refus
// métier silencieusement toléré — panique explicite, détectée au premier appel plutôt que de
// laisser un seuil affaibli passer inaperçu en production.
func (v *Verifier) VerifyQuorum(
	ctx context.Context,
	expectedAuthorityDomain string,
	assertions [][]byte,
	threshold int,
) (Result, error) {
	if threshold < MinimumThreshold {
		panic(fmt.Sprintf("quorum: threshold %d inférieur au plancher imposé (%d)", threshold, MinimumThreshold))
	}

	seen := make(map[string]struct{})
	for _, assertion := range assertions {
		resp, err := v.client.VerifyAssertion(ctx, &identityv1.VerifyAssertionRequest{
			Assertion:               assertion,
			ExpectedAuthorityDomain: expectedAuthorityDomain,
		})
		if err != nil {
			return Result{}, fmt.Errorf("vérification d'assertion de quorum : %w", err)
		}
		if !resp.Valid {
			continue
		}
		seen[resp.SubjectId] = struct{}{}
	}

	distinct := make([]string, 0, len(seen))
	for subject := range seen {
		distinct = append(distinct, subject)
	}

	return Result{
		Reached:          len(distinct) >= threshold,
		DistinctSubjects: distinct,
	}, nil
}
