// Package httpapi expose apps/admin-api/internal/quorum en HTTP (contracts/openapi/
// admin-api.yaml) — première entrée réseau réelle de ce composant. api_generated.go est généré
// (DO NOT EDIT) ; ce fichier porte la logique.
//
// operation_id (chemin d'URL) n'est PAS transmis à quorum.VerifyQuorum : le vérificateur reste
// agnostique de l'opération protégée (ADR-021, angle mort hérité du modèle de menaces) — ce
// composant ne sait toujours pas quelle opération critique il protège ni qui a le droit de
// l'initier, operation_id n'est ici qu'une valeur de corrélation pour un futur appelant/journal.
//
// Pas de TLS dans ce lot — signalé, même limite que partout ailleurs.
package httpapi

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	auditv1 "github.com/Biscuits-ia/biscuits-shield/pkg/gen/audit/v1"

	"github.com/Biscuits-ia/biscuits-shield/apps/admin-api/internal/quorum"
)

type API struct {
	verifier    *quorum.Verifier
	auditClient auditv1.AuditCollectionServiceClient
}

func New(v *quorum.Verifier, auditClient auditv1.AuditCollectionServiceClient) *API {
	return &API{verifier: v, auditClient: auditClient}
}

func (a *API) VerifyQuorum(w http.ResponseWriter, r *http.Request, operationId string) {
	var body QuorumRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "corps_de_requete_malforme")
		return
	}

	// quorum.VerifyQuorum panique si threshold < MinimumThreshold (erreur de configuration de
	// l'appelant, par construction — voir ADR-021) : sur une requête HTTP non fiable, cette
	// panique doit devenir un refus explicite (400), jamais un crash du processus.
	result, err := verifyQuorumRecovered(r, a.verifier, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// quorum.operation n'est audité que pour les porteurs réellement vérifiés
	// (result.DistinctSubjects) — jamais pour un refus avant vérification (seuil invalide, corps
	// malformé) : sans identité établie, il n'y a personne à qui attribuer l'événement.
	a.recordQuorumOperation(r.Context(), operationId, body.ExpectedAuthorityDomain, result)

	writeJSON(w, http.StatusOK, QuorumResult{
		Reached:          result.Reached,
		DistinctSubjects: result.DistinctSubjects,
	})
}

// recordQuorumOperation envoie un quorum.operation par porteur distinct vérifié — le contrat
// (contracts/events/audit-event.schema.json) n'a qu'un seul champ `actor` par événement, pas de
// notion native de groupe de porteurs ; un événement par porteur préserve l'attribution
// individuelle sans inventer de champ (décision explicite, pas de précédent dans ce dépôt avant
// ce lot). `outcome` reflète le résultat GLOBAL du quorum (atteint ou non), pas la validité de la
// vérification individuelle du porteur — même principe que policy.decided (ADR-027) : un porteur
// peut avoir été correctement vérifié alors que le quorum global reste refusé.
//
// Best-effort, comme policy.decided (ADR-027) : une panne d'audit-collector est journalisée,
// jamais renvoyée à l'appelant HTTP — le quorum a déjà été évalué de façon irréversible.
func (a *API) recordQuorumOperation(ctx context.Context, operationID, authorityDomain string, result quorum.Result) {
	outcome := "denied"
	if result.Reached {
		outcome = "success"
	}

	for _, subjectID := range result.DistinctSubjects {
		res, err := a.auditClient.Record(ctx, &auditv1.RawEvent{
			AuthorityDomain: authorityDomain,
			EventType:       "quorum.operation",
			Actor: &auditv1.Actor{
				SubjectId: subjectID,
				Kind:      "human",
			},
			Target: &auditv1.Target{
				Type: "critical_operation",
				Id:   operationID,
			},
			Outcome: outcome,
		})
		if err != nil {
			log.Printf("admin-api: échec de l'envoi de quorum.operation à audit-collector (opération %s, porteur %s) : %v", operationID, subjectID, err)
			continue
		}
		if !res.Accepted {
			log.Printf("admin-api: quorum.operation refusé par audit-collector (opération %s, porteur %s) : %s", operationID, subjectID, res.Reason)
		}
	}
}

func verifyQuorumRecovered(r *http.Request, v *quorum.Verifier, body QuorumRequest) (result quorum.Result, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = errPanic(rec)
		}
	}()
	result, callErr := v.VerifyQuorum(r.Context(), body.ExpectedAuthorityDomain, body.Assertions, body.Threshold)
	if callErr != nil {
		return quorum.Result{}, callErr
	}
	return result, nil
}

type panicError struct{ v any }

func (e panicError) Error() string { return "seuil_de_quorum_invalide" }

func errPanic(v any) error { return panicError{v: v} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, Error{Reason: reason})
}
