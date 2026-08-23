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
	"encoding/json"
	"net/http"

	"github.com/Biscuits-ia/biscuits-shield/apps/admin-api/internal/quorum"
)

type API struct {
	verifier *quorum.Verifier
}

func New(v *quorum.Verifier) *API {
	return &API{verifier: v}
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

	writeJSON(w, http.StatusOK, QuorumResult{
		Reached:          result.Reached,
		DistinctSubjects: result.DistinctSubjects,
	})
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
