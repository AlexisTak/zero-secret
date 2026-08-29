// Package httpapi expose apps/admin-api/internal/quorum en HTTP (contracts/openapi/
// admin-api.yaml) — première entrée réseau réelle de ce composant. api_generated.go est généré
// (DO NOT EDIT) ; ce fichier porte la logique.
//
// operation_id (chemin d'URL) n'est PAS transmis à quorum.VerifyQuorum : le vérificateur reste
// agnostique de l'opération protégée (ADR-021) — ce composant ne sait pas quelle opération
// critique il protège, operation_id n'est ici qu'une valeur de corrélation pour le journal.
//
// L'appelant, lui, est authentifié depuis ADR-035 : son assertion identity-assertion/v1
// (X-Identity-Assertion) est vérifiée et son niveau AAL3 exigé AVANT toute évaluation du quorum.
// Ce qui reste hors périmètre est l'habilitation : ce composant sait désormais QUI initie, pas
// si cette personne a le droit d'initier CETTE opération — la granularité des rôles reste
// l'angle mort non tranché de security/threat-models/admin-api.md.
//
// L'assertion de l'appelant n'est jamais comptée parmi les porteurs du quorum : initiateur et
// porteur sont deux rôles distincts, et un initiateur qui s'auto-compterait ramènerait le quorum
// réel à un seul porteur indépendant — exactement ce que le plancher MinimumThreshold interdit.
//
// Pas de TLS dans ce lot — signalé, même limite que partout ailleurs.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	auditv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/audit/v1"
	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

// aalRequisPourInitier : niveau d'authentification minimal de l'appelant qui declenche une
// operation critique (ADR-035). Constante et non configurable : un niveau abaissable par
// configuration serait un contournement trivial du controle.
const aalRequisPourInitier = "AAL3"

type API struct {
	verifier *quorum.Verifier
	// identityClient verifie l'assertion de l'APPELANT. C'est le meme service que celui utilise
	// par quorum.Verifier pour les porteurs, mais l'appel vit ici et non dans le module quorum :
	// ADR-021 impose que quorum reste agnostique de l'operation et du role, et l'authentification
	// de l'initiateur est une preoccupation de la couche HTTP (meme decoupage qu'access-broker).
	identityClient identityv1.AssertionVerificationServiceClient
	auditClient    auditv1.AuditCollectionServiceClient
}

func New(
	v *quorum.Verifier,
	identityClient identityv1.AssertionVerificationServiceClient,
	auditClient auditv1.AuditCollectionServiceClient,
) *API {
	return &API{verifier: v, identityClient: identityClient, auditClient: auditClient}
}

// NewHandler construit le routeur en remplacant le gestionnaire d'erreur de parametres par defaut
// d'oapi-codegen, qui renvoie 400 text/plain avec err.Error() brut. Deux raisons : un en-tete
// d'assertion absent est un refus d'authentification (401), pas une requete malformee ; et le
// message d'erreur genere ne doit jamais atteindre le client tel quel.
func NewHandler(api *API) http.Handler {
	return HandlerWithOptions(api, StdHTTPServerOptions{ErrorHandlerFunc: writeParamError})
}

// writeParamError traduit les erreurs de liaison de parametres en refus explicites, sans jamais
// recopier le message d'origine dans la reponse.
func writeParamError(w http.ResponseWriter, r *http.Request, err error) {
	var manquant *RequiredHeaderError
	if errors.As(err, &manquant) {
		writeError(w, http.StatusUnauthorized, "assertion_de_lappelant_absente")
		return
	}
	writeError(w, http.StatusBadRequest, "parametre_de_requete_invalide")
}

func (a *API) VerifyQuorum(w http.ResponseWriter, r *http.Request, operationId string, params VerifyQuorumParams) {
	var body QuorumRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "corps_de_requete_malforme")
		return
	}

	// Authentification de l'appelant AVANT toute evaluation du quorum (ADR-035). L'assertion est
	// verifiee contre expected_authority_domain du corps : un appelant hors de ce domaine echoue
	// ici meme, sans qu'aucun controle de domaine separe soit necessaire.
	caller, refus := a.verifyCaller(r.Context(), params.XIdentityAssertion, body.ExpectedAuthorityDomain)
	if refus != nil {
		writeError(w, refus.status, refus.reason)
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
	a.recordQuorumInitiator(r.Context(), operationId, body.ExpectedAuthorityDomain, caller, result)

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

// refusAppelant porte le couple statut/motif d'un refus d'authentification — jamais le detail
// technique sous-jacent, qui resterait exploitable pour affiner une attaque.
type refusAppelant struct {
	status int
	reason string
}

// verifyCaller verifie l'assertion de l'appelant et impose AAL3.
//
// Refus par defaut (regle absolue #2) : une indisponibilite d'identity-provider est un refus 502
// explicite, jamais un repli permissif. Une assertion invalide et une assertion absente
// produisent le meme 401 sans distinction exploitable.
func (a *API) verifyCaller(ctx context.Context, assertion, expectedAuthorityDomain string) (*identityv1.VerifyAssertionResponse, *refusAppelant) {
	if assertion == "" {
		return nil, &refusAppelant{http.StatusUnauthorized, "assertion_de_lappelant_absente"}
	}

	resp, err := a.identityClient.VerifyAssertion(ctx, &identityv1.VerifyAssertionRequest{
		Assertion:               []byte(assertion),
		ExpectedAuthorityDomain: expectedAuthorityDomain,
	})
	if err != nil {
		return nil, &refusAppelant{http.StatusBadGateway, "verification_de_lappelant_indisponible"}
	}
	if !resp.Valid {
		return nil, &refusAppelant{http.StatusUnauthorized, "assertion_de_lappelant_invalide"}
	}
	// AAL3 exige : une operation critique ne se declenche pas depuis une session de niveau
	// inferieur, meme authentifiee. Toute valeur autre que "AAL3" — y compris vide, cas d'un
	// champ non renseigne par le verificateur (P2) — est refusee.
	if resp.Aal != aalRequisPourInitier {
		return nil, &refusAppelant{http.StatusForbidden, "niveau_dauthentification_insuffisant"}
	}
	return resp, nil
}

// recordQuorumInitiator audite QUI a declenche l'operation, en plus des porteurs.
//
// Reutilise le type d'evenement quorum.operation avec actor = initiateur : le schema d'evenement
// (contracts/events/audit-event.schema.json) n'a qu'un champ actor, et le modifier casserait la
// verifiabilite de l'historique existant. L'initiateur se distingue des porteurs par son
// auth_method, present dans l'assertion verifiee.
//
// Best-effort comme recordQuorumOperation : le quorum a deja ete evalue de facon irreversible.
func (a *API) recordQuorumInitiator(ctx context.Context, operationID, authorityDomain string, caller *identityv1.VerifyAssertionResponse, result quorum.Result) {
	outcome := "denied"
	if result.Reached {
		outcome = "success"
	}

	res, err := a.auditClient.Record(ctx, &auditv1.RawEvent{
		AuthorityDomain: authorityDomain,
		EventType:       "quorum.operation",
		Actor: &auditv1.Actor{
			SubjectId: caller.SubjectId,
			Kind:      "human",
		},
		Target: &auditv1.Target{
			Type: "critical_operation",
			Id:   operationID,
		},
		Outcome: outcome,
	})
	if err != nil {
		log.Printf("admin-api: échec de l'envoi de quorum.operation (initiateur %s, opération %s) : %v", caller.SubjectId, operationID, err)
		return
	}
	if !res.Accepted {
		log.Printf("admin-api: quorum.operation refusé par audit-collector (initiateur %s, opération %s) : %s", caller.SubjectId, operationID, res.Reason)
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
