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
// Le sujet de l'appelant est EXCLU du comptage des porteurs (excludeInitiator) : sans cette
// exclusion, un porteur qui se declare aussi initiateur atteindrait un quorum de 2 avec un seul
// approbateur reellement independant de lui — la lettre du plancher MinimumThreshold serait
// respectee, son intention non.
//
// Pas de TLS dans ce lot — signalé, même limite que partout ailleurs.
package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	auditv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/audit/v1"
	identityv1 "github.com/AlexisTak/biscuits-shield/pkg/gen/identity/v1"

	"github.com/AlexisTak/biscuits-shield/apps/admin-api/internal/quorum"
)

// aalRequisPourInitier : niveau d'authentification minimal de l'appelant qui declenche une
// operation critique (ADR-035). Constante et non configurable : un niveau abaissable par
// configuration serait un contournement trivial du controle.
const aalRequisPourInitier = "AAL3"

// enTeteAssertionAppelant : nom de l'en-tete portant l'assertion de l'initiateur, aligne sur
// access-broker. Constante partagee entre le handler et writeParamError, qui doivent designer
// exactement le meme parametre.
const enTeteAssertionAppelant = "X-Identity-Assertion"

// MotifExclusionInitiateur est la valeur EXACTE portee par context.justification de l'evenement
// d'initiateur lorsque son assertion de porteur a ete ecartee du quorum. Constante exportee, et
// non chaine libre ecrite en place : le rejeu hors ligne (zs-replay, ADR-034) doit pouvoir la
// reconnaitre par egalite, jamais par appariement de sous-chaine.
const MotifExclusionInitiateur = "assertion de porteur de l'initiateur ecartee du quorum (ADR-035)"

// maxOctetsCorps borne la lecture du corps AVANT toute authentification : le decodage JSON precede
// necessairement la verification de l'appelant (expected_authority_domain, contre lequel son
// assertion est verifiee, vient du corps). Sans cette borne, un anonyme fait allouer autant qu'il
// veut. Dimensionne pour maxAssertions assertions de 4096 octets (MAX_BYTES de
// zs-crypto/src/identity_assertion.rs) encodees en base64, plus l'enveloppe JSON.
const maxOctetsCorps = 512 * 1024

// maxAssertions borne le nombre de porteurs, et donc le nombre d'appels gRPC sortants declenches
// par une seule requete — sans quoi un appelant authentifie une fois amplifie sa requete en
// autant d'appels vers identity-provider qu'il place d'assertions. Egalement declare au contrat
// (maxItems) : ici c'est l'application qui refuse, le contrat qui documente.
const maxAssertions = 64

// delaiVerification borne la verification de l'appelant, premier appel sortant du handler.
const delaiVerification = 5 * time.Second

// delaiEvaluation borne l'EVALUATION : verification de l'appelant, puis jusqu'a maxAssertions
// verifications de porteurs faites en serie par le module quorum. Un delai pose sur le seul
// appelant laissait ces N appels sans echeance — un verificateur lent, ou tenu par l'attaquant,
// immobilisait alors un goroutine jusqu'a deconnexion du client.
const delaiEvaluation = 25 * time.Second

// delaiAudit borne CHAQUE envoi d'audit pris isolement, sur un budget detache de celui de
// l'evaluation.
//
// Deux pieges evites, tous deux du meme genre : un budget partage avec l'evaluation, puis un
// budget unique partage entre les N+1 envois. Dans les deux cas l'appelant garde le levier — il
// choisit le nombre de porteurs, donc le nombre d'appels sortants en serie — et epuise le budget
// avant le dernier envoi. Les evenements perdus sont alors ceux de la fin de lot, l'operation
// critique aboutissant malgre tout en 200 : suppression de trace pilotee par l'attaquant, ce
// qu'interdit la regle absolue #9. Un budget PAR EVENEMENT supprime ce levier : le cout d'un envoi
// ne depend plus de ce qui a ete envoye avant.
const delaiAudit = 5 * time.Second

// plafondAudit borne la phase d'audit PRISE DANS SON ENSEMBLE, en plus du budget par evenement.
//
// Les deux bornes sont necessaires et repondent a deux menaces opposees. Sans budget par
// evenement, l'appelant epuise le lot et supprime les dernieres traces (repudiation). Sans
// plafond agrege, la duree de la requete devient proportionnelle au nombre de porteurs qu'il
// choisit — jusqu'a (maxAssertions + 1) x delaiAudit — et immobilise un goroutine sur le
// composant qui porte le chemin de revocation d'urgence (deni de service).
//
// L'arbitrage entre les deux est rendu acceptable par l'ORDRE : l'initiateur part en premier,
// donc la trace la plus precieuse est emise avant que le plafond puisse mordre. Un depassement
// est journalise, jamais silencieux.
const plafondAudit = 15 * time.Second

type API struct {
	verifier *quorum.Verifier
	// identityClient verifie l'assertion de l'APPELANT. C'est le meme service que celui utilise
	// par quorum.Verifier pour les porteurs, mais l'appel vit ici et non dans le module quorum :
	// ADR-021 impose que quorum reste agnostique de l'operation et du role, et l'authentification
	// de l'initiateur est une preoccupation de la couche HTTP (meme decoupage qu'access-broker).
	identityClient identityv1.AssertionVerificationServiceClient
	auditClient    auditv1.AuditCollectionServiceClient
	// expectedAuthorityDomain est fixe par la configuration du binaire, jamais deduit de la
	// requete. Laisser l'appelant choisir le domaine contre lequel il est verifie rendrait le
	// controle tautologique des qu'un identity-provider accepte plus d'un domaine : il suffirait
	// de presenter des assertions d'un domaine A pour agir sur le perimetre B.
	expectedAuthorityDomain string
	// Budgets portes par l'instance plutot que lus depuis les constantes : les tests les
	// raccourcissent pour exercer les chemins de depassement sans attendre les valeurs de
	// production. Champs non exportes, initialises par New — jamais une variable globale mutable.
	delaiVerification time.Duration
	delaiEvaluation   time.Duration
	delaiAudit        time.Duration
	plafondAudit      time.Duration
}

func New(
	v *quorum.Verifier,
	identityClient identityv1.AssertionVerificationServiceClient,
	auditClient auditv1.AuditCollectionServiceClient,
	expectedAuthorityDomain string,
) *API {
	return &API{
		verifier:                v,
		identityClient:          identityClient,
		auditClient:             auditClient,
		expectedAuthorityDomain: expectedAuthorityDomain,
		delaiVerification:       delaiVerification,
		delaiEvaluation:         delaiEvaluation,
		delaiAudit:              delaiAudit,
		plafondAudit:            plafondAudit,
	}
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
	// Un en-tete d'assertion non decodable en base64 est refuse par le binding genere avant
	// d'atteindre le handler. C'est un refus d'AUTHENTIFICATION (401), pas une requete malformee :
	// le statut doit dire la meme chose que si l'assertion avait ete rejetee par le verificateur,
	// sans quoi un client apprend, par le seul code de statut, ou son assertion a echoue.
	var format *InvalidParamFormatError
	if errors.As(err, &format) && format.ParamName == enTeteAssertionAppelant {
		writeError(w, http.StatusUnauthorized, "assertion_de_lappelant_malformee")
		return
	}
	// Deux en-tetes d'assertion : refus d'authentification lui aussi. Le laisser retomber sur le
	// 400 generique donnerait un statut different d'un en-tete absent ou illisible, et renseignerait
	// donc l'appelant sur l'endroit exact ou son assertion a echoue.
	var multiple *TooManyValuesForParamError
	if errors.As(err, &multiple) && multiple.ParamName == enTeteAssertionAppelant {
		writeError(w, http.StatusUnauthorized, "assertion_de_lappelant_malformee")
		return
	}
	writeError(w, http.StatusBadRequest, "parametre_de_requete_invalide")
}

func (a *API) VerifyQuorum(w http.ResponseWriter, r *http.Request, operationId string, params VerifyQuorumParams) {
	// Budget de l'EVALUATION : verification de l'appelant puis des porteurs. Les envois d'audit
	// ont le leur (ctxAudit, plus bas), detache de celui-ci.
	ctx, annulerEvaluation := context.WithTimeout(r.Context(), a.delaiEvaluation)
	defer annulerEvaluation()

	r.Body = http.MaxBytesReader(w, r.Body, maxOctetsCorps)

	var body QuorumRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		// Corps malforme et corps trop volumineux produisent le meme refus : distinguer les deux
		// renseignerait un attaquant sur la borne exacte sans servir un client legitime.
		writeError(w, http.StatusBadRequest, "corps_de_requete_malforme")
		return
	}

	// Authentification de l'appelant AVANT tout autre controle de contenu (ADR-035). Les controles
	// de domaine et de plafond viennent APRES : places avant, ils laissaient un anonyme enumerer
	// par reponse differentielle le domaine d'autorite configure et la valeur exacte du plafond.
	// Seul MaxBytesReader, qui ne renvoie aucune information, protege le chemin anonyme.
	caller, refus := a.verifyCaller(ctx, params.XIdentityAssertion, r.Header.Get(enTeteAssertionAppelant))
	if refus != nil {
		writeError(w, refus.status, refus.reason)
		return
	}

	if len(body.Assertions) > maxAssertions {
		writeError(w, http.StatusBadRequest, "trop_dassertions")
		return
	}

	// Le domaine d'autorite est celui de la configuration, jamais celui propose par le corps.
	if body.ExpectedAuthorityDomain != a.expectedAuthorityDomain {
		writeError(w, http.StatusBadRequest, "domaine_dautorite_inattendu")
		return
	}

	// quorum.VerifyQuorum panique si threshold < MinimumThreshold (erreur de configuration de
	// l'appelant, par construction — voir ADR-021) : sur une requête HTTP non fiable, cette
	// panique doit devenir un refus explicite (400), jamais un crash du processus.
	// Le plancher est verifie ICI, explicitement, avant d'appeler le module : quorum.VerifyQuorum
	// panique sous le plancher (erreur de configuration de l'appelant par construction, ADR-021),
	// et se reposer sur cette panique pour produire un refus metier revenait a confondre un refus
	// attendu avec un defaut interne.
	if body.Threshold < quorum.MinimumThreshold {
		writeError(w, http.StatusBadRequest, "seuil_de_quorum_invalide")
		return
	}

	result, err := verifyQuorumRecovered(ctx, a.verifier, body)
	if err != nil {
		// Jamais err.Error() dans la reponse : le message enveloppe par le module quorum contient
		// l'adresse d'identity-provider et le code gRPC exact.
		//
		// Une panique atteignant ce point n'est PLUS un seuil invalide (verifie au-dessus) : c'est
		// un defaut interne. La journaliser est indispensable — sans trace serveur, un attaquant
		// qui trouverait une entree faisant paniquer le module disposerait d'un oracle silencieux,
		// distinguable par son seul code de statut, pour iterer en production.
		var interne panicError
		if errors.As(err, &interne) {
			// %q sur une valeur TRONQUEE : le message d'une panique venue de la pile gRPC peut
			// contenir tout ou partie de la requete serialisee, donc des assertions d'identite.
			// Les journaux ne contiennent jamais de credential (convention du projet), et %q
			// neutralise les sauts de ligne — sans quoi un contenu choisi injecterait des lignes
			// dans un journal ligne-oriente.
			log.Printf(
				"admin-api: panique interne lors de l'évaluation du quorum (opération %s), valeur de type %T : %q",
				operationId, interne.v, tronque(fmt.Sprint(interne.v), maxOctetsPaniqueJournalisee),
			)
			writeError(w, http.StatusInternalServerError, "defaut_interne")
			return
		}
		writeError(w, http.StatusBadGateway, "verification_des_porteurs_indisponible")
		return
	}

	// quorum.operation n'est audité que pour les porteurs réellement vérifiés
	// (result.DistinctSubjects) — jamais pour un refus avant vérification (seuil invalide, corps
	// malformé) : sans identité établie, il n'y a personne à qui attribuer l'événement.
	// Exclusion de l'initiateur AVANT l'audit et avant la reponse : le quorum publie, journalise et
	// renvoye est celui des porteurs reellement independants de celui qui declenche.
	result, initiateurEtaitPorteur := excludeInitiator(result, caller.SubjectId, body.Threshold)

	// WithoutCancel : l'audit ne doit heriter ni de l'echeance ni de l'annulation du budget
	// d'evaluation, sinon un appelant qui epuise ce budget supprime la trace de l'operation qu'il
	// vient de reussir. Il herite en revanche des valeurs du contexte de requete (tracage).
	ctxAudit, annulerAudit := context.WithTimeout(context.WithoutCancel(r.Context()), a.plafondAudit)
	defer annulerAudit()

	// L'initiateur est audite EN PREMIER : son evenement est le seul a porter qui a declenche
	// l'operation, son niveau d'authentification et l'eventuelle exclusion. Le placer en fin de
	// lot en faisait la premiere victime d'un budget epuise — l'information la plus precieuse
	// perdue en premier.
	a.recordQuorumInitiator(ctxAudit, operationId, a.expectedAuthorityDomain, caller, result, initiateurEtaitPorteur)
	a.recordQuorumOperation(ctxAudit, operationId, a.expectedAuthorityDomain, result)

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
		// Budget PAR evenement : partage entre les N envois, il serait de nouveau fonction du
		// nombre de porteurs, donc d'une quantite choisie par l'appelant.
		ctxEvenement, annuler := context.WithTimeout(ctx, a.budgetParEvenement())
		res, err := a.auditClient.Record(ctxEvenement, &auditv1.RawEvent{
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
		annuler()
		if err != nil {
			log.Printf("admin-api: échec de l'envoi de quorum.operation à audit-collector (opération %s, porteur %s) : %v", operationID, subjectID, err)
			continue
		}
		if !res.Accepted {
			log.Printf("admin-api: quorum.operation refusé par audit-collector (opération %s, porteur %s) : %s", operationID, subjectID, res.Reason)
		}
	}
}

// budgetParEvenement renvoie le budget d'un envoi d'audit, en refusant la valeur zero.
//
// Un delaiAudit nul produirait un contexte DEJA expire : aucun evenement emis, et une reponse 200
// malgre tout — perte de trace totale et silencieuse, exactement le mode de defaillance que ce
// composant cherche a fermer. La construction par New ne peut pas produire zero, mais un litteral
// &API{...} intra-paquet le pourrait : le repli sur la constante est un garde-fou structurel, pas
// une correction de bug connu.
func (a *API) budgetParEvenement() time.Duration {
	if a.delaiAudit <= 0 {
		return delaiAudit
	}
	return a.delaiAudit
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
func (a *API) verifyCaller(ctx context.Context, assertion []byte, enTeteBrut string) (*identityv1.VerifyAssertionResponse, *refusAppelant) {
	// L'en-tete est declare format: byte au contrat : le decodage base64 est fait par le binding
	// genere, jamais a la main ici. Un en-tete non decodable n'atteint pas cette fonction —
	// writeParamError le refuse en 401.
	if len(assertion) == 0 {
		return nil, &refusAppelant{http.StatusUnauthorized, "assertion_de_lappelant_absente"}
	}

	// Le decodeur du runtime genere n'est pas strict : il choisit son alphabet selon la presence
	// de padding et de caracteres URL-safe, et ne verifie pas les bits de bourrage. Une meme
	// assertion admet donc plusieurs chaines d'en-tete distinctes. On impose ici la representation
	// canonique unique (RFC 4648 §4, avec padding) en re-encodant et en comparant : sans cela, tout
	// mecanisme qui indexerait sur la chaine de l'en-tete — limitation de debit par assertion,
	// cache, deduplication de journal — verrait quatre cles pour une seule identite.
	if base64.StdEncoding.EncodeToString(assertion) != enTeteBrut {
		return nil, &refusAppelant{http.StatusUnauthorized, "assertion_de_lappelant_malformee"}
	}

	ctx, annuler := context.WithTimeout(ctx, a.delaiVerification)
	defer annuler()

	resp, err := a.identityClient.VerifyAssertion(ctx, &identityv1.VerifyAssertionRequest{
		Assertion:               assertion,
		ExpectedAuthorityDomain: a.expectedAuthorityDomain,
	})
	// resp nil sans erreur ne peut pas venir d'un vrai client gRPC, mais un intercepteur ou un
	// client de repli le pourrait : le lire sans garde paniquerait sur le chemin non authentifie.
	if err != nil || resp == nil {
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
	// subject_id et auth_method sont declares "presents seulement si valid = true" par le contrat
	// (assertion_verification.proto) : une reponse valide mais incomplete est un verificateur qui
	// ne respecte pas son contrat, pas une identite. Les accepter produirait un evenement d'audit
	// sans acteur — non-repudiation perdue — et une cle d'exclusion vide.
	if resp.SubjectId == "" || resp.AuthMethod == "" {
		return nil, &refusAppelant{http.StatusBadGateway, "verification_de_lappelant_incomplete"}
	}
	return resp, nil
}

// recordQuorumInitiator audite QUI a declenche l'operation, en plus des porteurs.
//
// Reutilise le type d'evenement quorum.operation avec actor = initiateur : le schema d'evenement
// (contracts/events/audit-event.schema.json) n'a qu'un champ actor, et le modifier casserait la
// verifiabilite de l'historique existant.
//
// actor.aal et actor.auth_method (optionnels au contrat, sealing.proto) sont renseignes ICI et
// nulle part ailleurs : c'est ce qui distingue l'evenement de l'initiateur de ceux des porteurs,
// dont le module quorum ne renvoie pas le niveau d'authentification. Sans ces champs, les N+1
// evenements d'une meme operation seraient strictement identiques en forme, et un auditeur — ou
// zs-replay (ADR-034) — compterait un approbateur de trop.
//
// Best-effort comme recordQuorumOperation : le quorum a deja ete evalue de facon irreversible.
func (a *API) recordQuorumInitiator(ctx context.Context, operationID, authorityDomain string, caller *identityv1.VerifyAssertionResponse, result quorum.Result, initiateurEtaitPorteur bool) {
	outcome := "denied"
	if result.Reached {
		outcome = "success"
	}

	evenement := &auditv1.RawEvent{
		AuthorityDomain: authorityDomain,
		EventType:       "quorum.operation",
		Actor: &auditv1.Actor{
			SubjectId:  caller.SubjectId,
			Kind:       "human",
			Aal:        &caller.Aal,
			AuthMethod: &caller.AuthMethod,
		},
		Target: &auditv1.Target{
			Type: "critical_operation",
			Id:   operationID,
		},
		Outcome: outcome,
	}
	// Sans cette trace, une tentative d'auto-approbation ne laisse AUCUNE empreinte : le resultat
	// audite est le resultat filtre, indiscernable d'une requete ou l'initiateur n'aurait soumis
	// aucune assertion de porteur. Le champ justification du contexte (contrat existant, borne a
	// 512 caracteres) porte le fait, sans modifier le schema d'evenement.
	if initiateurEtaitPorteur {
		motif := MotifExclusionInitiateur
		evenement.Context = &auditv1.Context{Justification: &motif}
	}

	ctxEvenement, annuler := context.WithTimeout(ctx, a.budgetParEvenement())
	defer annuler()

	res, err := a.auditClient.Record(ctxEvenement, evenement)
	if err != nil {
		log.Printf("admin-api: échec de l'envoi de quorum.operation (initiateur %s, opération %s) : %v", caller.SubjectId, operationID, err)
		return
	}
	if !res.Accepted {
		log.Printf("admin-api: quorum.operation refusé par audit-collector (initiateur %s, opération %s) : %s", caller.SubjectId, operationID, res.Reason)
	}
}

// excludeInitiator retire le sujet de l'initiateur des porteurs comptes, puis reevalue l'atteinte
// du seuil sur les porteurs restants.
//
// Rien n'interdit a un porteur de se declarer aussi initiateur : son assertion peut figurer dans
// l'en-tete ET dans le corps. Sans cette exclusion, un quorum de 2 serait atteint avec un seul
// approbateur independant de celui qui declenche l'operation — le controle serait respecte a la
// lettre et vide de sens.
//
// Vit dans la couche HTTP et non dans le module quorum : ADR-021 impose que quorum ignore
// l'operation et les roles, et l'initiateur est une notion de la couche HTTP.
func excludeInitiator(result quorum.Result, initiateur string, threshold int) (quorum.Result, bool) {
	porteurs := slices.DeleteFunc(slices.Clone(result.DistinctSubjects), func(sujet string) bool {
		return sujet == initiateur
	})
	exclu := len(porteurs) != len(result.DistinctSubjects)
	return quorum.Result{
		Reached:          len(porteurs) >= threshold,
		DistinctSubjects: porteurs,
	}, exclu
}

// maxOctetsPaniqueJournalisee borne ce qui est recopie d'une valeur de panique dans le journal.
const maxOctetsPaniqueJournalisee = 200

// tronque coupe une chaine a n octets, en signalant la coupe.
func tronque(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(tronqué)"
}

func verifyQuorumRecovered(ctx context.Context, v *quorum.Verifier, body QuorumRequest) (result quorum.Result, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = errPanic(rec)
		}
	}()
	result, callErr := v.VerifyQuorum(ctx, body.ExpectedAuthorityDomain, body.Assertions, body.Threshold)
	if callErr != nil {
		return quorum.Result{}, callErr
	}
	return result, nil
}

type panicError struct{ v any }

// Le plancher de quorum etant desormais verifie explicitement AVANT l'appel au module, ce type ne
// represente plus jamais un seuil invalide mais un defaut interne. Le message le dit : laisser
// "seuil_de_quorum_invalide" ferait conclure a tort a un refus metier a la premiere relecture.
func (e panicError) Error() string { return "panique interne du module quorum" }

func errPanic(v any) error { return panicError{v: v} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, Error{Reason: reason})
}
