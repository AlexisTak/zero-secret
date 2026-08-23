//! Endpoints HTTP de cérémonie WebAuthn (H5, ADR-023, `contracts/openapi/identity-provider.yaml`).
//! Traduit HTTP <-> `zs_webauthn::{registration, authentication}` (vérification pure) et
//! `zs_crypto::{identity_assertion, audit_seal}` (scellement, via `zs-hsm`). Aucune logique
//! cryptographique n'est écrite ici — seulement l'orchestration : consommer le challenge avant
//! de vérifier, jamais après ; le `subject_id` d'une authentification vient toujours de
//! l'authentificateur résolu en base, jamais du corps de requête.
//!
//! Portée assumée et non résolue ici (signalée, pas cachée) : l'enregistrement accepte
//! `subject_id` tel quel dans `RegistrationChallengeRequest` — aucun mécanisme d'invitation ou
//! de première authentification n'est instruit dans ce lot (bootstrap du tout premier facteur,
//! angle mort documenté par ADR-023).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;

use zs_crypto::audit_seal::{
    self, Actor as AuditActor, ActorKind, AuditEventFields, AuditSealer,
    EventType as AuditEventType, Outcome as AuditOutcome, Sequence, Target as AuditTarget,
};
use zs_crypto::authenticator_proof::{self, Challenge};
use zs_crypto::identity_assertion::{self, AssertionClaims, AssertionSealer, AssuranceLevel};
use zs_webauthn::authentication::{
    Aal, AuthenticationCeremonyInput, RegisteredCredential, verify_authentication_ceremony,
};
use zs_webauthn::policy::AttestationPolicy;
use zs_webauthn::registration::{RegistrationCeremonyInput, verify_registration_ceremony};

use crate::store::{AuditStore, IdentityStore};

pub struct AppState {
    pub identity_store: IdentityStore,
    pub audit_store: AuditStore,
    pub assertion_sealer: AssertionSealer,
    pub audit_sealer: AuditSealer,
    pub rp_id: String,
    pub origin: String,
    pub authority_domain: String,
    pub audience: String,
    pub challenge_ttl_seconds: i64,
    pub assertion_ttl_seconds: i64,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/v1/webauthn/registration/challenge",
            post(registration_challenge),
        )
        .route(
            "/v1/webauthn/registration/verify",
            post(registration_verify),
        )
        .route(
            "/v1/webauthn/authentication/challenge",
            post(authentication_challenge),
        )
        .route(
            "/v1/webauthn/authentication/verify",
            post(authentication_verify),
        )
        .with_state(state)
}

fn b64_decode(field: &str, value: &str) -> Result<Vec<u8>, ApiError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad_request(format!("{field}_encodage_invalide")))
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Extrait le challenge présenté par le navigateur depuis `clientDataJSON`, **sans le valider**
/// (la validation complète — type, origine, concordance — reste à `zs_webauthn::client_data`,
/// appelée plus loin par `verify_*_ceremony`). Seule cette lecture minimale est nécessaire pour
/// savoir quelle ligne de `identity.challenges` consommer.
fn presented_challenge_bytes(client_data_json: &[u8]) -> Result<Vec<u8>, ApiError> {
    #[derive(Deserialize)]
    struct Partial {
        challenge: String,
    }
    let partial: Partial = serde_json::from_slice(client_data_json)
        .map_err(|_| ApiError::bad_request("client_data_json_invalide"))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&partial.challenge)
        .map_err(|_| ApiError::bad_request("challenge_encodage_invalide"))
}

fn now_rfc3339() -> String {
    crate::rfc3339_now()
}

/// Encodage hexadécimal minuscule — pas une opération cryptographique (règle absolue #4) :
/// `zs_crypto::common::hex_encode` existe mais n'est pas ré-exportée publiquement (interne au
/// crate), une duplication triviale de ce formatage est préférable à l'exposer.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// --- registration/challenge ------------------------------------------------------------------

#[derive(Deserialize)]
struct RegistrationChallengeRequest {
    subject_id: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
    rp_id: String,
    expires_at: String,
}

async fn registration_challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegistrationChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let challenge = authenticator_proof::new_challenge();
    state
        .identity_store
        .issue_challenge(
            challenge.as_bytes(),
            &req.subject_id,
            "registration",
            state.challenge_ttl_seconds,
        )
        .await
        .map_err(ApiError::store_unavailable)?;
    let (_, expires_at) = crate::rfc3339_now_and_after(state.challenge_ttl_seconds);

    Ok(Json(ChallengeResponse {
        challenge: b64_encode(challenge.as_bytes()),
        rp_id: state.rp_id.clone(),
        expires_at,
    }))
}

// --- registration/verify ---------------------------------------------------------------------

#[derive(Deserialize)]
struct RegistrationVerifyRequest {
    client_data_json: String,
    attestation_object: String,
}

#[derive(Serialize)]
struct RegistrationVerifyResponse {
    credential_id: String,
}

async fn registration_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegistrationVerifyRequest>,
) -> Result<Json<RegistrationVerifyResponse>, ApiError> {
    let client_data_json = b64_decode("client_data_json", &req.client_data_json)?;
    let attestation_object = b64_decode("attestation_object", &req.attestation_object)?;

    let presented = presented_challenge_bytes(&client_data_json)?;

    // Consommé AVANT verify_registration_ceremony — un échec de vérification ne doit jamais
    // laisser le challenge rejouable (mise en garde referent-crypto, H5).
    let consumed = state
        .identity_store
        .consume_challenge(&presented, "registration")
        .await
        .map_err(ApiError::store_unavailable)?
        .ok_or_else(|| ApiError::bad_request("challenge_invalide"))?;

    let challenge = identity_assertion_challenge(presented)?;

    let outcome = verify_registration_ceremony(RegistrationCeremonyInput {
        client_data_json: &client_data_json,
        attestation_object: &attestation_object,
        expected_origin: &state.origin,
        expected_rp_id: &state.rp_id,
        expected_challenge: &challenge,
        policy: AttestationPolicy::Any,
    })
    .map_err(|e| ApiError::unauthorized(format!("cérémonie_invalide : {e}")))?;

    // Figé une fois, jamais réévalué (migration 004) : un sign_count non nul dès
    // l'enregistrement signale un compteur significatif.
    let counter_supported = outcome.sign_count != 0;

    state
        .identity_store
        .insert_authenticator(
            &consumed.subject_id,
            &outcome.credential_id,
            outcome.public_key_algorithm,
            &outcome.public_key_raw,
            outcome.sign_count,
            &outcome.aaguid,
            outcome.attestation_format,
            counter_supported,
        )
        .await
        .map_err(ApiError::store_unavailable)?;

    seal_and_append_audit_event(
        &state,
        AuditEventType::AuthenticatorRegistered,
        &consumed.subject_id,
        None,
        None,
        AuditOutcome::Success,
    )
    .await?;

    Ok(Json(RegistrationVerifyResponse {
        credential_id: b64_encode(&outcome.credential_id),
    }))
}

fn identity_assertion_challenge(bytes: Vec<u8>) -> Result<Challenge, ApiError> {
    authenticator_proof::accept_challenge(authenticator_proof::SUITE_V1, bytes)
        .map_err(|_| ApiError::bad_request("challenge_invalide"))
}

// --- authentication/challenge -----------------------------------------------------------------

#[derive(Deserialize)]
struct AuthenticationChallengeRequest {
    subject_id: String,
}

#[derive(Serialize)]
struct AuthenticationChallengeResponse {
    challenge: String,
    rp_id: String,
    expires_at: String,
    allow_credentials: Vec<String>,
}

async fn authentication_challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthenticationChallengeRequest>,
) -> Result<Json<AuthenticationChallengeResponse>, ApiError> {
    let challenge = authenticator_proof::new_challenge();
    state
        .identity_store
        .issue_challenge(
            challenge.as_bytes(),
            &req.subject_id,
            "authentication",
            state.challenge_ttl_seconds,
        )
        .await
        .map_err(ApiError::store_unavailable)?;
    let (_, expires_at) = crate::rfc3339_now_and_after(state.challenge_ttl_seconds);

    // Liste vide si le sujet n'a aucun credential — pas d'oracle sur l'existence du sujet
    // (même refus par défaut, même absence de distinction, que ChallengeStore::consume).
    let credential_ids = state
        .identity_store
        .credential_ids_for_subject(&req.subject_id)
        .await
        .map_err(ApiError::store_unavailable)?;

    Ok(Json(AuthenticationChallengeResponse {
        challenge: b64_encode(challenge.as_bytes()),
        rp_id: state.rp_id.clone(),
        expires_at,
        allow_credentials: credential_ids.iter().map(|c| b64_encode(c)).collect(),
    }))
}

// --- authentication/verify ----------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthenticationVerifyRequest {
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

#[derive(Serialize)]
struct AuthenticationVerifyResponse {
    assertion: String,
}

async fn authentication_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthenticationVerifyRequest>,
) -> Result<Json<AuthenticationVerifyResponse>, ApiError> {
    let credential_id = b64_decode("credential_id", &req.credential_id)?;
    let client_data_json = b64_decode("client_data_json", &req.client_data_json)?;
    let authenticator_data = b64_decode("authenticator_data", &req.authenticator_data)?;
    let signature = b64_decode("signature", &req.signature)?;

    let presented = presented_challenge_bytes(&client_data_json)?;

    let consumed = state
        .identity_store
        .consume_challenge(&presented, "authentication")
        .await
        .map_err(ApiError::store_unavailable)?
        .ok_or_else(|| ApiError::unauthorized("challenge_invalide"))?;
    let _ = consumed; // subject_id de la ligne de challenge — non réutilisé ici : le sujet
    // authentifié vient du credential résolu ci-dessous, jamais du challenge.

    let row = state
        .identity_store
        .find_authenticator(&credential_id)
        .await
        .map_err(ApiError::store_unavailable)?
        .ok_or_else(|| ApiError::unauthorized("authentification_refusee"))?;

    let challenge = identity_assertion_challenge(presented)?;

    let credential = RegisteredCredential {
        subject_id: row.subject_id.clone(),
        credential_id: row.credential_id.clone(),
        public_key_algorithm: row.algorithm,
        public_key_raw: row.public_key.clone(),
        counter_supported: row.counter_supported,
        stored_sign_count: row.sign_count,
        revoked: row.revoked,
    };

    let claims = verify_authentication_ceremony(AuthenticationCeremonyInput {
        client_data_json: &client_data_json,
        authenticator_data: &authenticator_data,
        signature: &signature,
        expected_origin: &state.origin,
        expected_rp_id: &state.rp_id,
        expected_challenge: &challenge,
        credential: &credential,
    })
    .map_err(|_| ApiError::unauthorized("authentification_refusee"))?;

    // Avance atomique, autoritative — le contrôle fait par verify_authentication_ceremony
    // porte sur la valeur lue avant cet appel ; un concurrent peut avoir avancé le compteur
    // entre-temps (fenêtre TOCTOU), c'est cette écriture-ci qui tranche en dernier ressort.
    let advanced = state
        .identity_store
        .advance_sign_count(&credential.credential_id, claims.new_sign_count)
        .await
        .map_err(ApiError::store_unavailable)?;

    if !advanced {
        seal_and_append_audit_event(
            &state,
            AuditEventType::AuthenticationFailed,
            &claims.subject_id,
            None,
            Some("clonage_suspecte_compteur_concurrent"),
            AuditOutcome::Denied,
        )
        .await?;
        return Err(ApiError::unauthorized("authentification_refusee"));
    }

    let event_id = uuid::Uuid::now_v7().to_string();
    let (now, expires_at) = crate::rfc3339_now_and_after(state.assertion_ttl_seconds);
    let aal = match claims.aal {
        Aal::Aal1 => AssuranceLevel::Aal1,
        Aal::Aal2 => AssuranceLevel::Aal2,
    };

    let assertion_claims = AssertionClaims {
        authority_domain: state.authority_domain.clone(),
        subject_id: identity_assertion::SubjectId::new(claims.subject_id.clone())
            .map_err(|_| ApiError::internal())?,
        aal,
        auth_method: identity_assertion::AuthMethod::new(claims.method)
            .map_err(|_| ApiError::internal())?,
        audience: identity_assertion::Audience::new(state.audience.clone())
            .map_err(|_| ApiError::internal())?,
        issued_at: identity_assertion::Timestamp::new(now.clone())
            .map_err(|_| ApiError::internal())?,
        expires_at: identity_assertion::Timestamp::new(expires_at.clone())
            .map_err(|_| ApiError::internal())?,
        audit_event_id: identity_assertion::EventId::new(event_id.clone())
            .map_err(|_| ApiError::internal())?,
    };

    let sealed_assertion = {
        let state = Arc::clone(&state);
        tokio::task::spawn_blocking(move || state.assertion_sealer.seal(assertion_claims))
            .await
            .map_err(|_| ApiError::internal())?
            .map_err(ApiError::sealing_unavailable)?
    };

    let digest_hex = hex_encode(&sealed_assertion.digest());

    seal_and_append_audit_event(
        &state,
        AuditEventType::AuthenticationSucceeded,
        &claims.subject_id,
        Some((event_id.as_str(), "identity_assertion", digest_hex.as_str())),
        None,
        AuditOutcome::Success,
    )
    .await?;

    Ok(Json(AuthenticationVerifyResponse {
        assertion: b64_encode(sealed_assertion.as_bytes()),
    }))
}

/// Scelle et persiste un événement d'audit — jamais optionnel (règle absolue #9) : si
/// l'ajout à la chaîne échoue, l'appelant ne doit pas pouvoir prétendre que l'action a réussi.
/// `explicit_event_id` permet de réutiliser l'identifiant déjà généré pour une assertion scellée
/// (R7 : l'`audit_event_id` de l'assertion doit être celui de l'événement qui la couvre).
async fn seal_and_append_audit_event(
    state: &Arc<AppState>,
    event_type: AuditEventType,
    subject_id: &str,
    explicit_event_id_and_target: Option<(&str, &str, &str)>,
    justification: Option<&str>,
    outcome: AuditOutcome,
) -> Result<(), ApiError> {
    let head = state
        .audit_store
        .chain_head(&state.authority_domain)
        .await
        .map_err(ApiError::store_unavailable)?;

    let event_id_string = match explicit_event_id_and_target {
        Some((id, _, _)) => id.to_string(),
        None => uuid::Uuid::now_v7().to_string(),
    };
    let target = explicit_event_id_and_target.map(|(_, target_type, id)| AuditTarget {
        target_type: audit_seal::ShortText::new(target_type).expect("constante interne valide"),
        id: audit_seal::ShortText::new(id).expect("hex encodé, longueur bornée"),
    });

    let fields = AuditEventFields {
        event_id: audit_seal::EventId::new(event_id_string.clone())
            .map_err(|_| ApiError::internal())?,
        sequence: Sequence::new(head.next_sequence).map_err(|_| ApiError::internal())?,
        prev_hash: head.prev_hash,
        occurred_at: audit_seal::Timestamp::new(now_rfc3339()).map_err(|_| ApiError::internal())?,
        authority_domain: audit_seal::AuthorityDomain::new(state.authority_domain.clone())
            .map_err(|_| ApiError::internal())?,
        event_type,
        actor: AuditActor {
            subject_id: identity_assertion::SubjectId::new(subject_id.to_string())
                .map_err(|_| ApiError::internal())?,
            kind: ActorKind::Human,
            aal: None,
            auth_method: None,
        },
        target,
        outcome,
        context: justification.map(|j| audit_seal::Context {
            source_network: None,
            ticket_ref: None,
            justification: audit_seal::Justification::new(j).ok(),
        }),
    };

    let sealed = {
        let state = Arc::clone(state);
        tokio::task::spawn_blocking(move || state.audit_sealer.seal(fields))
            .await
            .map_err(|_| ApiError::internal())?
            .map_err(ApiError::sealing_unavailable)?
    };

    state
        .audit_store
        .append(
            &event_id_string,
            head.next_sequence,
            &now_rfc3339(),
            &state.authority_domain,
            event_type_str(event_type),
            actor_json(subject_id),
            outcome_str(outcome),
            &hex_encode(&head.prev_hash),
            signature_json(&sealed),
            sealed.as_bytes(),
        )
        .await
        .map_err(ApiError::store_unavailable)?;

    Ok(())
}

fn event_type_str(t: AuditEventType) -> &'static str {
    match t {
        AuditEventType::AuthenticatorRegistered => "authenticator.registered",
        AuditEventType::AuthenticatorRevoked => "authenticator.revoked",
        AuditEventType::AuthenticationAttempted => "authentication.attempted",
        AuditEventType::AuthenticationSucceeded => "authentication.succeeded",
        AuditEventType::AuthenticationFailed => "authentication.failed",
        AuditEventType::RecoveryInitiated => "recovery.initiated",
        AuditEventType::QuorumOperation => "quorum.operation",
        AuditEventType::AuditChainVerified => "audit.chain_verified",
    }
}

fn outcome_str(o: AuditOutcome) -> &'static str {
    match o {
        AuditOutcome::Success => "success",
        AuditOutcome::Denied => "denied",
        AuditOutcome::Error => "error",
    }
}

fn actor_json(subject_id: &str) -> serde_json::Value {
    json!({ "subject_id": subject_id, "kind": "human" })
}

fn signature_json(sealed: &audit_seal::SealedAuditEvent) -> serde_json::Value {
    // Reconstruction minimale pour la colonne `signature` (jsonb) de audit.events — le contenu
    // probant réel est `sealed.as_bytes()` (colonne `sealed_bytes`), cette valeur ne sert qu'à
    // l'inspection humaine directe en base, jamais à la vérification (qui relit `sealed_bytes`).
    json!({ "suite": sealed.suite() })
}

// --- erreurs HTTP --------------------------------------------------------------------------

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    reason: String,
}

impl ApiError {
    fn bad_request(reason: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            reason: reason.into(),
        }
    }

    fn unauthorized(reason: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            reason: reason.into(),
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            reason: "erreur_interne".to_string(),
        }
    }

    fn store_unavailable(_: sqlx::Error) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            reason: "base_de_donnees_indisponible".to_string(),
        }
    }

    fn sealing_unavailable<E: std::fmt::Display>(_: E) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            reason: "scellement_indisponible".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "reason": self.reason }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- b64_decode / b64_encode : base64url sans padding (RFC 4648 §5) ---------------------
    #[test]
    fn b64_round_trip_preserve_les_octets() {
        let original = b"\x00\x01\xfe\xff-webauthn-";
        let encoded = b64_encode(original);
        assert!(!encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='));
        assert_eq!(b64_decode("champ", &encoded).unwrap(), original);
    }

    #[test]
    fn b64_decode_refuse_un_encodage_standard_avec_padding() {
        // "AAA=" est du base64 standard valide, mais pas base64url-sans-padding — refusé.
        assert!(b64_decode("champ", "AAA=").is_err());
    }

    // --- presented_challenge_bytes ------------------------------------------------------------
    #[test]
    fn presented_challenge_bytes_extrait_le_challenge_du_json() {
        let challenge = b"0123456789abcdef0123456789abcdef";
        let encoded = b64_encode(challenge);
        let cdj = serde_json::json!({
            "type": "webauthn.get",
            "challenge": encoded,
            "origin": "https://zero-secret.example",
        })
        .to_string();

        assert_eq!(
            presented_challenge_bytes(cdj.as_bytes()).unwrap(),
            challenge
        );
    }

    #[test]
    fn presented_challenge_bytes_refuse_un_json_malforme() {
        assert!(presented_challenge_bytes(b"{not json").is_err());
    }

    #[test]
    fn presented_challenge_bytes_refuse_un_champ_challenge_manquant() {
        let cdj = serde_json::json!({ "type": "webauthn.get", "origin": "x" }).to_string();
        assert!(presented_challenge_bytes(cdj.as_bytes()).is_err());
    }

    // --- hex_encode ----------------------------------------------------------------------------
    #[test]
    fn hex_encode_produit_des_paires_hexadecimales_minuscules() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
    }
}
