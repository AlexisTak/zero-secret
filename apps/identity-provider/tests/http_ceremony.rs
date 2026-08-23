//! Tests d'intégration HTTP de bout en bout contre un **vrai** SoftHSM2 et une **vraie**
//! Postgres (H5, ADR-023) — même discipline que `crates/zs-hsm/tests/pkcs11_integration.rs` :
//! `#[ignore]` par défaut, activé par `make test-crypto`/CI dédiée, jamais un mock du HSM ou de
//! la base (ce serait exactement le repli logiciel que l'invariant 7 de `zs-crypto` interdit,
//! déguisé en test). Le routeur axum est appelé en process (`tower::ServiceExt::oneshot`), sans
//! socket réel — évite une dépendance client HTTP pour ce seul besoin (règle absolue #10).
//!
//! Variables requises, toutes obligatoires — absentes, le test échoue plutôt que de se dérober
//! silencieusement : `ZS_HSM_MODULE`, `SOFTHSM2_PIN`, `ZS_IDP_IDENTITY_DATABASE_URL`,
//! `ZS_IDP_AUDIT_DATABASE_URL` (pointant vers une base avec les migrations `deploy/migrations/`
//! déjà appliquées — `make up` les applique via `tools/migrate.sh`).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use identity_provider::httpapi::{self, AppState};
use identity_provider::store::{AuditStore, IdentityStore};

use secrecy::SecretString;
use std::time::Duration;
use zs_crypto::audit_seal::{AuditSealer, HsmSettings as AuditHsmSettings};
use zs_crypto::identity_assertion::{AssertionSealer, HsmSettings as AssertionHsmSettings};

const RP_ID: &str = "zero-secret.example";
const ORIGIN: &str = "https://zero-secret.example";

fn require_env(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| {
        panic!(
            "{var} doit être défini pour ce test d'intégration — il échoue plutôt que de se \
             dérober silencieusement (même discipline que pkcs11_integration.rs, ADR-011)."
        )
    })
}

async fn build_state(unique_suffix: &str) -> Arc<AppState> {
    let module_path: std::path::PathBuf = require_env("ZS_HSM_MODULE").into();
    let pin = SecretString::from(require_env("SOFTHSM2_PIN"));

    let assertion_sealer = AssertionSealer::open(AssertionHsmSettings {
        module_path: module_path.clone(),
        slot_id: None,
        pin: pin.clone(),
        pool_size: 2,
        acquire_timeout: Duration::from_secs(5),
        key_label: "zs-identity-assertion-v1".to_string(),
    })
    .expect("ouverture du scelleur d'assertions (SoftHSM2 provisionné par make setup)");

    let audit_sealer = AuditSealer::open(AuditHsmSettings {
        module_path,
        slot_id: None,
        pin,
        pool_size: 2,
        acquire_timeout: Duration::from_secs(5),
        key_label: "zs-audit-seal-v1".to_string(),
    })
    .expect("ouverture du scelleur d'audit");

    let identity_store = IdentityStore::connect(&require_env("ZS_IDP_IDENTITY_DATABASE_URL"))
        .await
        .expect("connexion identity_app (make up doit avoir appliqué les migrations)");
    let audit_store = AuditStore::connect(&require_env("ZS_IDP_AUDIT_DATABASE_URL"))
        .await
        .expect("connexion audit_writer");

    Arc::new(AppState {
        identity_store,
        audit_store,
        assertion_sealer,
        audit_sealer,
        rp_id: RP_ID.to_string(),
        origin: ORIGIN.to_string(),
        authority_domain: format!("identity-provider-test-{unique_suffix}"),
        audience: "test-audience".to_string(),
        challenge_ttl_seconds: 120,
        assertion_ttl_seconds: 120,
    })
}

async fn post_json(
    router: axum::Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64_field(json: &serde_json::Value, field: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(json[field].as_str().unwrap())
        .unwrap()
}

/// Authentificateur FIDO2 de test — reproduit exactement le patron de
/// `crates/zs-webauthn/src/registration.rs::tests::TestAuthenticator`, dupliqué ici faute
/// d'export public depuis le crate (les fixtures de test n'y sont délibérément pas exposées).
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self, KeyPair};
    use ciborium::value::{Integer, Value as CborValue};
    use coset::{CborSerializable, CoseKeyBuilder, iana};

    pub struct TestAuthenticator {
        keypair: signature::EcdsaKeyPair,
        rng: SystemRandom,
    }

    impl TestAuthenticator {
        pub fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )
            .unwrap();
            let keypair = signature::EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8.as_ref(),
            )
            .unwrap();
            Self { keypair, rng }
        }

        fn cose_public_key(&self) -> Vec<u8> {
            let raw = self.keypair.public_key().as_ref();
            let x = raw[1..33].to_vec();
            let y = raw[33..65].to_vec();
            CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
                .algorithm(iana::Algorithm::ES256)
                .build()
                .to_vec()
                .unwrap()
        }

        pub fn auth_data(
            &self,
            rp_id: &str,
            flags: u8,
            sign_count: u32,
            credential_id: &[u8],
        ) -> Vec<u8> {
            let mut data = Vec::new();
            data.extend_from_slice(&sha256(rp_id.as_bytes()));
            data.push(flags);
            data.extend_from_slice(&sign_count.to_be_bytes());
            if flags & 0x40 != 0 {
                data.extend_from_slice(&[0xAA; 16]);
                data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
                data.extend_from_slice(credential_id);
                data.extend_from_slice(&self.cose_public_key());
            }
            data
        }

        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.keypair
                .sign(&self.rng, message)
                .unwrap()
                .as_ref()
                .to_vec()
        }

        pub fn attestation_object_none(&self, auth_data: &[u8]) -> Vec<u8> {
            let cbor = CborValue::Map(vec![
                (
                    CborValue::Text("fmt".into()),
                    CborValue::Text("none".into()),
                ),
                (CborValue::Text("attStmt".into()), CborValue::Map(vec![])),
                (
                    CborValue::Text("authData".into()),
                    CborValue::Bytes(auth_data.to_vec()),
                ),
            ]);
            let mut out = Vec::new();
            ciborium::ser::into_writer(&cbor, &mut out).unwrap();
            out
        }

        #[allow(dead_code)]
        pub fn attestation_object_packed(
            &self,
            auth_data: &[u8],
            client_data_json: &[u8],
        ) -> Vec<u8> {
            let client_data_hash = sha256(client_data_json);
            let mut signed_message = auth_data.to_vec();
            signed_message.extend_from_slice(&client_data_hash);
            let sig = self.sign(&signed_message);
            let att_stmt = CborValue::Map(vec![
                (
                    CborValue::Text("alg".into()),
                    CborValue::Integer(Integer::from(-7)),
                ),
                (CborValue::Text("sig".into()), CborValue::Bytes(sig)),
            ]);
            let cbor = CborValue::Map(vec![
                (
                    CborValue::Text("fmt".into()),
                    CborValue::Text("packed".into()),
                ),
                (CborValue::Text("attStmt".into()), att_stmt),
                (
                    CborValue::Text("authData".into()),
                    CborValue::Bytes(auth_data.to_vec()),
                ),
            ]);
            let mut out = Vec::new();
            ciborium::ser::into_writer(&cbor, &mut out).unwrap();
            out
        }
    }

    pub fn sha256(data: &[u8]) -> [u8; 32] {
        use aws_lc_rs::digest;
        let d = digest::digest(&digest::SHA256, data);
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }

    pub fn client_data_json(ceremony_type: &str, origin: &str, challenge: &[u8]) -> Vec<u8> {
        use base64::Engine;
        serde_json::json!({
            "type": ceremony_type,
            "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            "origin": origin,
        })
        .to_string()
        .into_bytes()
    }
}

use tests::{TestAuthenticator, client_data_json};

#[tokio::test]
#[ignore]
async fn enregistrement_puis_authentification_bout_en_bout() {
    let state = build_state("nominal").await;
    let subject_id = format!("subject-{}", uuid::Uuid::now_v7());

    // --- enregistrement ---------------------------------------------------------------------
    let (status, challenge_resp) = post_json(
        httpapi::router(state.clone()),
        "/v1/webauthn/registration/challenge",
        serde_json::json!({ "subject_id": subject_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{challenge_resp:?}");
    let challenge = b64_field(&challenge_resp, "challenge");

    let auth = TestAuthenticator::new();
    let credential_id = b"integration-test-credential";
    let cdj = client_data_json("webauthn.create", ORIGIN, &challenge);
    let auth_data = auth.auth_data(RP_ID, 0x41, 0, credential_id); // UP + AT, sign_count=0
    let attestation_object = auth.attestation_object_none(&auth_data);

    let (status, verify_resp) = post_json(
        httpapi::router(state.clone()),
        "/v1/webauthn/registration/verify",
        serde_json::json!({
            "client_data_json": b64(&cdj),
            "attestation_object": b64(&attestation_object),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verify_resp:?}");

    // --- authentification ---------------------------------------------------------------------
    let (status, auth_challenge_resp) = post_json(
        httpapi::router(state.clone()),
        "/v1/webauthn/authentication/challenge",
        serde_json::json!({ "subject_id": subject_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{auth_challenge_resp:?}");
    let allow_credentials = auth_challenge_resp["allow_credentials"].as_array().unwrap();
    assert_eq!(allow_credentials.len(), 1, "un seul credential enregistré");
    let auth_challenge = b64_field(&auth_challenge_resp, "challenge");

    let auth_cdj = client_data_json("webauthn.get", ORIGIN, &auth_challenge);
    let auth_auth_data = auth.auth_data(RP_ID, 0x05, 1, credential_id); // UP + UV, sign_count=1
    let client_data_hash = tests::sha256(&auth_cdj);
    let mut signed_message = auth_auth_data.clone();
    signed_message.extend_from_slice(&client_data_hash);
    let signature = auth.sign(&signed_message);

    let (status, auth_verify_resp) = post_json(
        httpapi::router(state.clone()),
        "/v1/webauthn/authentication/verify",
        serde_json::json!({
            "credential_id": b64(credential_id),
            "client_data_json": b64(&auth_cdj),
            "authenticator_data": b64(&auth_auth_data),
            "signature": b64(&signature),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{auth_verify_resp:?}");
    assert!(
        auth_verify_resp["assertion"].as_str().is_some(),
        "attendu une assertion scellée"
    );
}

#[tokio::test]
#[ignore]
async fn rejeu_du_meme_challenge_est_refuse() {
    let state = build_state("rejeu").await;
    let subject_id = format!("subject-{}", uuid::Uuid::now_v7());

    let (_, challenge_resp) = post_json(
        httpapi::router(state.clone()),
        "/v1/webauthn/registration/challenge",
        serde_json::json!({ "subject_id": subject_id }),
    )
    .await;
    let challenge = b64_field(&challenge_resp, "challenge");

    let auth = TestAuthenticator::new();
    let credential_id = b"replay-test-credential";
    let cdj = client_data_json("webauthn.create", ORIGIN, &challenge);
    let auth_data = auth.auth_data(RP_ID, 0x41, 0, credential_id);
    let attestation_object = auth.attestation_object_none(&auth_data);

    let body = serde_json::json!({
        "client_data_json": b64(&cdj),
        "attestation_object": b64(&attestation_object),
    });

    let (status_1, _) = post_json(
        httpapi::router(state.clone()),
        "/v1/webauthn/registration/verify",
        body.clone(),
    )
    .await;
    assert_eq!(status_1, StatusCode::OK);

    // Même corps, même challenge déjà consommé — doit être refusé, pas ré-accepté.
    let (status_2, resp_2) = post_json(
        httpapi::router(state.clone()),
        "/v1/webauthn/registration/verify",
        body,
    )
    .await;
    assert_ne!(status_2, StatusCode::OK, "{resp_2:?}");
}

#[tokio::test]
#[ignore]
async fn signature_invalide_est_refusee() {
    let state = build_state("signature-invalide").await;
    let subject_id = format!("subject-{}", uuid::Uuid::now_v7());

    let (_, challenge_resp) = post_json(
        httpapi::router(state.clone()),
        "/v1/webauthn/registration/challenge",
        serde_json::json!({ "subject_id": subject_id }),
    )
    .await;
    let challenge = b64_field(&challenge_resp, "challenge");

    let auth = TestAuthenticator::new();
    let credential_id = b"bad-signature-credential";
    let cdj = client_data_json("webauthn.create", ORIGIN, &challenge);
    let auth_data = auth.auth_data(RP_ID, 0x41, 0, credential_id);
    // "none" n'a pas de signature à falsifier — utilise "packed" avec une signature d'une autre
    // clé pour exercer le chemin de refus cryptographique plutôt que structurel.
    let autre_auth = TestAuthenticator::new();
    let bad_attestation = autre_auth.attestation_object_packed(&auth_data, &cdj);

    let (status, resp) = post_json(
        httpapi::router(state.clone()),
        "/v1/webauthn/registration/verify",
        serde_json::json!({
            "client_data_json": b64(&cdj),
            "attestation_object": b64(&bad_attestation),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{resp:?}");
}
