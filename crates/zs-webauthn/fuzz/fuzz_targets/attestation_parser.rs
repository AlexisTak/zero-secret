//! Cible de fuzzing pour le parseur d'attestation (backlog L1.1, ADR-006). Identifié par
//! `referent-crypto` comme le point le plus exposé du système
//! (`security/threat-models/identity-provider.md`) : format binaire (CBOR), source non fiable
//! (navigateur/authentificateur), plusieurs formats d'attestation à distinguer.
//!
//! `clientDataJSON`/challenge/origin/rpId sont fixés à des valeurs valides : seul
//! `attestationObject` varie, pour concentrer le fuzzing sur le parseur CBOR/authenticatorData,
//! pas sur la vérification JSON (déjà couverte par les tests unitaires de `client_data.rs`).
//!
//! `make fuzz TARGET=attestation_parser` (Makefile racine).

#![no_main]

use libfuzzer_sys::fuzz_target;
use zs_crypto::authenticator_proof::new_challenge;
use zs_webauthn::{verify_registration_ceremony, AttestationPolicy, RegistrationCeremonyInput};

fuzz_target!(|attestation_object: &[u8]| {
    let challenge = new_challenge();
    let client_data_json = serde_json::json!({
        "type": "webauthn.create",
        "challenge": base64_url_encode(challenge.as_bytes()),
        "origin": "https://zero-secret.example",
    })
    .to_string()
    .into_bytes();

    // Ne doit jamais paniquer, quel que soit l'octet fourni — un refus (Err) est le
    // comportement attendu pour à peu près toute entrée aléatoire ; un panic ne l'est jamais.
    let _ = verify_registration_ceremony(RegistrationCeremonyInput {
        client_data_json: &client_data_json,
        attestation_object,
        expected_origin: "https://zero-secret.example",
        expected_rp_id: "zero-secret.example",
        expected_challenge: &challenge,
        policy: AttestationPolicy::Any,
    });
});

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
