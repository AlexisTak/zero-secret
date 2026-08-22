//! Parsing et vérification de `clientDataJSON` (spec WebAuthn §5.8.1). JSON, pas CBOR — moins
//! exposé que l'attestation, mais toujours une entrée non fiable (fournie par le navigateur).

use serde::Deserialize;
use zs_crypto::authenticator_proof::{Challenge, challenge_matches};

#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ceremony_type: String,
    challenge: String, // base64url, RFC 4648 §5, sans padding
    origin: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("clientDataJSON n'est pas un JSON valide")]
    InvalidJson,
    #[error("type de cérémonie inattendu : {0}")]
    UnexpectedType(String),
    #[error("origine inattendue : {0}")]
    UnexpectedOrigin(String),
    #[error("challenge non concordant — rejoué ou falsifié")]
    ChallengeMismatch,
    #[error("challenge encodé en base64url invalide")]
    InvalidChallengeEncoding,
}

/// Vérifie `clientDataJSON` contre le type de cérémonie, l'origine et le challenge attendus.
/// Refuse par défaut sur toute divergence — c'est le point exact où le scénario 1
/// (hameçonnage) est tenu : l'origine est comparée ici, jamais déclarée par confiance.
pub fn verify(
    client_data_json: &[u8],
    expected_type: &str,
    expected_origin: &str,
    expected_challenge: &Challenge,
) -> Result<(), Error> {
    let data: ClientData =
        serde_json::from_slice(client_data_json).map_err(|_| Error::InvalidJson)?;

    if data.ceremony_type != expected_type {
        return Err(Error::UnexpectedType(data.ceremony_type));
    }
    if data.origin != expected_origin {
        return Err(Error::UnexpectedOrigin(data.origin));
    }

    use base64::Engine;
    let presented = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&data.challenge)
        .map_err(|_| Error::InvalidChallengeEncoding)?;
    if !challenge_matches(expected_challenge, &presented) {
        return Err(Error::ChallengeMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use zs_crypto::authenticator_proof::new_challenge;

    fn client_data_json(ceremony_type: &str, origin: &str, challenge_b64: &str) -> Vec<u8> {
        serde_json::json!({
            "type": ceremony_type,
            "challenge": challenge_b64,
            "origin": origin,
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn cas_nominal_est_accepte() {
        let challenge = new_challenge();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes());
        let cdj = client_data_json("webauthn.create", "https://zero-secret.example", &b64);
        assert!(
            verify(
                &cdj,
                "webauthn.create",
                "https://zero-secret.example",
                &challenge
            )
            .is_ok()
        );
    }

    // --- les trois refus obligatoires de L1.1 -------------------------------------------
    #[test]
    fn challenge_rejoue_est_refuse() {
        let challenge = new_challenge();
        let autre_challenge = new_challenge();
        let b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(autre_challenge.as_bytes());
        let cdj = client_data_json("webauthn.create", "https://zero-secret.example", &b64);
        assert_eq!(
            verify(
                &cdj,
                "webauthn.create",
                "https://zero-secret.example",
                &challenge
            ),
            Err(Error::ChallengeMismatch)
        );
    }

    #[test]
    fn origin_incorrecte_est_refusee() {
        let challenge = new_challenge();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes());
        let cdj = client_data_json("webauthn.create", "https://phishing.example", &b64);
        assert_eq!(
            verify(
                &cdj,
                "webauthn.create",
                "https://zero-secret.example",
                &challenge
            ),
            Err(Error::UnexpectedOrigin(
                "https://phishing.example".to_string()
            ))
        );
    }

    #[test]
    fn type_de_ceremonie_incorrect_est_refuse() {
        let challenge = new_challenge();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes());
        // une preuve d'authentification rejouée comme si c'était un enregistrement
        let cdj = client_data_json("webauthn.get", "https://zero-secret.example", &b64);
        assert_eq!(
            verify(
                &cdj,
                "webauthn.create",
                "https://zero-secret.example",
                &challenge
            ),
            Err(Error::UnexpectedType("webauthn.get".to_string()))
        );
    }
}
