//! Cérémonie d'enregistrement WebAuthn (backlog L1.1, RFC 8809 / spec W3C WebAuthn L3).
//!
//! Ordre des vérifications imposé (mise en garde `referent-crypto`, ADR-006) : structure avant
//! signature avant contenu. Un `?` mal placé produirait un succès prématuré silencieux — chaque
//! étape retourne explicitement avant la suivante, aucune n'est court-circuitée par accident.

use crate::flags::{FLAG_ATTESTED_CRED_DATA, FLAG_USER_PRESENT};
use crate::policy::AttestationPolicy;
use ciborium::value::Value as CborValue;
use std::io::Cursor;
use zs_crypto::authenticator_proof::{self, Challenge};

/// Taille maximale acceptée pour `attestationObject`, avant tout décodage CBOR (mise en garde
/// « borner la taille d'entrée avant décodage, jamais après »). 64 Kio est largement au-delà de
/// ce que produit un authentificateur réel ; au-delà, refus immédiat sans tenter de décoder.
const MAX_ATTESTATION_OBJECT_LEN: usize = 64 * 1024;

pub struct RegistrationCeremonyInput<'a> {
    pub client_data_json: &'a [u8],
    pub attestation_object: &'a [u8],
    pub expected_origin: &'a str,
    pub expected_rp_id: &'a str,
    pub expected_challenge: &'a Challenge,
    pub policy: AttestationPolicy,
}

#[derive(Debug)]
pub struct RegistrationOutcome {
    pub credential_id: Vec<u8>,
    pub sign_count: u32,
    pub attestation_format: &'static str,
    pub aaguid: [u8; 16],
    pub public_key_algorithm: authenticator_proof::Algorithm,
    /// Clé publique brute acceptée (même encodage que `PublicKeyMaterial::raw`). Sans ce champ,
    /// impossible de la persister pour l'authentification ultérieure (L1.2) sans re-parser
    /// l'attestation — bloquant identifié par `referent-crypto` en amont de L1.2.
    pub public_key_raw: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistrationError {
    #[error("clientDataJSON invalide : {0}")]
    ClientData(#[from] crate::client_data::Error),
    #[error("attestationObject dépasse la taille maximale acceptée")]
    AttestationObjectTooLarge,
    #[error("attestationObject n'est pas un CBOR valide")]
    InvalidCbor,
    #[error("attestationObject : champ obligatoire manquant ou de type incorrect")]
    MalformedAttestationObject,
    #[error("authenticatorData tronqué ou incohérent")]
    MalformedAuthenticatorData,
    #[error("rpIdHash ne correspond pas au rpId attendu")]
    RpIdMismatch,
    #[error("le drapeau attestedCredentialData n'est pas positionné")]
    MissingAttestedCredentialData,
    #[error("le drapeau user present (UP) n'est pas positionné")]
    UserNotPresent,
    #[error("clé publique COSE invalide : {0}")]
    Cose(#[from] crate::cose::Error),
    #[error("format d'attestation '{0}' non supporté (seuls 'none' et 'packed' le sont)")]
    UnsupportedAttestationFormat(String),
    #[error("attestation exigée par la politique, mais absente (fmt: none)")]
    AttestationRequiredButAbsent,
    #[error("attestation 'packed' avec chaîne de certificats (x5c) non supportée")]
    AttestationCertificateChainUnsupported,
    #[error("statement d'attestation 'packed' malformé")]
    MalformedAttestationStatement,
    #[error("signature d'attestation invalide")]
    InvalidAttestationSignature,
}

/// Vérifie une cérémonie d'enregistrement complète. Retourne les informations nécessaires à
/// L1.2 (identity-assertion, ADR-007) pour construire l'assertion d'identité, sans avoir à
/// re-parser l'attestation.
pub fn verify_registration_ceremony(
    input: RegistrationCeremonyInput,
) -> Result<RegistrationOutcome, RegistrationError> {
    // 1. clientDataJSON : type, origine, challenge — AVANT toute interprétation de l'attestation.
    crate::client_data::verify(
        input.client_data_json,
        "webauthn.create",
        input.expected_origin,
        input.expected_challenge,
    )?;

    // 2. Bornage de taille avant décodage CBOR — jamais après.
    if input.attestation_object.len() > MAX_ATTESTATION_OBJECT_LEN {
        return Err(RegistrationError::AttestationObjectTooLarge);
    }

    // 3. Décodage structurel de attestationObject (CBOR canonique attendu par ciborium).
    let cbor: CborValue = ciborium::de::from_reader(input.attestation_object)
        .map_err(|_| RegistrationError::InvalidCbor)?;
    let map = cbor
        .into_map()
        .map_err(|_| RegistrationError::MalformedAttestationObject)?;
    let get = |key: &str| -> Option<&CborValue> {
        map.iter()
            .find_map(|(k, v)| (k.as_text() == Some(key)).then_some(v))
    };
    let fmt = get("fmt")
        .and_then(|v| v.as_text())
        .ok_or(RegistrationError::MalformedAttestationObject)?
        .to_string();
    let auth_data = get("authData")
        .and_then(|v| v.as_bytes())
        .ok_or(RegistrationError::MalformedAttestationObject)?;

    // 4. Refus explicite des formats hors périmètre v1 — code distinct d'un refus "malformé".
    if fmt != "none" && fmt != "packed" {
        return Err(RegistrationError::UnsupportedAttestationFormat(fmt));
    }

    // 5. Politique d'attestation, refus par défaut si non satisfaite.
    if input.policy == AttestationPolicy::Required && fmt == "none" {
        return Err(RegistrationError::AttestationRequiredButAbsent);
    }

    // 6. authenticatorData : structure avant tout usage de son contenu.
    let parsed = parse_authenticator_data(auth_data)?;

    if parsed.rp_id_hash != rp_id_hash(input.expected_rp_id) {
        return Err(RegistrationError::RpIdMismatch);
    }
    if parsed.flags & FLAG_USER_PRESENT == 0 {
        return Err(RegistrationError::UserNotPresent);
    }
    if parsed.flags & FLAG_ATTESTED_CRED_DATA == 0 {
        return Err(RegistrationError::MissingAttestedCredentialData);
    }
    let cred = parsed
        .attested_credential_data
        .ok_or(RegistrationError::MissingAttestedCredentialData)?;

    // 7. Clé publique de l'authentificateur, décodée via zs-webauthn::cose puis acceptée par
    //    zs-crypto (frontière ADR-006).
    let key_material = crate::cose::extract_public_key_material(&cred.public_key_cbor)?;
    let algorithm = key_material.algorithm;
    let public_key_raw = key_material.raw.clone();
    let accepted_key = authenticator_proof::accept_key(authenticator_proof::SUITE_V1, key_material)
        .map_err(|_| RegistrationError::MalformedAttestationObject)?;

    // 8. Signature avant contenu : vérifier l'attStmt "packed" (auto-attestation uniquement,
    //    x5c refusé explicitement — ADR-006 limite le périmètre v1).
    if fmt == "packed" {
        verify_packed_attestation(
            get("attStmt"),
            auth_data,
            input.client_data_json,
            &accepted_key,
        )?;
    }

    Ok(RegistrationOutcome {
        credential_id: cred.credential_id,
        sign_count: parsed.sign_count,
        attestation_format: if fmt == "none" { "none" } else { "packed" },
        aaguid: cred.aaguid,
        public_key_algorithm: algorithm,
        public_key_raw,
    })
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    authenticator_proof::sha256(rp_id.as_bytes())
}

struct AttestedCredentialData {
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
    public_key_cbor: Vec<u8>,
}

struct ParsedAuthenticatorData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    attested_credential_data: Option<AttestedCredentialData>,
}

/// Parse `authenticatorData` (spec WebAuthn §6.1). Format binaire, pas CBOR (hors la clé
/// publique embarquée) — chaque longueur est validée avant lecture, jamais supposée.
fn parse_authenticator_data(data: &[u8]) -> Result<ParsedAuthenticatorData, RegistrationError> {
    // rpIdHash(32) || flags(1) || signCount(4)
    if data.len() < 37 {
        return Err(RegistrationError::MalformedAuthenticatorData);
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&data[0..32]);
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    let attested_credential_data = if flags & FLAG_ATTESTED_CRED_DATA != 0 {
        let rest = &data[37..];
        // aaguid(16) || credentialIdLength(2, BE) || credentialId(var) || credentialPublicKey(CBOR)
        if rest.len() < 18 {
            return Err(RegistrationError::MalformedAuthenticatorData);
        }
        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&rest[0..16]);
        let cred_id_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
        let cred_id_start: usize = 18;
        let cred_id_end = cred_id_start
            .checked_add(cred_id_len)
            .filter(|&end| end <= rest.len())
            .ok_or(RegistrationError::MalformedAuthenticatorData)?;
        let credential_id = rest[cred_id_start..cred_id_end].to_vec();

        // La clé COSE est auto-délimitée : on décode juste assez d'octets pour la consommer,
        // sans supposer sa longueur à l'avance.
        let key_bytes = &rest[cred_id_end..];
        let mut cursor = Cursor::new(key_bytes);
        let _: CborValue = ciborium::de::from_reader(&mut cursor)
            .map_err(|_| RegistrationError::MalformedAuthenticatorData)?;
        let consumed = cursor.position() as usize;
        let public_key_cbor = key_bytes[..consumed].to_vec();

        Some(AttestedCredentialData {
            aaguid,
            credential_id,
            public_key_cbor,
        })
    } else {
        None
    };

    Ok(ParsedAuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested_credential_data,
    })
}

/// Vérifie un attStmt "packed" en auto-attestation (pas de x5c). Le message signé est
/// `authData || SHA-256(clientDataJSON)` (spec WebAuthn §8.2).
fn verify_packed_attestation(
    att_stmt: Option<&CborValue>,
    auth_data: &[u8],
    client_data_json: &[u8],
    key: &authenticator_proof::AcceptedKey,
) -> Result<(), RegistrationError> {
    let map = att_stmt
        .and_then(|v| v.as_map())
        .ok_or(RegistrationError::MalformedAttestationStatement)?;
    let get = |k: &str| {
        map.iter()
            .find_map(|(key, v)| (key.as_text() == Some(k)).then_some(v))
    };

    if get("x5c").is_some() {
        // Chaîne de certificats d'attestation : validation X.509 hors périmètre v1 (ADR-006).
        return Err(RegistrationError::AttestationCertificateChainUnsupported);
    }

    let sig = get("sig")
        .and_then(|v| v.as_bytes())
        .ok_or(RegistrationError::MalformedAttestationStatement)?;

    let client_data_hash = authenticator_proof::sha256(client_data_json);
    let mut signed_message = Vec::with_capacity(auth_data.len() + 32);
    signed_message.extend_from_slice(auth_data);
    signed_message.extend_from_slice(&client_data_hash);

    authenticator_proof::verify(key, &signed_message, sig)
        .map_err(|_| RegistrationError::InvalidAttestationSignature)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self, KeyPair};
    use base64::Engine;
    use ciborium::value::Integer;
    use coset::{CborSerializable, CoseKeyBuilder, iana};
    use zs_crypto::authenticator_proof::new_challenge;

    const RP_ID: &str = "zero-secret.example";
    const ORIGIN: &str = "https://zero-secret.example";

    struct TestAuthenticator {
        keypair: signature::EcdsaKeyPair,
        rng: SystemRandom,
    }

    impl TestAuthenticator {
        fn new() -> Self {
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
            let raw = self.keypair.public_key().as_ref(); // 0x04 || X(32) || Y(32)
            let x = raw[1..33].to_vec();
            let y = raw[33..65].to_vec();
            CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
                .algorithm(iana::Algorithm::ES256)
                .build()
                .to_vec()
                .unwrap()
        }

        fn auth_data(&self, rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
            let mut data = Vec::new();
            data.extend_from_slice(&authenticator_proof::sha256(rp_id.as_bytes()));
            data.push(flags);
            data.extend_from_slice(&sign_count.to_be_bytes());
            if flags & FLAG_ATTESTED_CRED_DATA != 0 {
                data.extend_from_slice(&[0xAA; 16]); // aaguid factice
                let cred_id = b"test-credential-id";
                data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
                data.extend_from_slice(cred_id);
                data.extend_from_slice(&self.cose_public_key());
            }
            data
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.keypair
                .sign(&self.rng, message)
                .unwrap()
                .as_ref()
                .to_vec()
        }
    }

    fn client_data_json(ceremony_type: &str, origin: &str, challenge: &[u8]) -> Vec<u8> {
        serde_json::json!({
            "type": ceremony_type,
            "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            "origin": origin,
        })
        .to_string()
        .into_bytes()
    }

    fn attestation_object_none(auth_data: &[u8]) -> Vec<u8> {
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

    fn attestation_object_packed(
        auth_data: &[u8],
        client_data_json: &[u8],
        authenticator: &TestAuthenticator,
    ) -> Vec<u8> {
        let client_data_hash = authenticator_proof::sha256(client_data_json);
        let mut signed_message = auth_data.to_vec();
        signed_message.extend_from_slice(&client_data_hash);
        let sig = authenticator.sign(&signed_message);

        let att_stmt = CborValue::Map(vec![
            (
                CborValue::Text("alg".into()),
                CborValue::Integer(Integer::from(-7)),
            ), // ES256
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

    // --- cas nominal ---------------------------------------------------------------------
    #[test]
    fn enregistrement_none_avec_politique_any_est_accepte() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.create", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x41, 0); // UP + AT
        let att_obj = attestation_object_none(&auth_data);

        let outcome = verify_registration_ceremony(RegistrationCeremonyInput {
            client_data_json: &cdj,
            attestation_object: &att_obj,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            policy: AttestationPolicy::Any,
        })
        .unwrap();

        assert_eq!(outcome.attestation_format, "none");
        assert_eq!(outcome.credential_id, b"test-credential-id");
    }

    #[test]
    fn enregistrement_packed_auto_attestation_est_accepte() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.create", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x41, 0);
        let att_obj = attestation_object_packed(&auth_data, &cdj, &auth);

        let outcome = verify_registration_ceremony(RegistrationCeremonyInput {
            client_data_json: &cdj,
            attestation_object: &att_obj,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            policy: AttestationPolicy::Required,
        })
        .unwrap();

        assert_eq!(outcome.attestation_format, "packed");
    }

    // --- les trois refus obligatoires de L1.1 --------------------------------------------
    #[test]
    fn challenge_rejoue_est_refuse() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let autre_challenge = new_challenge();
        let cdj = client_data_json("webauthn.create", ORIGIN, autre_challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x41, 0);
        let att_obj = attestation_object_none(&auth_data);

        let result = verify_registration_ceremony(RegistrationCeremonyInput {
            client_data_json: &cdj,
            attestation_object: &att_obj,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            policy: AttestationPolicy::Any,
        });

        assert!(matches!(
            result,
            Err(RegistrationError::ClientData(
                crate::client_data::Error::ChallengeMismatch
            ))
        ));
    }

    #[test]
    fn origin_incorrecte_est_refusee() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json(
            "webauthn.create",
            "https://phishing.example",
            challenge.as_bytes(),
        );
        let auth_data = auth.auth_data(RP_ID, 0x41, 0);
        let att_obj = attestation_object_none(&auth_data);

        let result = verify_registration_ceremony(RegistrationCeremonyInput {
            client_data_json: &cdj,
            attestation_object: &att_obj,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            policy: AttestationPolicy::Any,
        });

        assert!(matches!(
            result,
            Err(RegistrationError::ClientData(
                crate::client_data::Error::UnexpectedOrigin(_)
            ))
        ));
    }

    #[test]
    fn attestation_absente_alors_quexigee_est_refusee() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.create", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x41, 0);
        let att_obj = attestation_object_none(&auth_data); // fmt: none

        let result = verify_registration_ceremony(RegistrationCeremonyInput {
            client_data_json: &cdj,
            attestation_object: &att_obj,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            policy: AttestationPolicy::Required, // exige packed
        });

        assert_eq!(
            result.unwrap_err(),
            RegistrationError::AttestationRequiredButAbsent
        );
    }

    // --- cas de refus supplémentaires (mise en garde referent-crypto) --------------------
    #[test]
    fn format_attestation_non_supporte_est_refuse_explicitement() {
        let auth_data = TestAuthenticator::new().auth_data(RP_ID, 0x41, 0);
        let cbor = CborValue::Map(vec![
            (CborValue::Text("fmt".into()), CborValue::Text("tpm".into())),
            (CborValue::Text("attStmt".into()), CborValue::Map(vec![])),
            (
                CborValue::Text("authData".into()),
                CborValue::Bytes(auth_data),
            ),
        ]);
        let mut att_obj = Vec::new();
        ciborium::ser::into_writer(&cbor, &mut att_obj).unwrap();

        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.create", ORIGIN, challenge.as_bytes());

        let result = verify_registration_ceremony(RegistrationCeremonyInput {
            client_data_json: &cdj,
            attestation_object: &att_obj,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            policy: AttestationPolicy::Any,
        });

        assert!(
            matches!(result, Err(RegistrationError::UnsupportedAttestationFormat(fmt)) if fmt == "tpm")
        );
    }

    #[test]
    fn rp_id_incorrect_est_refuse() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.create", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data("autre-domaine.example", 0x41, 0);
        let att_obj = attestation_object_none(&auth_data);

        let result = verify_registration_ceremony(RegistrationCeremonyInput {
            client_data_json: &cdj,
            attestation_object: &att_obj,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            policy: AttestationPolicy::Any,
        });

        assert_eq!(result.unwrap_err(), RegistrationError::RpIdMismatch);
    }

    #[test]
    fn user_present_absent_est_refuse() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.create", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x40, 0); // AT sans UP
        let att_obj = attestation_object_none(&auth_data);

        let result = verify_registration_ceremony(RegistrationCeremonyInput {
            client_data_json: &cdj,
            attestation_object: &att_obj,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            policy: AttestationPolicy::Any,
        });

        assert_eq!(result.unwrap_err(), RegistrationError::UserNotPresent);
    }

    #[test]
    fn signature_attestation_packed_invalide_est_refusee() {
        let auth = TestAuthenticator::new();
        let autre_auth = TestAuthenticator::new(); // clé différente -> signature ne correspondra pas
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.create", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x41, 0);
        // signe avec une autre clé que celle embarquée dans auth_data
        let att_obj = attestation_object_packed(&auth_data, &cdj, &autre_auth);

        let result = verify_registration_ceremony(RegistrationCeremonyInput {
            client_data_json: &cdj,
            attestation_object: &att_obj,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            policy: AttestationPolicy::Any,
        });

        assert_eq!(
            result.unwrap_err(),
            RegistrationError::InvalidAttestationSignature
        );
    }
}
