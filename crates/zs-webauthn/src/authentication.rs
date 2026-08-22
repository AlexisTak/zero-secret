//! Cérémonie d'authentification WebAuthn (backlog L1.2a, découpage acté ADR-008 sur mise en
//! garde `referent-crypto`). Vérifie une assertion (`webauthn.get`) contre un authentificateur
//! **déjà enregistré** — jamais contre une clé fournie par l'appelant : `credential` provient
//! du registre (identity.authenticators), pas du client, sinon un attaquant pourrait présenter
//! sa propre clé et signer avec (mise en garde referent-crypto, frontière R2).
//!
//! Le message signé par l'authentificateur est identique à celui de l'enregistrement
//! (`authenticatorData || SHA-256(clientDataJSON)`, spec WebAuthn §7.2 étape 20) : seule la
//! suite `authenticator-proof/v1` déjà existante est réutilisée, aucune nouvelle opération
//! crypto n'est ajoutée à `zs-crypto` par ce module.
//!
//! **Émission d'assertion d'identité signée (ADR-007) : hors périmètre ici.** Ce module produit
//! des `AuthenticationClaims`, un type qui n'implémente **volontairement** aucune sérialisation
//! ni export hors crate — le sceller en un objet transmissible est le rôle de
//! `zs_crypto::identity_assertion` (L1.2c, différée, ADR-008), qui n'existe pas encore. Un type
//! d'assertion « non signée » mais sérialisable serait un contournement d'authentification
//! représentable ; le refus par défaut (règle absolue #2 du `CLAUDE.md` racine) l'interdit par
//! construction, pas par discipline de revue.

use crate::flags::{FLAG_USER_PRESENT, FLAG_USER_VERIFIED};
use zs_crypto::authenticator_proof::{self, Challenge};

/// Authentificateur tel que connu du registre, **jamais reconstruit depuis une entrée client**.
/// `counter_supported` est figé une fois à l'enregistrement (migration 004) et ne doit jamais
/// être réévalué ici : un clone qui force `sign_count = 0` sur une assertion ultérieure ne doit
/// pas pouvoir désactiver rétroactivement la détection pour un authentificateur qui la
/// supportait (mise en garde `referent-crypto`).
pub struct RegisteredCredential {
    pub subject_id: String,
    pub credential_id: Vec<u8>,
    pub public_key_algorithm: authenticator_proof::Algorithm,
    pub public_key_raw: Vec<u8>,
    pub counter_supported: bool,
    pub stored_sign_count: u32,
    /// Révoqué (backlog L1.3) : refusé immédiatement, avant toute vérification de signature —
    /// une révocation doit avoir un effet immédiat (`docs/architecture.md`, délai cible < 5 s),
    /// jamais une fenêtre de grâce le temps qu'un cache expire.
    pub revoked: bool,
}

pub struct AuthenticationCeremonyInput<'a> {
    pub client_data_json: &'a [u8],
    pub authenticator_data: &'a [u8],
    pub signature: &'a [u8],
    pub expected_origin: &'a str,
    pub expected_rp_id: &'a str,
    pub expected_challenge: &'a Challenge,
    pub credential: &'a RegisteredCredential,
}

/// Niveau d'assurance d'authentification atteint. Déterminé uniquement à partir des drapeaux
/// **vérifiés** de `authenticatorData`, jamais d'une valeur déclarée par le client (modèle de
/// menaces `identity-provider.md`, STRIDE Elevation of Privilege). AAL3 est hors périmètre de
/// L1.2 : il exigerait de distinguer un authentificateur lié au matériel d'une passkey
/// synchronisée (bits `BE`/`BS`, non décodés ici) — différé, pas oublié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aal {
    /// Présence utilisateur (UP) sans vérification (UV).
    Aal1,
    /// Utilisateur vérifié (UV) — biométrie ou PIN validé par l'authentificateur.
    Aal2,
}

/// Affirmations d'authentification déterminées côté serveur. **Ne dérive ni `Serialize` ni
/// `Clone` publiquement exposé, n'est pas exporté hors crate au-delà de cette signature de
/// retour** : la seule façon d'obtenir un objet transmissible est de sceller ces claims via
/// `zs_crypto::identity_assertion` (L1.2c). Voir la mise en garde du module.
#[derive(Debug)]
pub struct AuthenticationClaims {
    pub subject_id: String,
    pub credential_id: Vec<u8>,
    pub aal: Aal,
    pub method: &'static str,
    pub new_sign_count: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthenticationError {
    #[error("clientDataJSON invalide : {0}")]
    ClientData(#[from] crate::client_data::Error),
    #[error("authenticatorData tronqué ou incohérent")]
    MalformedAuthenticatorData,
    #[error("rpIdHash ne correspond pas au rpId attendu")]
    RpIdMismatch,
    #[error("le drapeau user present (UP) n'est pas positionné")]
    UserNotPresent,
    #[error("clé publique enregistrée invalide")]
    MalformedRegisteredKey,
    #[error("signature invalide")]
    InvalidSignature,
    #[error("compteur de signature régressif ou rejoué — clonage suspecté")]
    SignCounterRegression,
    #[error("authentificateur révoqué")]
    AuthenticatorRevoked,
}

/// Vérifie une cérémonie d'authentification complète. Ne consulte aucun stockage : le challenge
/// et le compteur enregistré sont fournis par l'appelant (même style que
/// `verify_registration_ceremony`), qui doit les avoir obtenus via `ChallengeStore`/
/// `SignCounterStore` (voir `crate::store`) avant d'appeler cette fonction.
pub fn verify_authentication_ceremony(
    input: AuthenticationCeremonyInput,
) -> Result<AuthenticationClaims, AuthenticationError> {
    // 0. Révocation (backlog L1.3) : porte sur `input.credential`, déjà connu du registre —
    //    ne dépend d'aucune entrée cliente non fiable, vérifié avant même le reste pour ne
    //    dépenser aucun effort de parsing sur une entrée dont le sort est déjà scellé.
    if input.credential.revoked {
        return Err(AuthenticationError::AuthenticatorRevoked);
    }

    // 1. clientDataJSON : type, origine, challenge — AVANT toute interprétation de l'assertion.
    //    "webauthn.get", jamais "webauthn.create" : un client ne peut pas rejouer une preuve
    //    d'enregistrement comme si c'était une authentification (confusion de cérémonie).
    crate::client_data::verify(
        input.client_data_json,
        "webauthn.get",
        input.expected_origin,
        input.expected_challenge,
    )?;

    // 2. authenticatorData : structure avant tout usage de son contenu.
    let parsed = parse_authenticator_data(input.authenticator_data)?;

    if parsed.rp_id_hash != rp_id_hash(input.expected_rp_id) {
        return Err(AuthenticationError::RpIdMismatch);
    }
    if parsed.flags & FLAG_USER_PRESENT == 0 {
        return Err(AuthenticationError::UserNotPresent);
    }

    // 3. Compteur de signature : vérifié avant la signature elle-même (refuser tôt un clonage
    //    suspecté sans dépenser une vérification de signature dessus n'est qu'un détail de
    //    performance ici, mais l'ordre "structure avant contenu avant signature" reste respecté :
    //    le compteur fait partie de la structure d'authenticatorData, pas de son contenu signé).
    if input.credential.counter_supported && parsed.sign_count <= input.credential.stored_sign_count
    {
        return Err(AuthenticationError::SignCounterRegression);
    }

    // 4. Clé publique — reconstruite depuis le registre, jamais depuis l'entrée cliente
    //    (frontière R2, mise en garde referent-crypto). `accept_key` revalide l'encodage à
    //    chaque appel, comme à l'enregistrement.
    let accepted_key = authenticator_proof::accept_key(
        authenticator_proof::SUITE_V1,
        authenticator_proof::PublicKeyMaterial {
            algorithm: input.credential.public_key_algorithm,
            raw: input.credential.public_key_raw.clone(),
        },
    )
    .map_err(|_| AuthenticationError::MalformedRegisteredKey)?;

    // 5. Signature en dernier, sur authenticatorData || SHA-256(clientDataJSON).
    let client_data_hash = authenticator_proof::sha256(input.client_data_json);
    let mut signed_message = Vec::with_capacity(input.authenticator_data.len() + 32);
    signed_message.extend_from_slice(input.authenticator_data);
    signed_message.extend_from_slice(&client_data_hash);

    authenticator_proof::verify(&accepted_key, &signed_message, input.signature)
        .map_err(|_| AuthenticationError::InvalidSignature)?;

    let aal = if parsed.flags & FLAG_USER_VERIFIED != 0 {
        Aal::Aal2
    } else {
        Aal::Aal1
    };
    // Méthode déterminée à partir d'un signal déjà connu (support du compteur, figé à
    // l'enregistrement) plutôt que des bits BE/BS non décodés ici — classification volontairement
    // grossière, à affiner si L1.3/L1.4 en ont besoin d'une plus fine.
    let method = if input.credential.counter_supported {
        "webauthn/device-bound"
    } else {
        "webauthn/synced-or-unknown"
    };

    Ok(AuthenticationClaims {
        subject_id: input.credential.subject_id.clone(),
        credential_id: input.credential.credential_id.clone(),
        aal,
        method,
        new_sign_count: parsed.sign_count,
    })
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    authenticator_proof::sha256(rp_id.as_bytes())
}

struct ParsedAssertionAuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
}

/// Parse le préfixe fixe de `authenticatorData` pour une assertion : `rpIdHash(32) || flags(1) ||
/// signCount(4)`. Contrairement à l'enregistrement, aucune donnée d'identifiant attesté ne suit
/// (`attestedCredentialData` n'apparaît qu'en enregistrement) ; d'éventuelles extensions au-delà
/// de l'octet 37 sont ignorées — hors périmètre L1.2, pas une troncature accidentelle.
fn parse_authenticator_data(data: &[u8]) -> Result<ParsedAssertionAuthData, AuthenticationError> {
    if data.len() < 37 {
        return Err(AuthenticationError::MalformedAuthenticatorData);
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&data[0..32]);
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    Ok(ParsedAssertionAuthData {
        rp_id_hash,
        flags,
        sign_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self, KeyPair};
    use base64::Engine;
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

        fn public_key_raw(&self) -> Vec<u8> {
            self.keypair.public_key().as_ref().to_vec() // 0x04 || X(32) || Y(32)
        }

        fn auth_data(&self, rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
            let mut data = Vec::new();
            data.extend_from_slice(&authenticator_proof::sha256(rp_id.as_bytes()));
            data.push(flags);
            data.extend_from_slice(&sign_count.to_be_bytes());
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

    fn registered(
        auth: &TestAuthenticator,
        counter_supported: bool,
        stored: u32,
    ) -> RegisteredCredential {
        RegisteredCredential {
            subject_id: "subject-1".to_string(),
            credential_id: b"test-credential-id".to_vec(),
            public_key_algorithm: authenticator_proof::Algorithm::Es256,
            public_key_raw: auth.public_key_raw(),
            counter_supported,
            stored_sign_count: stored,
            revoked: false,
        }
    }

    fn sign_and_build(auth: &TestAuthenticator, cdj: &[u8], auth_data: &[u8]) -> Vec<u8> {
        let client_data_hash = authenticator_proof::sha256(cdj);
        let mut signed_message = auth_data.to_vec();
        signed_message.extend_from_slice(&client_data_hash);
        auth.sign(&signed_message)
    }

    // --- cas nominal ---------------------------------------------------------------------
    #[test]
    fn assertion_valide_est_acceptee() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.get", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x05, 7); // UP + UV, sign_count=7
        let sig = sign_and_build(&auth, &cdj, &auth_data);
        let credential = registered(&auth, true, 6);

        let claims = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        })
        .unwrap();

        assert_eq!(claims.aal, Aal::Aal2);
        assert_eq!(claims.new_sign_count, 7);
        assert_eq!(claims.subject_id, "subject-1");
    }

    #[test]
    fn compteur_non_supporte_est_accepte_a_zero() {
        // Passkey synchronisée : signCount reste à 0 en permanence, comportement légitime
        // (spec WebAuthn L3 §6.1.1) — ne doit jamais être refusé pour cette seule raison.
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.get", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x01, 0); // UP seul, sign_count=0
        let sig = sign_and_build(&auth, &cdj, &auth_data);
        let credential = registered(&auth, false, 0);

        let claims = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        })
        .unwrap();

        assert_eq!(claims.aal, Aal::Aal1);
    }

    // --- refus obligatoires ----------------------------------------------------------------
    #[test]
    fn compteur_regressif_est_refuse() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.get", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x01, 5); // sign_count=5
        let sig = sign_and_build(&auth, &cdj, &auth_data);
        let credential = registered(&auth, true, 10); // stocké=10 > reçu=5 : clonage suspecté

        let result = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        });

        assert_eq!(
            result.unwrap_err(),
            AuthenticationError::SignCounterRegression
        );
    }

    #[test]
    fn compteur_identique_est_refuse() {
        // Rejeu exact du compteur, pas seulement une régression stricte.
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.get", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x01, 10);
        let sig = sign_and_build(&auth, &cdj, &auth_data);
        let credential = registered(&auth, true, 10);

        let result = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        });

        assert_eq!(
            result.unwrap_err(),
            AuthenticationError::SignCounterRegression
        );
    }

    #[test]
    fn challenge_rejoue_est_refuse() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let autre_challenge = new_challenge();
        let cdj = client_data_json("webauthn.get", ORIGIN, autre_challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x01, 1);
        let sig = sign_and_build(&auth, &cdj, &auth_data);
        let credential = registered(&auth, true, 0);

        let result = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        });

        assert!(matches!(
            result,
            Err(AuthenticationError::ClientData(
                crate::client_data::Error::ChallengeMismatch
            ))
        ));
    }

    #[test]
    fn origin_incorrecte_est_refusee() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json(
            "webauthn.get",
            "https://phishing.example",
            challenge.as_bytes(),
        );
        let auth_data = auth.auth_data(RP_ID, 0x01, 1);
        let sig = sign_and_build(&auth, &cdj, &auth_data);
        let credential = registered(&auth, true, 0);

        let result = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        });

        assert!(matches!(
            result,
            Err(AuthenticationError::ClientData(
                crate::client_data::Error::UnexpectedOrigin(_)
            ))
        ));
    }

    #[test]
    fn confusion_de_ceremonie_est_refusee() {
        // Une preuve d'enregistrement ("webauthn.create") rejouée comme authentification.
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.create", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x01, 1);
        let sig = sign_and_build(&auth, &cdj, &auth_data);
        let credential = registered(&auth, true, 0);

        let result = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        });

        assert!(matches!(
            result,
            Err(AuthenticationError::ClientData(
                crate::client_data::Error::UnexpectedType(_)
            ))
        ));
    }

    #[test]
    fn rp_id_incorrect_est_refuse() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.get", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data("autre-domaine.example", 0x01, 1);
        let sig = sign_and_build(&auth, &cdj, &auth_data);
        let credential = registered(&auth, true, 0);

        let result = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        });

        assert_eq!(result.unwrap_err(), AuthenticationError::RpIdMismatch);
    }

    #[test]
    fn user_present_absent_est_refuse() {
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.get", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x00, 1); // aucun drapeau
        let sig = sign_and_build(&auth, &cdj, &auth_data);
        let credential = registered(&auth, true, 0);

        let result = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        });

        assert_eq!(result.unwrap_err(), AuthenticationError::UserNotPresent);
    }

    #[test]
    fn signature_invalide_est_refusee() {
        let auth = TestAuthenticator::new();
        let autre_auth = TestAuthenticator::new(); // signe avec une autre clé que l'enregistrée
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.get", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x01, 1);
        let sig = sign_and_build(&autre_auth, &cdj, &auth_data);
        let credential = registered(&auth, true, 0); // clé enregistrée = auth, pas autre_auth

        let result = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        });

        assert_eq!(result.unwrap_err(), AuthenticationError::InvalidSignature);
    }

    #[test]
    fn authentificateur_revoque_est_refuse_immediatement() {
        // Effet immédiat (backlog L1.3) : refusé même avec une signature par ailleurs valide,
        // avant toute autre vérification (docs/architecture.md, délai cible < 5 s).
        let auth = TestAuthenticator::new();
        let challenge = new_challenge();
        let cdj = client_data_json("webauthn.get", ORIGIN, challenge.as_bytes());
        let auth_data = auth.auth_data(RP_ID, 0x01, 1);
        let sig = sign_and_build(&auth, &cdj, &auth_data);
        let mut credential = registered(&auth, true, 0);
        credential.revoked = true;

        let result = verify_authentication_ceremony(AuthenticationCeremonyInput {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &sig,
            expected_origin: ORIGIN,
            expected_rp_id: RP_ID,
            expected_challenge: &challenge,
            credential: &credential,
        });

        assert_eq!(
            result.unwrap_err(),
            AuthenticationError::AuthenticatorRevoked
        );
    }
}
