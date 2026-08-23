//! Suite `authenticator-proof` (ADR-006) : vérifie qu'un authentificateur FIDO2 externe détient
//! la clé privée correspondant à la clé publique qu'il présente. Vérification uniquement —
//! l'algorithme est imposé par l'authentificateur, pas choisi par nous (exception documentée à
//! l'invariant d'hybridation stricte).
//!
//! Ce module ne décode aucun CBOR/COSE : `zs-webauthn` extrait l'algorithme et la clé publique
//! brute, ce module ne fait que composer `aws-lc-rs` pour la vérification elle-même.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, ED25519, UnparsedPublicKey};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

/// Identifiant de suite courant. Une suite retirée serait refusée explicitement (invariant 4
/// de `zs-crypto/CLAUDE.md`) — à ce jour, une seule version existe, rien à retirer.
pub const SUITE_V1: &str = "authenticator-proof/v1";

/// Algorithme accepté par la suite `authenticator-proof/v1`. Fermé volontairement : RSA
/// (RS256/PS256) et les courbes P-384/P-521 sont refusés par décision (ADR-006), pas absents
/// par oubli.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Es256,
    EdDsa,
}

/// Clé publique d'authentificateur, déjà extraite de sa structure COSE par l'appelant
/// (`zs-webauthn`). Ce type ne contient aucune donnée sensible — clé publique uniquement.
pub struct PublicKeyMaterial {
    pub algorithm: Algorithm,
    /// Point EC non compressé (SEC1) pour ES256 ; 32 octets bruts pour EdDSA.
    pub raw: Vec<u8>,
}

/// Clé acceptée par `accept_key`. Ne peut être construite que par cette fonction : une clé dont
/// l'algorithme ou l'encodage est invalide n'existe jamais sous cette forme.
pub struct AcceptedKey {
    algorithm: Algorithm,
    raw: Vec<u8>,
}

/// Preuve de possession vérifiée. Aucun constructeur public : impossible de fabriquer une
/// vérification ailleurs que dans `verify` — le refus par défaut est structurel, pas
/// disciplinaire.
pub struct Verified(());

#[derive(Debug, Error)]
pub enum Error {
    #[error("suite inconnue ou retirée")]
    UnknownSuite,
    #[error("clé publique malformée")]
    MalformedKey,
    #[error("signature invalide")]
    InvalidSignature,
    #[error("challenge malformé")]
    MalformedChallenge,
}

/// Accepte une clé publique d'authentificateur pour la suite donnée. Refuse toute suite qui
/// n'est pas la version courante (pas de période de recouvrement définie pour l'instant : une
/// seule version existe) et tout encodage de clé incohérent avec l'algorithme déclaré.
pub fn accept_key(suite: &str, material: PublicKeyMaterial) -> Result<AcceptedKey, Error> {
    if suite != SUITE_V1 {
        return Err(Error::UnknownSuite);
    }
    let expected_len = match material.algorithm {
        Algorithm::Es256 => 65, // 0x04 || X (32) || Y (32), SEC1 non compressé
        Algorithm::EdDsa => 32,
    };
    if material.raw.len() != expected_len {
        return Err(Error::MalformedKey);
    }
    if material.algorithm == Algorithm::Es256 && material.raw[0] != 0x04 {
        return Err(Error::MalformedKey);
    }
    Ok(AcceptedKey {
        algorithm: material.algorithm,
        raw: material.raw,
    })
}

/// Vérifie une preuve de possession. `message` est construit par l'appelant
/// (`authenticatorData || SHA-256(clientDataJSON)`, cf. spec WebAuthn) — le hachage du message
/// signé et la comparaison des algorithmes restent ici.
///
/// Règle non négociable (ADR-006) : l'algorithme utilisé pour vérifier est celui de la clé
/// **enregistrée** (`key.algorithm`), jamais un algorithme déclaré par l'appelant à l'appel —
/// il n'y a d'ailleurs pas de paramètre d'algorithme dans cette signature, précisément pour
/// rendre la confusion d'algorithme impossible à exprimer.
pub fn verify(key: &AcceptedKey, message: &[u8], signature: &[u8]) -> Result<Verified, Error> {
    let verifying_key = match key.algorithm {
        Algorithm::Es256 => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &key.raw),
        Algorithm::EdDsa => UnparsedPublicKey::new(&ED25519, &key.raw),
    };
    verifying_key
        .verify(message, signature)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(Verified(()))
}

/// Challenge de cérémonie (enregistrement ou authentification). Effacé de la mémoire au drop
/// (invariant 8 de `zs-crypto/CLAUDE.md`), bien qu'il ne s'agisse pas d'une clé — un challenge
/// prévisible ou persistant au-delà de sa durée de vie affaiblit la garantie anti-rejeu.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Challenge(Vec<u8>);

impl Challenge {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Longueur du challenge pour `authenticator-proof/v1` : 32 octets, comme recommandé par la
/// spec WebAuthn (entropie suffisante contre la prédiction).
const CHALLENGE_LEN: usize = 32;

/// Génère un nouveau challenge de cérémonie via un CSPRNG.
pub fn new_challenge() -> Challenge {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; CHALLENGE_LEN];
    // SystemRandom::fill ne peut échouer que si le générateur système est indisponible — un
    // refus par panic est correct ici : il n'existe aucun repli sûr à un CSPRNG absent.
    rng.fill(&mut bytes).expect("CSPRNG système indisponible");
    Challenge(bytes)
}

/// Réhydrate un challenge précédemment émis par `new_challenge` et persisté par l'appelant
/// (H5 : `identity.challenges.challenge`). Ce n'est **pas** un constructeur arbitraire : la
/// longueur est celle imposée par la suite, et l'origine CSPRNG reste garantie par le fait que
/// `new_challenge` est le seul émetteur (ADR-006 : un challenge est tiré, jamais dérivé).
/// Nécessaire à tout serveur sans état — entre l'émission et la vérification, le processus peut
/// avoir redémarré ou changer d'instance, un `Challenge` ne peut donc pas rester seulement en
/// mémoire.
///
/// Prend `bytes` **par valeur** délibérément : le tampon lu en base est déplacé dans le type
/// effacé au drop, sans laisser de copie non effacée chez l'appelant (invariant 8). L'appelant
/// doit déplacer directement la colonne lue (`Vec<u8>`), jamais un `clone()` intermédiaire.
pub fn accept_challenge(suite: &str, mut bytes: Vec<u8>) -> Result<Challenge, Error> {
    if suite != SUITE_V1 {
        bytes.zeroize();
        return Err(Error::UnknownSuite);
    }
    if bytes.len() != CHALLENGE_LEN {
        bytes.zeroize();
        return Err(Error::MalformedChallenge);
    }
    Ok(Challenge(bytes))
}

/// Compare un challenge attendu à ce qu'un client a présenté, en temps constant (invariant 6 —
/// fourni ici et nulle part ailleurs). Une comparaison non constante sur un challenge n'est pas
/// le risque le plus grave de ce module, mais l'invariant ne fait pas d'exception de degré.
pub fn challenge_matches(expected: &Challenge, presented: &[u8]) -> bool {
    expected.0.ct_eq(presented).into()
}

/// Empreinte SHA-256, utilisée par `zs-webauthn` pour construire `rpIdHash` et le message signé
/// (`authData || SHA-256(clientDataJSON)`, spec WebAuthn §8.2). Exposée ici — pas dans
/// `zs-webauthn` — car toute opération cryptographique, y compris le hachage, passe par cette
/// façade (règle absolue #4 du `CLAUDE.md` racine).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use aws_lc_rs::digest;
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self, KeyPair};

    fn gen_es256() -> (PublicKeyMaterial, signature::EcdsaKeyPair) {
        let rng = SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let kp = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
        )
        .unwrap();
        let raw = kp.public_key().as_ref().to_vec();
        (
            PublicKeyMaterial {
                algorithm: Algorithm::Es256,
                raw,
            },
            kp,
        )
    }

    // --- cas nominal --------------------------------------------------------------------
    #[test]
    fn es256_signature_valide_est_acceptee() {
        let (material, kp) = gen_es256();
        let key = accept_key(SUITE_V1, material).unwrap();
        let rng = SystemRandom::new();
        let msg = b"authData || sha256(clientDataJSON)";
        let sig = kp.sign(&rng, msg).unwrap();
        assert!(verify(&key, msg, sig.as_ref()).is_ok());
    }

    // --- cas de refus --------------------------------------------------------------------
    #[test]
    fn signature_invalide_est_refusee() {
        let (material, kp) = gen_es256();
        let key = accept_key(SUITE_V1, material).unwrap();
        let rng = SystemRandom::new();
        let sig = kp.sign(&rng, b"message original").unwrap();
        // message different -> signature ne doit plus correspondre
        assert!(verify(&key, b"message modifie", sig.as_ref()).is_err());
    }

    #[test]
    fn suite_inconnue_est_refusee() {
        let (material, _kp) = gen_es256();
        assert!(matches!(
            accept_key("authenticator-proof/v0-inexistante", material),
            Err(Error::UnknownSuite)
        ));
    }

    #[test]
    fn cle_es256_mal_encodee_est_refusee() {
        let material = PublicKeyMaterial {
            algorithm: Algorithm::Es256,
            raw: vec![0u8; 65],
        }; // pas de préfixe 0x04 valide
        assert!(matches!(
            accept_key(SUITE_V1, material),
            Err(Error::MalformedKey)
        ));
    }

    #[test]
    fn cle_longueur_incoherente_avec_algorithme_est_refusee() {
        let material = PublicKeyMaterial {
            algorithm: Algorithm::EdDsa,
            raw: vec![0u8; 65],
        };
        assert!(matches!(
            accept_key(SUITE_V1, material),
            Err(Error::MalformedKey)
        ));
    }

    #[test]
    fn challenge_rejoue_est_detecte_comme_non_concordant() {
        let c1 = new_challenge();
        let c2 = new_challenge();
        assert!(!challenge_matches(&c1, c2.as_bytes()));
        assert!(challenge_matches(&c1, c1.as_bytes()));
    }

    // --- accept_challenge (H5) ---------------------------------------------------------------
    #[test]
    fn challenge_reussit_le_round_trip_par_ses_octets() {
        let original = new_challenge();
        let bytes = original.as_bytes().to_vec();
        let rehydrated = accept_challenge(SUITE_V1, bytes).unwrap();
        assert!(challenge_matches(&original, rehydrated.as_bytes()));
    }

    #[test]
    fn challenge_de_longueur_incorrecte_est_refuse() {
        assert!(matches!(
            accept_challenge(SUITE_V1, vec![0u8; 31]),
            Err(Error::MalformedChallenge)
        ));
        assert!(matches!(
            accept_challenge(SUITE_V1, vec![0u8; 33]),
            Err(Error::MalformedChallenge)
        ));
    }

    #[test]
    fn challenge_avec_suite_inconnue_est_refuse() {
        assert!(matches!(
            accept_challenge("autre-suite/v1", vec![0u8; 32]),
            Err(Error::UnknownSuite)
        ));
    }
}
