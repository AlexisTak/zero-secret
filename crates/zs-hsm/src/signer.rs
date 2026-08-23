//! Surface publique de signature (ADR-011). Générique, sans vocabulaire métier : ce crate ignore
//! ce qu'est une « assertion d'identité » ou un « événement d'audit » — c'est `zs-crypto` qui
//! porte cette intention, `zs-hsm` ne fait que signer un condensé avec une clé référencée par
//! son étiquette.

use crate::error::HsmError;
use crate::mechanism::SigningMechanism;

/// Référence logique d'une clé dans le jeton — jamais un handle PKCS#11 persisté : un handle
/// n'est pas stable entre deux exécutions du processus, seule l'étiquette (`CKA_LABEL`) l'est.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef {
    label: String,
}

impl KeyRef {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Signature brute `r‖s`, 64 octets pour `EcdsaP256Sha256` (ADR-011 : encodage figé, entre dans
/// `prev_hash` côté `zs-audit` — jamais DER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

/// Clé publique correspondante, encodage SEC1 non compressé (`0x04 || X || Y`) pour
/// `EcdsaP256Sha256` — même encodage que `zs_crypto::authenticator_proof::PublicKeyMaterial`,
/// pour que la vérification en aval reste uniforme dans tout le projet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyDer(pub Vec<u8>);

/// Point d'entrée unique de signature HSM. Trait — pas une struct concrète exportée — pour que
/// `zs-crypto` puisse injecter un double en test ; **aucune implémentation hors `zs-hsm` (et hors
/// `#[cfg(test)]`) n'est légitime** : un double de production serait exactement le repli logiciel
/// interdit par l'invariant 7 de `zs-crypto/CLAUDE.md`, déguisé en abstraction.
pub trait HsmSigner: Send + Sync {
    /// Signe `digest` (déjà condensé par l'appelant — ce crate ne hache jamais lui-même, un seul
    /// point de vérité pour le hachage côté `zs-crypto`/`zs-audit`) avec la clé `key`.
    ///
    /// Ne réessaie jamais en interne : voir ADR-011 (ECDSA est randomisé, un réessai produirait
    /// une seconde signature valide sur le même contenu — risque de fourche de chaîne
    /// d'audit). Toute anomalie remonte en `HsmError`, sans distinction masquée.
    fn sign_digest(
        &self,
        key: &KeyRef,
        mechanism: SigningMechanism,
        digest: &[u8],
    ) -> Result<Signature, HsmError>;

    /// Clé publique correspondant à `key`, pour publication ou vérification hors HSM.
    fn public_key(&self, key: &KeyRef) -> Result<PublicKeyDer, HsmError>;
}
