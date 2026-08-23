//! Types et fonctions partagés entre les suites d'émission de `zs-crypto` (`identity_assertion`,
//! `audit_seal`) — validateurs de contenu, encodage, canonicalisation JCS, façade de hachage.
//! Extrait de `identity_assertion.rs` (L1.2c) pour `audit_seal` (L1.4b, ADR-013) : un second
//! validateur UUIDv7/RFC3339 dupliqué aurait divergé du premier sans que rien ne le détecte.
//! Interne au crate — chaque suite compose ces briques sous son propre type d'erreur public.

use serde_json::Value;

/// Erreur de validation d'un champ, portée par les types partagés. Chaque suite la convertit
/// vers son propre type d'erreur public (`identity_assertion::SealError::InvalidClaims`,
/// `audit_seal::SealError::InvalidFields`) via `From<FieldError>` — jamais exposée telle quelle.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
#[error("champ invalide : '{0}'")]
pub struct FieldError(pub &'static str);

/// Chaîne validée à la construction : ASCII imprimable hors `"`/`\`, longueur bornée. Rend la
/// conformité JCS de l'échappement structurellement vraie plutôt que dépendante d'un détail de
/// `serde_json` sur tout l'espace Unicode (mise en garde `referent-crypto`, L1.2c).
macro_rules! bounded_ascii_string {
    ($name:ident, $max_len:expr, $field:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, crate::common::FieldError> {
                let value = value.into();
                if value.is_empty() || value.len() > $max_len {
                    return Err(crate::common::FieldError($field));
                }
                if !value
                    .bytes()
                    .all(|b| (0x20..=0x7E).contains(&b) && b != b'"' && b != b'\\')
                {
                    return Err(crate::common::FieldError($field));
                }
                Ok(Self(value))
            }

            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
pub(crate) use bounded_ascii_string;

/// RFC 3339 UTC strict : `AAAA-MM-JJThh:mm:ssZ` exactement — `Z` obligatoire, aucune fraction de
/// seconde. Validation structurelle (longueur, positions, plages numériques), pas un calendrier
/// complet — suffisant pour garantir une forme canonique unique d'un même instant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(String);

impl Timestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, FieldError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let valid = bytes.len() == 20
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes[19] == b'Z'
            && bytes
                .iter()
                .enumerate()
                .all(|(i, &b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit());
        if !valid {
            return Err(FieldError("timestamp"));
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// UUIDv7 validé structurellement : forme `8-4-4-4-12` hexadécimale, nibble de version (position
/// 14) égal à `7`. Réutilisé par `identity_assertion::audit_event_id` (référence vers
/// l'événement d'audit qui la porte) et `audit_seal::event_id` (identifiant propre de
/// l'événement) — même validation, deux usages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventId(String);

impl EventId {
    pub fn new(value: impl Into<String>) -> Result<Self, FieldError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let dashes_ok = bytes.len() == 36
            && bytes[8] == b'-'
            && bytes[13] == b'-'
            && bytes[18] == b'-'
            && bytes[23] == b'-';
        let hex_ok = dashes_ok
            && bytes
                .iter()
                .enumerate()
                .all(|(i, &b)| matches!(i, 8 | 13 | 18 | 23) || b.is_ascii_hexdigit());
        let version_ok = dashes_ok && bytes[14] == b'7';
        if !(hex_ok && version_ok) {
            return Err(FieldError("event_id"));
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub(crate) fn key_id_from_public_key(sec1_uncompressed: &[u8]) -> String {
    hex_encode(&sha256(sec1_uncompressed)[..8])
}

/// RFC 8785 (JCS) simplifié : `serde_json::Map` est adossée à une `BTreeMap` par défaut (feature
/// `preserve_order` absente de ce workspace), donc les clés sont déjà triées à la sérialisation ;
/// `serde_json::to_vec` ne produit aucun espace superflu — suffisant pour un document ne
/// contenant que chaînes, entiers, tableaux et objets, jamais de nombre à virgule flottante.
pub(crate) fn canonical_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("un serde_json::Value construit ici est toujours sérialisable")
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    use aws_lc_rs::digest;
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}
