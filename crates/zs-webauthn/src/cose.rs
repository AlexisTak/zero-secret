//! Extraction d'une clé publique COSE (RFC 9053) vers la représentation brute attendue par
//! `zs_crypto::authenticator_proof`. Ce module ne fait aucune vérification cryptographique —
//! il ne fait que lire une structure, la frontière avec `zs-crypto` est délibérée (ADR-006).

use coset::cbor::value::Value;
use coset::{CborSerializable, CoseKey, Label, RegisteredLabel};
use zs_crypto::authenticator_proof::{Algorithm, PublicKeyMaterial};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("clé COSE malformée (CBOR invalide)")]
    InvalidCbor,
    #[error("type de clé COSE non supporté par authenticator-proof/v1")]
    UnsupportedKeyType,
    #[error("paramètre de clé COSE manquant ou de longueur incorrecte")]
    MissingOrInvalidParameter,
}

/// Décode une clé publique COSE_Key et l'algorithme qu'elle porte, sous la forme attendue par
/// `zs_crypto::authenticator_proof::accept_key`.
///
/// Refuse explicitement tout type de clé hors EC2/P-256 (ES256) et OKP/Ed25519 (EdDSA) — RSA et
/// les autres courbes sont hors périmètre de `authenticator-proof/v1` (ADR-006).
pub fn extract_public_key_material(cose_key_bytes: &[u8]) -> Result<PublicKeyMaterial, Error> {
    let key = CoseKey::from_slice(cose_key_bytes).map_err(|_| Error::InvalidCbor)?;

    let param = |wanted: i64| -> Option<&Value> {
        key.params.iter().find_map(|(label, value)| match label {
            Label::Int(n) if *n == wanted => Some(value),
            _ => None,
        })
    };
    let int_param = |wanted: i64| -> Option<i128> {
        match param(wanted) {
            Some(Value::Integer(i)) => Some((*i).into()),
            _ => None,
        }
    };
    let bytes_param = |wanted: i64| -> Option<Vec<u8>> {
        match param(wanted) {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        }
    };

    match key.kty {
        RegisteredLabel::Assigned(coset::iana::KeyType::EC2) => {
            let crv = int_param(-1);
            if crv != Some(1) {
                // 1 = P-256 (RFC 9053). Toute autre courbe EC2 est hors suite v1.
                return Err(Error::UnsupportedKeyType);
            }
            let x = bytes_param(-2).ok_or(Error::MissingOrInvalidParameter)?;
            let y = bytes_param(-3).ok_or(Error::MissingOrInvalidParameter)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(Error::MissingOrInvalidParameter);
            }
            let mut raw = Vec::with_capacity(65);
            raw.push(0x04); // SEC1 non compressé
            raw.extend_from_slice(&x);
            raw.extend_from_slice(&y);
            Ok(PublicKeyMaterial {
                algorithm: Algorithm::Es256,
                raw,
            })
        }
        RegisteredLabel::Assigned(coset::iana::KeyType::OKP) => {
            let crv = int_param(-1);
            if crv != Some(6) {
                // 6 = Ed25519 (RFC 9053). Ed448 et autres OKP hors suite v1.
                return Err(Error::UnsupportedKeyType);
            }
            let x = bytes_param(-2).ok_or(Error::MissingOrInvalidParameter)?;
            if x.len() != 32 {
                return Err(Error::MissingOrInvalidParameter);
            }
            Ok(PublicKeyMaterial {
                algorithm: Algorithm::EdDsa,
                raw: x,
            })
        }
        _ => Err(Error::UnsupportedKeyType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{CborSerializable, CoseKeyBuilder, iana};

    #[test]
    fn cle_ec2_p256_valide_est_extraite() {
        let key = CoseKeyBuilder::new_ec2_pub_key(
            iana::EllipticCurve::P_256,
            vec![1u8; 32],
            vec![2u8; 32],
        )
        .algorithm(iana::Algorithm::ES256)
        .build();
        let bytes = key.to_vec().unwrap();
        let material = extract_public_key_material(&bytes).unwrap();
        assert_eq!(material.algorithm, Algorithm::Es256);
        assert_eq!(material.raw.len(), 65);
        assert_eq!(material.raw[0], 0x04);
    }

    #[test]
    fn cle_okp_ed25519_valide_est_extraite() {
        let key = CoseKeyBuilder::new_okp_key()
            .algorithm(iana::Algorithm::EdDSA)
            .param(-1, Value::from(6))
            .param(-2, Value::from(vec![7u8; 32]))
            .build();
        let bytes = key.to_vec().unwrap();
        let material = extract_public_key_material(&bytes).unwrap();
        assert_eq!(material.algorithm, Algorithm::EdDsa);
        assert_eq!(material.raw.len(), 32);
    }

    #[test]
    fn courbe_non_supportee_est_refusee() {
        let key = CoseKeyBuilder::new_ec2_pub_key(
            iana::EllipticCurve::P_384,
            vec![1u8; 48],
            vec![2u8; 48],
        )
        .algorithm(iana::Algorithm::ES384)
        .build();
        let bytes = key.to_vec().unwrap();
        assert!(matches!(
            extract_public_key_material(&bytes),
            Err(Error::UnsupportedKeyType)
        ));
    }

    #[test]
    fn cbor_invalide_est_refuse() {
        assert!(matches!(
            extract_public_key_material(&[0xff, 0x00, 0x01]),
            Err(Error::InvalidCbor)
        ));
    }
}
