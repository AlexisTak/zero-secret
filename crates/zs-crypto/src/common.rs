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

/// UUID validé structurellement : forme `8-4-4-4-12` hexadécimale. `$require_v7` impose en plus
/// le nibble de version (position 14) égal à `7` — utilisé par `EventId` (le contrat exige
/// UUIDv7, ordre lexicographique = ordre temporel) mais pas par `RequestId` (le contrat de
/// `decision.request_id` n'impose que `format: uuid`, sans version particulière : l'imposer
/// refuserait de sceller une décision légitime dont le `request_id` ne serait pas UUIDv7, un
/// événement d'audit perdu, contraire à la règle absolue #9 — ADR-027).
macro_rules! uuid_string {
    ($name:ident, $field:expr, $require_v7:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl $name {
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
                let version_ok = dashes_ok && (!$require_v7 || bytes[14] == b'7');
                if !(hex_ok && version_ok) {
                    return Err(FieldError($field));
                }
                Ok(Self(value))
            }

            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

// Réutilisé par `identity_assertion::audit_event_id` (référence vers l'événement d'audit qui la
// porte) et `audit_seal::event_id` (identifiant propre de l'événement) — UUIDv7 exigé dans les
// deux cas.
uuid_string!(EventId, "event_id", true);
// `audit_seal::DecisionInfo::request_id` (ADR-027) — UUID sans contrainte de version, voir la
// mise en garde ci-dessus.
uuid_string!(RequestId, "decision.request_id", false);

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

/// RFC 8785 (JCS) simplifié : tri **explicite et récursif** des clés d'objet (comparaison sur les
/// octets UTF-8 des littéraux ASCII de ce workspace — diverge de JCS au-dessus de U+FFFF, où JCS
/// trie sur les unités de code UTF-16 ; nos champs ne contiennent jamais un tel caractère, cf.
/// `bounded_ascii_string!`), tableaux laissés dans leur ordre (JCS §3.2.3 : l'ordre y est
/// sémantique, jamais trié) ; `serde_json::to_vec` ne produit aucun espace superflu.
///
/// **Ne repose plus sur le backing `BTreeMap` implicite de `serde_json::Map`.** Ancienne
/// hypothèse invalidée en L2.2 : l'ajout de `cedar-policy` (dépendance transitive
/// `cedar-policy-core` → `serde_json/preserve_order`, via `indexmap`) fait basculer
/// `serde_json::Map` en `IndexMap` (ordre d'insertion) **pour tout le workspace** dès que les deux
/// crates sont compilés ensemble (`cargo test --workspace`) — Cargo unifie les features d'une
/// dépendance partagée sur tout le graphe compilé. Symptôme réel observé : le test de vecteurs
/// figés `zs-audit::chain_vectors` échouait (`NonCanonical`) sous `--workspace` mais passait en
/// isolation. Consultation `referent-crypto` (ADR-015) : une signature ne doit jamais dépendre
/// d'un choix de feature Cargo d'une dépendance tierce — le tri est donc rendu explicite ici,
/// correct quel que soit le backing de `serde_json::Map`.
///
/// Nombre à virgule flottante : refusé explicitement (`assert!`), pas silencieusement signé sous
/// une forme ambiguë — JCS impose la sérialisation ES6 des flottants, non implémentée ici ; aucun
/// document de ce workspace n'en porte (invariant déjà existant, désormais vérifié).
pub(crate) fn canonical_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(&sort_keys_recursively(value))
        .expect("une Value canonicalisée par cette fonction est toujours sérialisable")
}

fn sort_keys_recursively(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            let mut sorted = serde_json::Map::with_capacity(map.len());
            for k in keys {
                sorted.insert(k.clone(), sort_keys_recursively(&map[k]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_keys_recursively).collect()),
        Value::Number(n) => {
            assert!(
                !n.is_f64(),
                "canonical_bytes : nombre à virgule flottante non supporté (JCS/ES6 non implémenté, \
                 invariant du document signé)"
            );
            value.clone()
        }
        _ => value.clone(),
    }
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    use aws_lc_rs::digest;
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cles_triees_quel_que_soit_lordre_dinsertion() {
        // Reste rouge sous `--all-features` tant que canonical_bytes dépend du backing implicite
        // de serde_json::Map (régression L2.2 : cedar-policy-core active preserve_order).
        let insertion_inverse = json!({ "z": 1, "a": 2, "m": 3 });
        let insertion_triee = json!({ "a": 2, "m": 3, "z": 1 });
        assert_eq!(
            canonical_bytes(&insertion_inverse),
            canonical_bytes(&insertion_triee)
        );
        assert_eq!(
            canonical_bytes(&insertion_inverse),
            br#"{"a":2,"m":3,"z":1}"#
        );
    }

    #[test]
    fn tri_recursif_dans_les_objets_imbriques() {
        let value = json!({ "b": { "y": 1, "x": 2 }, "a": 1 });
        assert_eq!(canonical_bytes(&value), br#"{"a":1,"b":{"x":2,"y":1}}"#);
    }

    #[test]
    fn ordre_des_tableaux_jamais_trie() {
        // RFC 8785 §3.2.3 : l'ordre d'un tableau est sémantique, ne doit jamais être réordonné.
        let value = json!({ "a": [3, 1, 2] });
        assert_eq!(canonical_bytes(&value), br#"{"a":[3,1,2]}"#);
    }

    #[test]
    fn aucun_espace_superflu() {
        let value = json!({ "a": 1, "b": [1, 2] });
        assert!(!canonical_bytes(&value).contains(&b' '));
    }

    #[test]
    #[should_panic(expected = "nombre à virgule flottante")]
    fn nombre_a_virgule_flottante_est_refuse() {
        canonical_bytes(&json!({ "a": 1.5 }));
    }
}
