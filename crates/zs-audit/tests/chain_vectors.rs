//! Consomme `tests/vectors/audit-seal-v1/chain.json` (produit par
//! `crates/zs-crypto/src/audit_seal.rs::tests::regenerer_les_vecteurs_de_chainage`, ADR-013) —
//! preuve d'intégration bout en bout entre `zs-audit` (chaînage) et `zs-crypto` (scellement),
//! chacun testé via sa seule API publique : aucune primitive cryptographique importée ici,
//! `zs-audit` ne fait que vérifier.

use zs_audit::{ChainEntry, verify_chain};
use zs_crypto::audit_seal::{self, AcceptancePolicy, accept_verifying_key};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn vecteurs_figes_verifient_signature_et_chainage() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/audit-seal-v1/chain.json"
    ))
    .expect("tests/vectors/audit-seal-v1/chain.json manquant");
    let vector: serde_json::Value = serde_json::from_str(&text).unwrap();

    let suite = vector["suite"].as_str().unwrap();
    let key_id = vector["key_id"].as_str().unwrap();
    let public_key = hex_decode(vector["public_key_sec1_hex"].as_str().unwrap());
    let key = accept_verifying_key(suite, key_id, &public_key).unwrap();

    let events_hex: Vec<&str> = vector["events_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    let policy = AcceptancePolicy {
        accepted_suites: &[audit_seal::SUITE_V1],
        expected_authority_domain: "identity-provider".to_string(),
    };

    let mut chain_entries = Vec::new();
    for hex in &events_hex {
        let bytes = hex_decode(hex);
        let verified = audit_seal::verify(std::slice::from_ref(&key), &bytes, &policy)
            .expect("chaque vecteur figé doit rester vérifiable — dérive de canonicalisation ?");

        chain_entries.push(ChainEntry {
            authority_domain: verified.authority_domain,
            sequence: verified.sequence,
            prev_hash: verified.prev_hash,
            sealed_bytes: bytes,
        });
    }

    verify_chain(&chain_entries).expect("la chaîne des 3 événements figés doit rester valide");
}
