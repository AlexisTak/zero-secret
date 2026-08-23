//! Cible de fuzzing pour `identity_assertion::verify` (backlog L1.2c, ADR-012). `verify` est le
//! seul analyseur d'`identity_assertion` exposé à une entrée non fiable (une assertion
//! présentée par un client à `access-broker`/`policy-engine`) — exigence de fuzzing de
//! `zs-crypto/CLAUDE.md`.
//!
//! Clé et politique fixes, seuls les octets du document varient : ne doit jamais paniquer, quel
//! que soit l'octet fourni — un refus (`Err`) est le comportement attendu pour à peu près toute
//! entrée aléatoire, un panic ne l'est jamais.
//!
//! `make fuzz TARGET=identity_assertion_verify` (Makefile racine).

#![no_main]

use libfuzzer_sys::fuzz_target;
use zs_crypto::identity_assertion::{AcceptancePolicy, SUITE_V1, Timestamp, accept_verifying_key};

fuzz_target!(|data: &[u8]| {
    // Point SEC1 non compressé arbitraire mais bien formé (0x04 || 64 octets) — seul l'encodage
    // structurel compte ici, pas la validité du point sur la courbe : verify() doit refuser
    // proprement, jamais paniquer, même contre une clé qui ne correspondrait à aucune signature
    // valide.
    let mut sec1 = vec![0x04u8; 65];
    sec1[1..].copy_from_slice(&[0x11u8; 64]);
    let Ok(key) = accept_verifying_key(SUITE_V1, "fuzz-key-id", &sec1) else {
        return;
    };
    let Ok(now) = Timestamp::new("2026-08-23T10:00:00Z") else {
        return;
    };
    let policy = AcceptancePolicy {
        accepted_suites: &[SUITE_V1],
        now,
        expected_authority_domain: "identity-provider".to_string(),
    };

    let _ = zs_crypto::identity_assertion::verify(&[key], data, &policy);
});
