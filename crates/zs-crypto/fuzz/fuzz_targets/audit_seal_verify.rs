//! Cible de fuzzing pour `audit_seal::verify` (backlog L1.4b, ADR-013), miroir de
//! `identity_assertion_verify`. Ne doit jamais paniquer, quel que soit l'octet fourni — un refus
//! (`Err`) est le comportement attendu pour à peu près toute entrée aléatoire.
//!
//! `make fuzz TARGET=audit_seal_verify` (Makefile racine).

#![no_main]

use libfuzzer_sys::fuzz_target;
use zs_crypto::audit_seal::{AcceptancePolicy, SUITE_V1, accept_verifying_key};

fuzz_target!(|data: &[u8]| {
    let mut sec1 = vec![0x04u8; 65];
    sec1[1..].copy_from_slice(&[0x11u8; 64]);
    let Ok(key) = accept_verifying_key(SUITE_V1, "fuzz-key-id", &sec1) else {
        return;
    };
    let policy = AcceptancePolicy {
        accepted_suites: &[SUITE_V1],
        expected_authority_domain: "identity-provider".to_string(),
    };

    let _ = zs_crypto::audit_seal::verify(&[key], data, &policy);
});
