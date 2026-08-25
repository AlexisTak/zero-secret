//! Vecteurs de conformité ECDSA P-256/SHA-256 (Project Wycheproof, format IEEE P1363 — signature
//! `r||s` brute, exactement ce qu'exige `ECDSA_P256_SHA256_FIXED` d'aws-lc-rs, seul point
//! d'entrée utilisé par `zs-crypto` pour vérifier ECDSA P-256 dans les trois suites
//! (`audit_seal`, `identity_assertion`, `decision_seal`). Comble audit.md §3.2 : `make
//! test-crypto` n'exécutait jusqu'ici aucun vecteur de conformité externe.
//!
//! `#[ignore]` : réservé à `make test-crypto`, pas au cycle rapide `cargo nextest run` /
//! `make test` — même discipline que les tests PKCS#11 (H1).

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use wycheproof::TestResult;
use wycheproof::ecdsa::{TestName, TestSet};

#[test]
#[ignore = "vecteurs de conformité externes — réservé à make test-crypto, audit.md §3.2"]
fn wycheproof_ecdsa_p256_sha256_p1363() {
    let test_set = TestSet::load(TestName::EcdsaSecp256r1Sha256P1363)
        .expect("chargement des vecteurs Wycheproof ECDSA P-256/SHA-256 P1363");

    let mut checked = 0usize;
    let mut failures = Vec::new();

    for group in &test_set.test_groups {
        let verifying_key =
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, group.key.key.as_ref());
        for test in &group.tests {
            checked += 1;
            let accepted = verifying_key
                .verify(test.msg.as_ref(), test.sig.as_ref())
                .is_ok();
            // Acceptable : la spec autorise refus ou acceptation (ex. propriété jugée trop
            // faible pour certaines politiques) — aws-lc-rs peut légitimement trancher dans les
            // deux sens sans que ce soit un défaut de conformité.
            let ok = match test.result {
                TestResult::Valid => accepted,
                TestResult::Invalid => !accepted,
                TestResult::Acceptable => true,
            };
            if !ok {
                failures.push(format!(
                    "tcId={} accepté={accepted} attendu={:?} — {}",
                    test.tc_id, test.result, test.comment
                ));
            }
        }
    }

    assert!(
        checked > 0,
        "aucun vecteur chargé — jeu de données Wycheproof vide ou absent"
    );
    assert!(
        failures.is_empty(),
        "{} échec(s) sur {checked} vecteurs Wycheproof :\n{}",
        failures.len(),
        failures.join("\n")
    );
}
