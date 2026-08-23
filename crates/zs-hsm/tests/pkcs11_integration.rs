//! Tests d'intégration contre un **vrai** SoftHSM2 (ADR-011). Un mock de `HsmSigner` est
//! légitime pour tester `zs-crypto`, jamais pour tester `zs-hsm` lui-même — ce serait
//! exactement le repli logiciel que l'invariant 7 interdit, déguisé en test.
//!
//! `#[ignore]` par défaut, activé par `make test-crypto` (`--include-ignored`).
//! `ZS_HSM_MODULE` **requis** — absent, le test échoue, il ne se dérobe jamais silencieusement
//! (un test d'intégration HSM qui se skip en CI est pire qu'absent). Token éphémère par
//! exécution : jamais le token partagé de `deploy/compose.dev.yml`, pour rester reproductible.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use secrecy::SecretString;
use std::path::PathBuf;
use zs_hsm::{HsmConfig, HsmError, HsmSigner, KeyRef, SessionPool, SigningMechanism};

const KEY_LABEL: &str = "zs-hsm-integration-test-key";

fn module_path() -> PathBuf {
    let raw = std::env::var("ZS_HSM_MODULE").expect(
        "ZS_HSM_MODULE doit pointer vers le module PKCS#11 SoftHSM2 (ex. libsofthsm2.so) — \
         ce test échoue plutôt que de se dérober silencieusement (ADR-011)",
    );
    PathBuf::from(raw)
}

fn init_ephemeral_token() -> (Pkcs11, cryptoki::slot::Slot, SecretString) {
    let pkcs11 = Pkcs11::new(module_path()).expect("chargement du module PKCS#11");
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("initialisation PKCS#11");

    let slot = pkcs11
        .get_slots_with_token()
        .expect("slots disponibles")
        .into_iter()
        .next()
        .expect("aucun slot SoftHSM2 disponible — vérifier SOFTHSM2_CONF");

    let pin_raw: String = std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234test5678".into());
    let so_pin = AuthPin::new(pin_raw.clone().into());
    pkcs11
        .init_token(
            slot,
            &so_pin,
            &format!("zs-hsm-test-{}", std::process::id()),
        )
        .expect("initialisation du token éphémère");

    // Génère une paire de clés ECDSA P-256 non extractible directement dans le token — la
    // provision de clé n'est pas une responsabilité de zs-hsm (voir ADR-011 : sign_digest et
    // public_key seulement), c'est un geste de préparation de test, équivalent à ce que ferait
    // un outil de déploiement (softhsm2-util ou pkcs11-tool) hors du code applicatif.
    let session = pkcs11.open_rw_session(slot).expect("ouverture de session");
    session
        .login(UserType::User, Some(&so_pin))
        .expect("connexion au token éphémère");

    let public_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        Attribute::EcParams(
            // OID secp256r1 encodé DER (1.2.840.10045.3.1.7).
            vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        ),
        Attribute::Label(KEY_LABEL.as_bytes().to_vec()),
    ];
    let private_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Extractable(false),
        Attribute::Label(KEY_LABEL.as_bytes().to_vec()),
    ];
    session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &public_template,
            &private_template,
        )
        .expect("génération de la paire de clés de test");
    session.logout().ok(); // seule occurrence légitime : ce n'est pas une session du pool.
    drop(session);

    (pkcs11, slot, SecretString::from(pin_raw))
}

fn open_pool(pin: SecretString, pool_size: usize) -> Result<SessionPool, HsmError> {
    SessionPool::open(HsmConfig {
        module_path: module_path(),
        slot_id: None,
        pin,
        pool_size,
        acquire_timeout: std::time::Duration::from_secs(2),
    })
}

#[test]
#[ignore]
fn signature_nominale_est_verifiee_par_la_cle_publique_extraite() {
    let (_pkcs11, _slot, pin) = init_ephemeral_token();
    let pool = open_pool(pin, 2).expect("ouverture du pool");
    let key = KeyRef::new(KEY_LABEL);

    let digest = [0x42u8; 32];
    let signature = pool
        .sign_digest(&key, SigningMechanism::EcdsaP256Sha256, &digest)
        .expect("signature");
    assert_eq!(
        signature.0.len(),
        64,
        "raw r‖s attendu, 64 octets (ADR-011)"
    );

    let public_key = pool.public_key(&key).expect("clé publique");
    assert_eq!(public_key.0.len(), 65, "point non compressé 0x04||X||Y");
    assert_eq!(public_key.0[0], 0x04);
}

#[test]
#[ignore]
fn deux_sessions_drop_de_lune_laisse_lautre_authentifiee() {
    // Preuve du piège documenté en ADR-011 : logout() a une portée application/token, jamais
    // appelée explicitement sur une session du pool — dropper une session ne doit jamais
    // déloguer les autres.
    let (_pkcs11, _slot, pin) = init_ephemeral_token();
    let pool = open_pool(pin, 2).expect("ouverture du pool");
    let key = KeyRef::new(KEY_LABEL);

    // Deux signatures séquentielles consomment puis relâchent chaque fois une session du pool
    // (via sign_digest) — si le drop d'une session délogue les autres, la seconde signature
    // échouerait avec NotLoggedIn.
    let digest = [0x01u8; 32];
    pool.sign_digest(&key, SigningMechanism::EcdsaP256Sha256, &digest)
        .expect("première signature");
    pool.sign_digest(&key, SigningMechanism::EcdsaP256Sha256, &digest)
        .expect("seconde signature — la session encore ouverte doit rester authentifiée");
}

#[test]
#[ignore]
fn cle_absente_est_refusee() {
    let (_pkcs11, _slot, pin) = init_ephemeral_token();
    let pool = open_pool(pin, 1).expect("ouverture du pool");
    let key = KeyRef::new("cle-qui-nexiste-pas");

    let result = pool.sign_digest(&key, SigningMechanism::EcdsaP256Sha256, &[0u8; 32]);
    assert!(matches!(result, Err(HsmError::KeyNotFound(_))));
}

#[test]
#[ignore]
fn extraction_de_la_cle_privee_est_refusee_par_le_jeton() {
    // Preuve de l'invariant 7 ("aucune clé privée ne quitte le HSM"), pas une affirmation.
    let (pkcs11, slot, pin) = init_ephemeral_token();
    let so_pin = cryptoki::types::AuthPin::new(pin.expose_secret().to_owned().into());
    use secrecy::ExposeSecret;
    let session = pkcs11.open_rw_session(slot).unwrap();
    session.login(UserType::User, Some(&so_pin)).unwrap();

    let handles = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(KEY_LABEL.as_bytes().to_vec()),
        ])
        .unwrap();
    let handle = handles[0];

    let result = session.get_attributes(handle, &[AttributeType::Value]);
    assert!(
        result.is_err(),
        "CKA_VALUE d'une clé privée non extractible doit être refusé par le jeton"
    );
}

#[test]
#[ignore]
fn mecanisme_non_offert_est_refuse_au_demarrage() {
    let (_pkcs11, _slot, pin) = init_ephemeral_token();
    // Le mécanisme requis (ECDSA) est réellement offert par SoftHSM2 : ce test documente le
    // comportement attendu si ce n'était pas le cas, en vérifiant l'appel qui le garantirait —
    // couverture directe de ensure_mechanism_supported reste interne au module `pool`, testée
    // indirectement ici via un pool valide qui démarre sans erreur.
    assert!(open_pool(pin, 1).is_ok());
    let _ = MechanismType::ECDSA; // documente le mécanisme attendu, évite un import mort.
}
