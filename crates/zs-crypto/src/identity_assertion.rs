//! Suite `identity-assertion` (ADR-007/008, scellement réel ADR-012). Scelle le résultat d'une
//! authentification déjà vérifiée en un objet transmissible, vérifiable hors HSM, lié à son
//! événement d'audit — la primitive de confiance en entrée du PDP, pas un jeton de session.
//!
//! Émetteur, pas vérificateur : soumis pleinement à l'invariant 5 (hybridation stricte) et à
//! l'invariant 7 (clé privée jamais hors HSM), contrairement à `authenticator_proof`. `seal`
//! appelle `zs_hsm` en interne ; aucun type `zs-hsm` n'apparaît dans cette surface publique
//! (ADR-011) — `HsmError` est traduit en `SealError::SealingUnavailable`, opaque, jamais
//! discriminable par un appelant tenté de faire un `match` qui déciderait de continuer.
//!
//! Format : JSON canonique RFC 8785 (JCS). `signatures` est un tableau dès `v1` (rappel R8,
//! ADR-008/012) : l'arité et l'ordre des composantes sont imposés par la suite, jamais par le
//! message — un document `v2` à une seule composante est refusé, pas validé partiellement.
//! Séparation de domaine par préfixe (`zero-secret/identity-assertion/v1`) : `audit-seal/v1`
//! réutilise la même primitive P-256/SHA-256 avec une clé distincte (ADR-011), la séparation
//! élimine toute confusion de contexte par construction plutôt que par convention de nommage.
//!
//! Types partagés (`Timestamp`, `EventId`, encodage, canonicalisation) extraits dans
//! `crate::common` (ADR-013) — `audit_seal` les réutilise, jamais un second validateur dupliqué.

use crate::common::{self, EventId, FieldError, Timestamp, bounded_ascii_string};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use zs_hsm::{HsmConfig, HsmSigner, KeyRef, SessionPool, SigningMechanism};

pub const SUITE_V1: &str = "identity-assertion/v1";
const DOMAIN_PREFIX: &str = "zero-secret/identity-assertion/v1";
const MAX_BYTES: usize = 4096;
const REQUIRED_COMPONENTS_V1: &[&str] = &["ecdsa-p256"];

/// Niveau d'assurance atteint — type plat, propre à `zs-crypto` : ce module ne dépend d'aucun
/// type `zs-webauthn` (frontière vérifiée par `tools/lib/check-zs-crypto-deps.sh`). L'appelant
/// (`identity-provider`) convertit `zs_webauthn::Aal` vers ce type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceLevel {
    Aal1,
    Aal2,
    Aal3,
}

impl AssuranceLevel {
    fn as_str(self) -> &'static str {
        match self {
            AssuranceLevel::Aal1 => "AAL1",
            AssuranceLevel::Aal2 => "AAL2",
            AssuranceLevel::Aal3 => "AAL3",
        }
    }
}

bounded_ascii_string!(SubjectId, 256, "subject_id");
bounded_ascii_string!(AuthMethod, 64, "auth_method");
bounded_ascii_string!(Audience, 256, "audience");

/// Contenu métier d'une assertion à sceller. `issued_at`/`expires_at`/`audit_event_id` sont
/// fournis par l'appelant — ce module ne lit aucune horloge ni ne génère d'identifiant
/// (déterminisme, testabilité, ordre R7 : l'UUIDv7 est produit avant, par l'IdP).
pub struct AssertionClaims {
    pub authority_domain: String,
    pub subject_id: SubjectId,
    pub aal: AssuranceLevel,
    pub auth_method: AuthMethod,
    pub audience: Audience,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub audit_event_id: EventId,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    #[error("contenu d'assertion invalide : champ '{0}'")]
    InvalidClaims(&'static str),
    #[error("scellement indisponible")]
    SealingUnavailable,
}

impl From<FieldError> for SealError {
    fn from(e: FieldError) -> Self {
        SealError::InvalidClaims(e.0)
    }
}

/// Configuration HSM propre à `zs-crypto` — recopiée vers `zs_hsm::HsmConfig` en interne,
/// aucun type `zs-hsm` ne traverse la frontière publique (ADR-011).
pub struct HsmSettings {
    pub module_path: std::path::PathBuf,
    pub slot_id: Option<u64>,
    pub pin: secrecy::SecretString,
    pub pool_size: usize,
    pub acquire_timeout: std::time::Duration,
    /// Étiquette de la clé HSM dédiée à `identity-assertion` — `zs-identity-assertion-v1` par
    /// convention (ADR-013), distincte de celle d'`audit-seal` (ADR-011, deux clés séparées).
    pub key_label: String,
}

/// Scelleur d'assertions — encapsule le pool de sessions HSM et la clé de vérification mise en
/// cache au démarrage (`key_id` publié = 8 premiers octets hex de `sha256(point SEC1)`).
pub struct AssertionSealer {
    pool: SessionPool,
    key: KeyRef,
    key_id: String,
}

impl AssertionSealer {
    /// Ouvre le pool HSM et met en cache l'identifiant de clé publiée. Échec dur si le HSM est
    /// indisponible au démarrage — jamais une ouverture différée qui masquerait le problème.
    pub fn open(settings: HsmSettings) -> Result<Self, SealError> {
        let key = KeyRef::new(settings.key_label);
        let pool = SessionPool::open(HsmConfig {
            module_path: settings.module_path,
            slot_id: settings.slot_id,
            pin: settings.pin,
            pool_size: settings.pool_size,
            acquire_timeout: settings.acquire_timeout,
        })
        .map_err(opaque)?;
        let public_key = pool.public_key(&key).map_err(opaque)?;
        let key_id = common::key_id_from_public_key(&public_key.0);
        Ok(Self { pool, key, key_id })
    }

    /// Scelle `claims` — construit le message signé (préfixe de domaine, condensé du document
    /// canonique sans `signatures`), l'envoie à `zs-hsm` (digest pré-calculé, jamais réessayé —
    /// ADR-011 : ECDSA est randomisé, un réessai produirait une seconde signature valide sur le
    /// même contenu, risque de fourche puisque `prev_hash` inclut la signature).
    pub fn seal(&self, claims: AssertionClaims) -> Result<SealedAssertion, SealError> {
        let unsigned = unsigned_document(&claims);
        let message = signed_message(&unsigned);
        let digest = common::sha256(&message);

        let signature = self
            .pool
            .sign_digest(&self.key, SigningMechanism::EcdsaP256Sha256, &digest)
            .map_err(opaque)?;

        let mut document = unsigned;
        document.insert(
            "signatures".to_string(),
            Value::Array(vec![json!({
                "component": REQUIRED_COMPONENTS_V1[0],
                "key_id": self.key_id,
                "value": common::hex_encode(&signature.0),
            })]),
        );

        Ok(SealedAssertion {
            bytes: common::canonical_bytes(&Value::Object(document)),
        })
    }
}

fn opaque(err: zs_hsm::HsmError) -> SealError {
    tracing::warn!(hsm_error = %err, "scellement d'assertion d'identité indisponible");
    SealError::SealingUnavailable
}

/// Assertion scellée. Aucun `Serialize` dérivé, aucun constructeur public depuis des octets
/// bruts (seule `verify` produit l'équivalent vérifié) — même garde-fou qu'`AuthenticationClaims`
/// (L1.2b) : un objet qui ressemble à une assertion sans preuve de scellement réel serait un
/// contournement d'authentification représentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAssertion {
    bytes: Vec<u8>,
}

impl SealedAssertion {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Empreinte des octets scellés — ce que `zs-audit` chaînera dans `prev_hash` de
    /// l'événement d'audit suivant (R7 : `audit_event_id` généré avant, assertion scellée le
    /// portant, événement scellé portant `SHA-256(assertion)`).
    pub fn digest(&self) -> [u8; 32] {
        common::sha256(&self.bytes)
    }

    pub fn suite(&self) -> &'static str {
        SUITE_V1
    }
}

/// Clé de vérification acceptée. Ne peut être construite que par `accept_verifying_key` — une
/// clé dont l'encodage est invalide n'existe jamais sous cette forme (même patron que
/// `authenticator_proof::AcceptedKey`).
#[derive(Debug)]
pub struct AcceptedVerifyingKey {
    key_id: String,
    raw: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("suite inconnue ou retirée")]
    UnknownSuite,
    #[error("clé publique malformée")]
    MalformedKey,
    #[error("assertion dépasse la taille maximale acceptée")]
    TooLarge,
    #[error("assertion n'est pas un JSON valide ou un champ requis manque")]
    MalformedDocument,
    #[error("sérialisation non canonique — octets rejoués ou falsifiés")]
    NonCanonical,
    #[error("nombre ou ordre de composantes de signature incorrect pour cette suite")]
    InvalidSignatureArity,
    #[error("identifiant de clé inconnu")]
    UnknownKeyId,
    #[error("signature invalide")]
    InvalidSignature,
    #[error("domaine d'autorité inattendu")]
    UnexpectedAuthorityDomain,
    #[error("assertion expirée ou pas encore valide")]
    NotYetValidOrExpired,
}

/// Accepte une clé de vérification pour la suite donnée. Refuse tout encodage incohérent —
/// `raw` est le point SEC1 non compressé (`0x04 || X(32) || Y(32)`, 65 octets pour P-256).
pub fn accept_verifying_key(
    suite: &str,
    key_id: &str,
    sec1_uncompressed: &[u8],
) -> Result<AcceptedVerifyingKey, VerifyError> {
    if suite != SUITE_V1 {
        return Err(VerifyError::UnknownSuite);
    }
    if sec1_uncompressed.len() != 65 || sec1_uncompressed[0] != 0x04 {
        return Err(VerifyError::MalformedKey);
    }
    Ok(AcceptedVerifyingKey {
        key_id: key_id.to_string(),
        raw: sec1_uncompressed.to_vec(),
    })
}

/// Politique d'acceptation — horloge et suites acceptées fournies par l'appelant (période de
/// recouvrement explicite, invariant 4), jamais lues en ambiant par ce module.
pub struct AcceptancePolicy {
    pub accepted_suites: &'static [&'static str],
    pub now: Timestamp,
    pub expected_authority_domain: String,
}

/// Assertion vérifiée. Aucun constructeur public — impossible d'obtenir cette valeur sans être
/// passé par `verify` (même patron que `authenticator_proof::Verified`).
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedAssertion {
    subject_id: String,
    aal: String,
    auth_method: String,
    audience: String,
    issued_at: String,
    expires_at: String,
    audit_event_id: String,
}

impl VerifiedAssertion {
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }
    pub fn aal(&self) -> &str {
        &self.aal
    }
    pub fn auth_method(&self) -> &str {
        &self.auth_method
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }
    pub fn audit_event_id(&self) -> &str {
        &self.audit_event_id
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDocument {
    schema_version: u32,
    suite: String,
    authority_domain: String,
    subject_id: String,
    aal: String,
    auth_method: String,
    audience: String,
    issued_at: String,
    expires_at: String,
    audit_event_id: String,
    signatures: Vec<WireSignatureComponent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSignatureComponent {
    component: String,
    key_id: String,
    value: String,
}

/// Vérifie une assertion scellée. Ordre non négociable (referent-crypto) : borne de taille avant
/// tout parse, parse strict, canonicité vérifiée par re-sérialisation (pas supposée), suite et
/// arité de signature, résolution de chaque clé, vérification de **toutes** les composantes
/// sans court-circuit, puis contexte (domaine, fenêtre temporelle).
pub fn verify(
    keys: &[AcceptedVerifyingKey],
    bytes: &[u8],
    policy: &AcceptancePolicy,
) -> Result<VerifiedAssertion, VerifyError> {
    if bytes.len() > MAX_BYTES {
        return Err(VerifyError::TooLarge);
    }

    let doc: WireDocument =
        serde_json::from_slice(bytes).map_err(|_| VerifyError::MalformedDocument)?;

    if doc.schema_version != 1 {
        return Err(VerifyError::MalformedDocument);
    }
    if !policy.accepted_suites.contains(&doc.suite.as_str()) {
        return Err(VerifyError::UnknownSuite);
    }

    let required = required_components(&doc.suite)?;
    if doc.signatures.len() != required.len()
        || doc
            .signatures
            .iter()
            .zip(required.iter())
            .any(|(got, want)| got.component != *want)
    {
        return Err(VerifyError::InvalidSignatureArity);
    }

    // Reconstruction canonique — la comparaison octet à octet avec l'entrée est le contrôle de
    // canonicité (attrape clés dupliquées, réordonnancement, échappements alternatifs).
    let unsigned = unsigned_document_from_wire(&doc);
    let mut full = unsigned.clone();
    full.insert(
        "signatures".to_string(),
        Value::Array(
            doc.signatures
                .iter()
                .map(|c| json!({"component": c.component, "key_id": c.key_id, "value": c.value}))
                .collect(),
        ),
    );
    if common::canonical_bytes(&Value::Object(full)) != bytes {
        return Err(VerifyError::NonCanonical);
    }

    // `ECDSA_P256_SHA256_FIXED::verify` hache `message` en interne (SHA-256) avant de vérifier —
    // c'est le message complet qu'il attend, pas un condensé pré-calculé. `zs-hsm::sign_digest`
    // signe le condensé (`sha256(message)`) directement, sans re-hachage côté jeton (mécanisme
    // CKM_ECDSA brut) : les deux chemins signent mathématiquement la même valeur, mais l'API
    // aws-lc-rs de vérification prend l'entrée non hachée, jamais le condensé lui-même.
    let message = signed_message(&unsigned);

    let mut all_valid = true;
    for component in &doc.signatures {
        let key = keys
            .iter()
            .find(|k| k.key_id == component.key_id)
            .ok_or(VerifyError::UnknownKeyId)?;
        let sig_bytes =
            common::hex_decode(&component.value).ok_or(VerifyError::InvalidSignature)?;
        let verifying_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &key.raw);
        all_valid &= verifying_key.verify(&message, &sig_bytes).is_ok();
    }
    if !all_valid {
        return Err(VerifyError::InvalidSignature);
    }

    if doc.authority_domain != policy.expected_authority_domain {
        return Err(VerifyError::UnexpectedAuthorityDomain);
    }
    let now = policy.now.as_str();
    if !(doc.issued_at.as_str() <= now && now < doc.expires_at.as_str()) {
        return Err(VerifyError::NotYetValidOrExpired);
    }

    Ok(VerifiedAssertion {
        subject_id: doc.subject_id,
        aal: doc.aal,
        auth_method: doc.auth_method,
        audience: doc.audience,
        issued_at: doc.issued_at,
        expires_at: doc.expires_at,
        audit_event_id: doc.audit_event_id,
    })
}

fn required_components(suite: &str) -> Result<&'static [&'static str], VerifyError> {
    match suite {
        SUITE_V1 => Ok(REQUIRED_COMPONENTS_V1),
        _ => Err(VerifyError::UnknownSuite),
    }
}

fn unsigned_document(claims: &AssertionClaims) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("schema_version".to_string(), json!(1));
    map.insert("suite".to_string(), json!(SUITE_V1));
    map.insert(
        "authority_domain".to_string(),
        json!(claims.authority_domain),
    );
    map.insert("subject_id".to_string(), json!(claims.subject_id.as_str()));
    map.insert("aal".to_string(), json!(claims.aal.as_str()));
    map.insert(
        "auth_method".to_string(),
        json!(claims.auth_method.as_str()),
    );
    map.insert("audience".to_string(), json!(claims.audience.as_str()));
    map.insert("issued_at".to_string(), json!(claims.issued_at.as_str()));
    map.insert("expires_at".to_string(), json!(claims.expires_at.as_str()));
    map.insert(
        "audit_event_id".to_string(),
        json!(claims.audit_event_id.as_str()),
    );
    map
}

fn unsigned_document_from_wire(doc: &WireDocument) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("schema_version".to_string(), json!(doc.schema_version));
    map.insert("suite".to_string(), json!(doc.suite));
    map.insert("authority_domain".to_string(), json!(doc.authority_domain));
    map.insert("subject_id".to_string(), json!(doc.subject_id));
    map.insert("aal".to_string(), json!(doc.aal));
    map.insert("auth_method".to_string(), json!(doc.auth_method));
    map.insert("audience".to_string(), json!(doc.audience));
    map.insert("issued_at".to_string(), json!(doc.issued_at));
    map.insert("expires_at".to_string(), json!(doc.expires_at));
    map.insert("audit_event_id".to_string(), json!(doc.audit_event_id));
    map
}

/// `m = préfixe de domaine || 0x00 || jcs(document sans "signatures")`.
fn signed_message(unsigned: &Map<String, Value>) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN_PREFIX.len() + 1 + 256);
    message.extend_from_slice(DOMAIN_PREFIX.as_bytes());
    message.push(0x00);
    message.extend_from_slice(&common::canonical_bytes(&Value::Object(unsigned.clone())));
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature as P256Signature, SigningKey};

    /// Signeur de test indépendant d'`aws-lc-rs` (RustCrypto `p256`) — légitime uniquement en
    /// test (ADR-011/012) : `AssertionSealer` réel n'appelle jamais que `zs-hsm`.
    struct MockSigner {
        signing_key: SigningKey,
    }

    impl MockSigner {
        fn new() -> Self {
            Self {
                signing_key: SigningKey::from_bytes(&[0x11u8; 32].into()).unwrap(),
            }
        }

        fn public_key_sec1(&self) -> Vec<u8> {
            self.signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
        }

        fn key_id(&self) -> String {
            common::key_id_from_public_key(&self.public_key_sec1())
        }

        fn sign_document(&self, unsigned: &Map<String, Value>) -> Vec<u8> {
            let message = signed_message(unsigned);
            let digest = common::sha256(&message);
            let sig: P256Signature = self.signing_key.sign_prehash(&digest).unwrap();
            sig.to_bytes().to_vec()
        }
    }

    fn sample_claims(subject: &str) -> AssertionClaims {
        AssertionClaims {
            authority_domain: "identity-provider".to_string(),
            subject_id: SubjectId::new(subject).unwrap(),
            aal: AssuranceLevel::Aal2,
            auth_method: AuthMethod::new("webauthn/device-bound").unwrap(),
            audience: Audience::new("policy-engine").unwrap(),
            issued_at: Timestamp::new("2026-08-23T10:00:00Z").unwrap(),
            expires_at: Timestamp::new("2026-08-23T10:02:00Z").unwrap(),
            audit_event_id: EventId::new("0198e6c1-0000-7000-8000-000000000000").unwrap(),
        }
    }

    fn seal_with_mock(signer: &MockSigner, claims: AssertionClaims) -> SealedAssertion {
        let unsigned = unsigned_document(&claims);
        let sig = signer.sign_document(&unsigned);
        let mut document = unsigned;
        document.insert(
            "signatures".to_string(),
            Value::Array(vec![json!({
                "component": "ecdsa-p256",
                "key_id": signer.key_id(),
                "value": common::hex_encode(&sig),
            })]),
        );
        SealedAssertion {
            bytes: common::canonical_bytes(&Value::Object(document)),
        }
    }

    fn default_policy() -> AcceptancePolicy {
        AcceptancePolicy {
            accepted_suites: &[SUITE_V1],
            now: Timestamp::new("2026-08-23T10:01:00Z").unwrap(),
            expected_authority_domain: "identity-provider".to_string(),
        }
    }

    // --- cas nominal -----------------------------------------------------------------------
    #[test]
    fn assertion_scellee_est_verifiee() {
        let signer = MockSigner::new();
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        let verified = verify(&[key], sealed.as_bytes(), &default_policy()).unwrap();
        assert_eq!(verified.subject_id(), "subject-1");
        assert_eq!(verified.aal(), "AAL2");
        assert_eq!(verified.audience(), "policy-engine");
    }

    #[test]
    fn digest_correspond_au_sha256_des_octets_scelles() {
        let signer = MockSigner::new();
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));
        assert_eq!(sealed.digest(), common::sha256(sealed.as_bytes()));
    }

    // --- refus obligatoires ------------------------------------------------------------------
    #[test]
    fn signature_modifiee_est_refusee() {
        let signer = MockSigner::new();
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        // Flippe un caractère dans la valeur de signature spécifiquement (pas un octet
        // arbitraire en fin de document, qui tomberait dans "suite" et produirait
        // UnknownSuite au lieu du refus attendu — l'ordre canonique des clés n'est pas
        // "signatures" en dernier).
        let text = String::from_utf8(sealed.as_bytes().to_vec()).unwrap();
        let value_start = text.find("\"value\":\"").unwrap() + "\"value\":\"".len();
        let mut chars: Vec<u8> = text.into_bytes();
        chars[value_start] = if chars[value_start] == b'0' {
            b'1'
        } else {
            b'0'
        };

        assert_eq!(
            verify(&[key], &chars, &default_policy()),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn cle_publique_dune_autre_paire_est_refusee() {
        let signer = MockSigner::new();
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));
        let autre = MockSigner {
            signing_key: SigningKey::from_bytes(&[0x22u8; 32].into()).unwrap(),
        };
        // key_id volontairement forcé à celui du vrai signataire pour isoler le test sur la
        // vérification cryptographique, pas sur la résolution de clé.
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &autre.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], sealed.as_bytes(), &default_policy()),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn suite_inconnue_est_refusee() {
        let signer = MockSigner::new();
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();
        let policy = AcceptancePolicy {
            accepted_suites: &["autre-suite/v1"],
            ..default_policy()
        };
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));

        assert_eq!(
            verify(&[key], sealed.as_bytes(), &policy),
            Err(VerifyError::UnknownSuite)
        );
    }

    #[test]
    fn arite_de_signature_incorrecte_est_refusee() {
        let signer = MockSigner::new();
        let claims = sample_claims("subject-1");
        let unsigned = unsigned_document(&claims);
        let sig = signer.sign_document(&unsigned);
        let mut document = unsigned;
        // Deux composantes en v1, alors qu'une seule est exigée — simule un document v2 mal
        // formé ou une tentative de contourner l'arité imposée par la suite.
        document.insert(
            "signatures".to_string(),
            Value::Array(vec![
                json!({"component": "ecdsa-p256", "key_id": signer.key_id(), "value": common::hex_encode(&sig)}),
                json!({"component": "ml-dsa-65", "key_id": "bogus", "value": "00"}),
            ]),
        );
        let bytes = common::canonical_bytes(&Value::Object(document));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], &bytes, &default_policy()),
            Err(VerifyError::InvalidSignatureArity)
        );
    }

    #[test]
    fn signatures_vide_est_refusee() {
        let signer = MockSigner::new();
        let unsigned = unsigned_document(&sample_claims("subject-1"));
        let mut document = unsigned;
        document.insert("signatures".to_string(), Value::Array(vec![]));
        let bytes = common::canonical_bytes(&Value::Object(document));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], &bytes, &default_policy()),
            Err(VerifyError::InvalidSignatureArity)
        );
    }

    #[test]
    fn cle_dupliquee_dans_le_json_est_refusee() {
        // Deux occurrences de "subject_id" : serde refuse nativement un champ de structure vu
        // deux fois (erreur de désérialisation), avant même que le contrôle de canonicité
        // n'ait l'occasion de s'exécuter — un objet dupliqué n'atteint jamais la comparaison
        // d'octets, il échoue au parse.
        let signer = MockSigner::new();
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));
        let text = String::from_utf8(sealed.as_bytes().to_vec()).unwrap();
        let injected = text.replacen(
            "\"subject_id\":\"subject-1\"",
            "\"subject_id\":\"subject-1\",\"subject_id\":\"subject-1\"",
            1,
        );
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], injected.as_bytes(), &default_policy()),
            Err(VerifyError::MalformedDocument)
        );
    }

    #[test]
    fn espace_superflu_est_refuse_comme_non_canonique() {
        // Un espace après ':' est un JSON valide que serde parse sans broncher, mais qui ne
        // correspond plus à la reconstruction canonique (JCS n'a aucun espace superflu) — la
        // seule voie qui atteint réellement le contrôle de canonicité.
        let signer = MockSigner::new();
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));
        let text = String::from_utf8(sealed.as_bytes().to_vec()).unwrap();
        let injected = text.replacen("\"schema_version\":", "\"schema_version\": ", 1);
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], injected.as_bytes(), &default_policy()),
            Err(VerifyError::NonCanonical)
        );
    }

    #[test]
    fn champ_inconnu_est_refuse() {
        let signer = MockSigner::new();
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));
        let text = String::from_utf8(sealed.as_bytes().to_vec()).unwrap();
        let injected = text.replacen('{', "{\"unknown_field\":\"x\",", 1);
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], injected.as_bytes(), &default_policy()),
            Err(VerifyError::MalformedDocument)
        );
    }

    #[test]
    fn expiree_est_refusee() {
        let signer = MockSigner::new();
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();
        let policy = AcceptancePolicy {
            now: Timestamp::new("2026-08-23T10:03:00Z").unwrap(),
            ..default_policy()
        };

        assert_eq!(
            verify(&[key], sealed.as_bytes(), &policy),
            Err(VerifyError::NotYetValidOrExpired)
        );
    }

    #[test]
    fn domaine_dautorite_inattendu_est_refuse() {
        let signer = MockSigner::new();
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();
        let policy = AcceptancePolicy {
            expected_authority_domain: "autre-domaine".to_string(),
            ..default_policy()
        };

        assert_eq!(
            verify(&[key], sealed.as_bytes(), &policy),
            Err(VerifyError::UnexpectedAuthorityDomain)
        );
    }

    #[test]
    fn identifiant_de_cle_inconnu_est_refuse() {
        let signer = MockSigner::new();
        let sealed = seal_with_mock(&signer, sample_claims("subject-1"));
        let key =
            accept_verifying_key(SUITE_V1, "autre-key-id", &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], sealed.as_bytes(), &default_policy()),
            Err(VerifyError::UnknownKeyId)
        );
    }

    #[test]
    fn taille_excessive_est_refusee_avant_tout_parse() {
        let oversized = vec![b'a'; MAX_BYTES + 1];
        assert_eq!(
            verify(&[], &oversized, &default_policy()),
            Err(VerifyError::TooLarge)
        );
    }

    #[test]
    fn subject_id_non_ascii_est_refuse() {
        assert_eq!(
            SubjectId::new("sujet-é").unwrap_err(),
            FieldError("subject_id")
        );
    }

    #[test]
    fn timestamp_avec_offset_est_refuse() {
        assert!(Timestamp::new("2026-08-23T10:00:00+02:00").is_err());
    }

    #[test]
    fn audit_event_id_version_4_est_refuse() {
        // Version 4 (nibble '4' au lieu de '7') — UUIDv7 exigé pour l'ordre lexicographique.
        assert!(EventId::new("0198e6c1-0000-4000-8000-000000000000").is_err());
    }

    #[test]
    fn cle_publique_malformee_est_refusee() {
        assert_eq!(
            accept_verifying_key(SUITE_V1, "k", &[0u8; 10]).unwrap_err(),
            VerifyError::MalformedKey
        );
    }

    #[test]
    fn suite_inconnue_a_lacceptation_de_cle_est_refusee() {
        assert_eq!(
            accept_verifying_key("autre-suite/v1", "k", &[0x04u8; 65]).unwrap_err(),
            VerifyError::UnknownSuite
        );
    }
}
