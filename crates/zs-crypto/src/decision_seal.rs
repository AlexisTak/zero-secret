//! Suite `decision-seal/v1` (H4, ADR-019) — authentifie l'origine d'une `DecisionResponse`
//! (`policy-engine`, L2.2) pour `credential-issuer` (L2.4), qui ne peut pas vérifier lui-même
//! (ADR-001 : frontière Rust/Go réseau, jamais FFI). `decision_hash` (`decision_binding`,
//! ADR-015) lie une décision à sa requête et à son corpus, mais ne prouve pas à lui seul
//! l'origine PDP ni ne lie `effect`/`reasons`/`max_ttl`/`constraints` — c'est le rôle de cette
//! suite.
//!
//! Émetteur : soumis pleinement aux invariants 5 (hybridation stricte) et 7 (clé privée jamais
//! hors HSM). Clé HSM dédiée `zs-decision-seal-v1`, troisième clé séparée après
//! `zs-identity-assertion-v1`/`zs-audit-seal-v1` (ADR-011 : jamais de réutilisation entre suites).
//!
//! **`DecisionResponse` est un message protobuf, pas un blob JSON opaque** (contrairement à
//! `identity_assertion`/`audit_seal`, où le document transmis EST les octets signés, reconstruits
//! depuis une entrée non fiable) : signataire et vérificateur reçoivent tous deux des champs déjà
//! typés (décodés par `prost`/`tonic`) — la canonicalisation JCS n'est ici qu'un détail de calcul
//! interne du message signé, pas une défense contre un document JSON forgé. Aucune surface
//! `NonCanonical`/`MalformedDocument`/clé dupliquée : ce risque n'existe pas pour un message déjà
//! structuré par le décodage protobuf.
//!
//! Portée du scellement (`referent-crypto`) : `request_id`, `decision_hash`, `policy_version`,
//! `effect`, `reasons`, `max_ttl`, `constraints`, `issued_at` — **jamais** `decision_hash` signé
//! isolément (il ne lie que requête + corpus ; un `effect` substitué sous un `decision_hash`
//! valide serait sinon indétectable).
//!
//! Règle absolue #5 (`CLAUDE.md` racine, « aucun appel réseau pendant l'évaluation ») porte sur
//! les **entrées** de la décision — `Pdp::decide` (`zs-policy`) reste synchrone, pur, sans HSM.
//! Le scellement est une étape postérieure et isolée, sans consultation externe pour DÉCIDER
//! (voir ADR-019 pour la discussion complète — `CLAUDE.md` non modifié).

use crate::common::{self, Timestamp};
use zs_hsm::{HsmConfig, HsmSigner, KeyRef, SessionPool, SigningMechanism};

pub const SUITE_V1: &str = "decision-seal/v1";
const DOMAIN_PREFIX: &str = "zero-secret/decision-seal/v1";

/// Contenu signé d'une décision — champs déjà typés (protobuf décodé côté appelant), jamais des
/// octets bruts à reparser. `effect_allow` plutôt qu'un type `Effect` importé : `zs-crypto` ne
/// dépend d'aucun type `zs-policy` (règle absolue #7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionFields {
    pub request_id: String,
    pub decision_hash: Vec<u8>,
    pub policy_version: String,
    pub effect_allow: bool,
    pub reasons: Vec<String>,
    pub max_ttl_seconds: u64,
    pub constraints: Vec<String>,
    pub issued_at: Timestamp,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    #[error("scellement indisponible")]
    SealingUnavailable,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("suite inconnue ou retirée")]
    UnknownSuite,
    #[error("clé publique malformée")]
    MalformedKey,
    #[error("signature ou identifiant de clé absent")]
    MissingSignature,
    #[error("identifiant de clé inconnu")]
    UnknownKeyId,
    #[error("signature invalide")]
    InvalidSignature,
}

/// Configuration HSM — mêmes champs qu'`identity_assertion::HsmSettings`/`audit_seal::HsmSettings`,
/// aucun type `zs-hsm` ne traverse la frontière publique (ADR-011).
pub struct HsmSettings {
    pub module_path: std::path::PathBuf,
    pub slot_id: Option<u64>,
    pub pin: secrecy::SecretString,
    pub pool_size: usize,
    pub acquire_timeout: std::time::Duration,
    /// `zs-decision-seal-v1` par convention (ADR-019) — distincte de
    /// `zs-identity-assertion-v1`/`zs-audit-seal-v1`.
    pub key_label: String,
}

/// Scelleur de décisions — encapsule le pool de sessions HSM et l'identifiant de clé publiée.
pub struct DecisionSealer {
    pool: SessionPool,
    key: KeyRef,
    key_id: String,
    public_key_sec1: Vec<u8>,
}

impl DecisionSealer {
    /// Ouvre le pool HSM et met en cache l'identifiant de clé. Échec dur si le HSM est
    /// indisponible au démarrage — jamais une ouverture différée (même discipline que
    /// `AssertionSealer::open`/`AuditSealer::open`).
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
        Ok(Self { pool, key, key_id, public_key_sec1: public_key.0 })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Clé de vérification correspondant à la clé de signature de ce scelleur — `policy-engine`
    /// vérifie ses propres décisions (H4/ADR-019, compromis de défense en profondeur assumé),
    /// pas de configuration de clé de vérification distincte à fournir.
    pub fn accepted_verifying_key(&self) -> Result<AcceptedVerifyingKey, VerifyError> {
        accept_verifying_key(SUITE_V1, &self.key_id, &self.public_key_sec1)
    }

    /// Scelle `fields` — digest pré-calculé, jamais réessayé (ADR-011 : ECDSA randomisé, un
    /// réessai produirait une seconde signature valide sur le même contenu). Retourne
    /// `(signature, key_id)` : l'appelant (`policy-engine`) les assigne directement aux champs
    /// `decision_signature`/`decision_signature_key_id` de `DecisionResponse`.
    pub fn seal(&self, fields: &DecisionFields) -> Result<(Vec<u8>, String), SealError> {
        let message = signed_message(fields);
        let digest = common::sha256(&message);
        let signature = self
            .pool
            .sign_digest(&self.key, SigningMechanism::EcdsaP256Sha256, &digest)
            .map_err(opaque)?;
        Ok((signature.0, self.key_id.clone()))
    }
}

fn opaque(err: zs_hsm::HsmError) -> SealError {
    tracing::warn!(hsm_error = %err, "scellement de décision indisponible");
    SealError::SealingUnavailable
}

/// Clé de vérification acceptée. Ne peut être construite que par `accept_verifying_key`.
#[derive(Debug)]
pub struct AcceptedVerifyingKey {
    key_id: String,
    raw: Vec<u8>,
}

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

/// Vérifie la signature `decision-seal/v1` de `fields`. `signature_key_id`/`signature` vides =
/// refus explicite (`MissingSignature`) — une décision non scellée n'est jamais traitée comme
/// une signature optionnelle (P2, `referent-crypto`).
pub fn verify(
    keys: &[AcceptedVerifyingKey],
    fields: &DecisionFields,
    signature_key_id: &str,
    signature: &[u8],
) -> Result<(), VerifyError> {
    if signature_key_id.is_empty() || signature.is_empty() {
        return Err(VerifyError::MissingSignature);
    }
    let key = keys
        .iter()
        .find(|k| k.key_id == signature_key_id)
        .ok_or(VerifyError::UnknownKeyId)?;

    let message = signed_message(fields);
    let verifying_key = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
        &key.raw,
    );
    verifying_key
        .verify(&message, signature)
        .map_err(|_| VerifyError::InvalidSignature)
}

/// `m = préfixe de domaine || 0x00 || jcs(objet de scellement)`. Construit un objet JSON interne
/// uniquement pour figer un ordre de sérialisation déterministe — jamais transmis tel quel (voir
/// commentaire de module).
fn signed_message(fields: &DecisionFields) -> Vec<u8> {
    let value = serde_json::json!({
        "suite": SUITE_V1,
        "request_id": fields.request_id,
        "decision_hash": common::hex_encode(&fields.decision_hash),
        "policy_version": fields.policy_version,
        "effect": if fields.effect_allow { "ALLOW" } else { "DENY" },
        "reasons": fields.reasons,
        "max_ttl_seconds": fields.max_ttl_seconds,
        "constraints": fields.constraints,
        "issued_at": fields.issued_at.as_str(),
    });

    let mut message = Vec::with_capacity(DOMAIN_PREFIX.len() + 1 + 256);
    message.extend_from_slice(DOMAIN_PREFIX.as_bytes());
    message.push(0x00);
    message.extend_from_slice(&common::canonical_bytes(&value));
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature as P256Signature, SigningKey};

    /// Signeur de test indépendant d'`aws-lc-rs` — légitime uniquement en test (ADR-011/012/019) :
    /// `DecisionSealer` réel n'appelle jamais que `zs-hsm`.
    struct MockSigner {
        signing_key: SigningKey,
    }

    impl MockSigner {
        fn new() -> Self {
            Self { signing_key: SigningKey::from_bytes(&[0x33u8; 32].into()).unwrap() }
        }

        fn public_key_sec1(&self) -> Vec<u8> {
            self.signing_key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
        }

        fn key_id(&self) -> String {
            common::key_id_from_public_key(&self.public_key_sec1())
        }

        fn sign(&self, fields: &DecisionFields) -> Vec<u8> {
            let message = signed_message(fields);
            let digest = common::sha256(&message);
            let sig: P256Signature = self.signing_key.sign_prehash(&digest).unwrap();
            sig.to_bytes().to_vec()
        }
    }

    fn sample_fields() -> DecisionFields {
        DecisionFields {
            request_id: "req-1".to_string(),
            decision_hash: vec![0xAB; 32],
            policy_version: "decision-binding/v1:abc".to_string(),
            effect_allow: true,
            reasons: vec!["db-connect-production".to_string()],
            max_ttl_seconds: 900,
            constraints: vec![],
            issued_at: Timestamp::new("2026-08-23T10:00:00Z").unwrap(),
        }
    }

    #[test]
    fn decision_scellee_est_verifiee() {
        let signer = MockSigner::new();
        let fields = sample_fields();
        let sig = signer.sign(&fields);
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert_eq!(verify(&[key], &fields, &signer.key_id(), &sig), Ok(()));
    }

    #[test]
    fn effect_substitue_sous_un_decision_hash_valide_est_refuse() {
        // Le cas exact que la construction dédiée (referent-crypto) doit empêcher : signer
        // effect=true, puis livrer effect=false avec le même decision_hash — doit être détecté.
        let signer = MockSigner::new();
        let fields = sample_fields();
        let sig = signer.sign(&fields);
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        let mut falsifie = fields;
        falsifie.effect_allow = false;

        assert_eq!(
            verify(&[key], &falsifie, &signer.key_id(), &sig),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn reasons_modifiees_sont_refusees() {
        let signer = MockSigner::new();
        let fields = sample_fields();
        let sig = signer.sign(&fields);
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        let mut falsifie = fields;
        falsifie.reasons = vec!["autre-politique".to_string()];

        assert_eq!(
            verify(&[key], &falsifie, &signer.key_id(), &sig),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn max_ttl_modifie_est_refuse() {
        let signer = MockSigner::new();
        let fields = sample_fields();
        let sig = signer.sign(&fields);
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        let mut falsifie = fields;
        falsifie.max_ttl_seconds = 999_999;

        assert_eq!(
            verify(&[key], &falsifie, &signer.key_id(), &sig),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn signature_absente_est_refusee() {
        let signer = MockSigner::new();
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], &sample_fields(), "", &[]),
            Err(VerifyError::MissingSignature)
        );
    }

    #[test]
    fn identifiant_de_cle_inconnu_est_refuse() {
        let signer = MockSigner::new();
        let fields = sample_fields();
        let sig = signer.sign(&fields);
        let key =
            accept_verifying_key(SUITE_V1, "autre-key-id", &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], &fields, &signer.key_id(), &sig),
            Err(VerifyError::UnknownKeyId)
        );
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

    #[test]
    fn cle_dune_autre_paire_est_refusee() {
        let signer = MockSigner::new();
        let fields = sample_fields();
        let sig = signer.sign(&fields);
        let autre = MockSigner { signing_key: SigningKey::from_bytes(&[0x44u8; 32].into()).unwrap() };
        let key = accept_verifying_key(SUITE_V1, &signer.key_id(), &autre.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], &fields, &signer.key_id(), &sig),
            Err(VerifyError::InvalidSignature)
        );
    }
}
