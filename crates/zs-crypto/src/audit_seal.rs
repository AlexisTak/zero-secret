//! Suite `audit-seal` (ADR-010, scellement réel ADR-013). Scelle un événement du journal
//! d'audit de sorte que son contenu, sa position dans la chaîne (`sequence`) et le lien vers son
//! prédécesseur (`prev_hash`) soient tous couverts par une même signature — même primitive
//! ECDSA P-256/SHA-256 qu'`identity_assertion`, **clé HSM distincte** (ADR-011, deux clés dès H1) :
//! compromettre celle-ci permettrait de réécrire l'historique complet du système, ce qui en fait
//! la suite la plus contrainte du projet (voir ADR-010).
//!
//! **Forme différente d'`identity_assertion` par construction du contrat** :
//! `contracts/events/audit-event.schema.json::signature` est un objet singulier
//! `{ suite, components: [...] }`, pas un tableau `signatures: [...]` au premier niveau —
//! `contracts/` fait foi (règle absolue #8 du `CLAUDE.md` racine). La suite qui lie
//! cryptographiquement le message n'est donc pas un champ signé de premier niveau : c'est le
//! préfixe de séparation de domaine, dérivé de `signature.suite` **après** l'avoir confrontée à
//! `accepted_suites`, qui joue ce rôle — un relabel `v1`↔`v2` change le message signé et invalide
//! la signature. Cette divergence de forme avec `identity_assertion` est assumée et datée pour
//! résorption au passage `v2` (ADR-013), pas un oubli.
//!
//! **Champ `decision` (ADR-027)** : porte `policy.decided` — extension additive du contrat v1
//! (déjà déclaré dans `contracts/events/audit-event.schema.json`, `zs-crypto` n'en implémentait
//! qu'un sous-ensemble). Couplage bidirectionnel obligatoire avec `EventType` :
//! `PolicyDecided` exige `decision`, tout autre type l'interdit
//! (`EventType::requires_decision`, vérifié en émission ET en vérification). `credential.issued`
//! (même forme de `decision`) reste hors périmètre — aucun producteur ne l'émet encore, pas
//! d'anticipation.
//!
//! `decision.decision_signature`/`decision_signature_key_id` sont transportés tels quels, JAMAIS
//! vérifiés par ce module : `audit-seal/v1` atteste que le domaine d'autorité a *détenu* ce
//! `decision_hash`, pas qu'il vient réellement du PDP. Établir l'origine PDP exige une
//! vérification indépendante de `decision-seal/v1` (clé distincte, hors du périmètre de ce
//! module) par un vérificateur hors ligne qui n'existe pas encore dans ce dépôt — limite
//! documentée explicitement (ADR-027, `security/threat-models/audit-sealer.md`).

use crate::common::{self, FieldError, bounded_ascii_string};
pub use crate::common::{EventId, RequestId, Timestamp};
use crate::identity_assertion::{AssuranceLevel, AuthMethod, SubjectId};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use zs_hsm::{HsmConfig, HsmSigner, KeyRef, SessionPool, SigningMechanism};

pub const SUITE_V1: &str = "audit-seal/v1";
const DOMAIN_PREFIX_V1: &str = "zero-secret/audit-seal/v1";
const MAX_BYTES: usize = 8192;
const REQUIRED_COMPONENTS_V1: &[&str] = &["ecdsa-p256"];
/// Plafond de `decision.reasons` — premier champ de cardinalité variable du document signé
/// (ADR-027). Sans borne, un événement peut être scellé, chaîné, persisté, puis refusé en
/// vérification (`MAX_BYTES` dépassé) : une rupture de chaîne définitive, pas un refus par
/// défaut sain. Vérifié en émission (`seal`) ET en vérification (`verify`).
const MAX_REASONS: usize = 16;

bounded_ascii_string!(AuthorityDomain, 128, "authority_domain");
bounded_ascii_string!(ShortText, 256, "text");
bounded_ascii_string!(Justification, 512, "context.justification");
bounded_ascii_string!(PolicyVersion, 256, "decision.policy_version");
bounded_ascii_string!(Reason, 256, "decision.reasons");

/// Séquence d'un événement dans la chaîne de son domaine d'autorité. Bornée à 2^53−1 : au-delà,
/// la canonicalisation numérique ECMAScript (RFC 8785) perd la précision qu'un vérificateur
/// JS/Go réimplémenterait — le journal doit rester vérifiable par un tiers avec ses propres
/// outils (mise en garde `referent-crypto`), pas seulement par ce crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sequence(u64);

const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;

impl Sequence {
    pub fn new(value: u64) -> Result<Self, FieldError> {
        if value > MAX_SAFE_INTEGER {
            return Err(FieldError("sequence"));
        }
        Ok(Self(value))
    }

    pub fn value(self) -> u64 {
        self.0
    }
}

/// Types d'événements couverts par le parcours WebAuthn (L1.1-L1.3) et le chaînage lui-même.
/// Sous-ensemble de `event_type` du contrat, miroir de `zs_audit::record::EventType` — la
/// duplication entre les deux crates est le prix de la frontière (`zs-crypto` ne dépend
/// d'aucun crate applicatif, `tools/lib/check-zs-crypto-deps.sh`), pas un oubli de partage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    AuthenticatorRegistered,
    AuthenticatorRevoked,
    AuthenticationAttempted,
    AuthenticationSucceeded,
    AuthenticationFailed,
    RecoveryInitiated,
    QuorumOperation,
    /// Ancrage périodique (contrat, déjà réservé). Livré ici comme type scellable ordinaire
    /// uniquement : la charge utile probante d'un ancrage (plage de séquences couverte,
    /// empreinte de tête, point de publication externe) n'existe dans aucun champ du contrat
    /// actuel — à instruire par un ADR dédié à l'ouverture d'`audit-collector`, pas improvisée
    /// ici sous forme de `target.id` composite.
    AuditChainVerified,
    /// Décision du PDP (`policy-engine`, ADR-015/ADR-019), ALLOW ou DENY — `outcome` distingue
    /// les deux (`success`/`denied`), `decision` (requis, voir `requires_decision`) porte la
    /// preuve rejouable hors ligne (ADR-027).
    PolicyDecided,
}

impl EventType {
    fn as_contract_str(self) -> &'static str {
        match self {
            EventType::AuthenticatorRegistered => "authenticator.registered",
            EventType::AuthenticatorRevoked => "authenticator.revoked",
            EventType::AuthenticationAttempted => "authentication.attempted",
            EventType::AuthenticationSucceeded => "authentication.succeeded",
            EventType::AuthenticationFailed => "authentication.failed",
            EventType::RecoveryInitiated => "recovery.initiated",
            EventType::QuorumOperation => "quorum.operation",
            EventType::AuditChainVerified => "audit.chain_verified",
            EventType::PolicyDecided => "policy.decided",
        }
    }

    fn from_contract_str(s: &str) -> Option<Self> {
        Some(match s {
            "authenticator.registered" => EventType::AuthenticatorRegistered,
            "authenticator.revoked" => EventType::AuthenticatorRevoked,
            "authentication.attempted" => EventType::AuthenticationAttempted,
            "authentication.succeeded" => EventType::AuthenticationSucceeded,
            "authentication.failed" => EventType::AuthenticationFailed,
            "recovery.initiated" => EventType::RecoveryInitiated,
            "quorum.operation" => EventType::QuorumOperation,
            "audit.chain_verified" => EventType::AuditChainVerified,
            "policy.decided" => EventType::PolicyDecided,
            _ => return None,
        })
    }

    /// Le contrat impose `decision` sur `policy.decided` et l'interdit sur tout autre type —
    /// JSON Schema seul ne peut pas exprimer ce couplage conditionnel (`additionalProperties`
    /// ne dépend pas d'un autre champ), donc porté ici et vérifié dans les deux sens (`seal`,
    /// `verify`) — ADR-027.
    fn requires_decision(self) -> bool {
        matches!(self, EventType::PolicyDecided)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    Human,
    Workload,
    System,
}

impl ActorKind {
    fn as_contract_str(self) -> &'static str {
        match self {
            ActorKind::Human => "human",
            ActorKind::Workload => "workload",
            ActorKind::System => "system",
        }
    }

    fn from_contract_str(s: &str) -> Option<Self> {
        Some(match s {
            "human" => ActorKind::Human,
            "workload" => ActorKind::Workload,
            "system" => ActorKind::System,
            _ => return None,
        })
    }
}

pub struct Actor {
    pub subject_id: SubjectId,
    pub kind: ActorKind,
    pub aal: Option<AssuranceLevel>,
    pub auth_method: Option<AuthMethod>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Denied,
    Error,
}

impl Outcome {
    fn as_contract_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Denied => "denied",
            Outcome::Error => "error",
        }
    }

    fn from_contract_str(s: &str) -> Option<Self> {
        Some(match s {
            "success" => Outcome::Success,
            "denied" => Outcome::Denied,
            "error" => Outcome::Error,
            _ => return None,
        })
    }
}

pub struct Target {
    pub target_type: ShortText,
    pub id: ShortText,
}

#[derive(Default)]
pub struct Context {
    pub source_network: Option<ShortText>,
    pub ticket_ref: Option<ShortText>,
    pub justification: Option<Justification>,
}

/// Preuve rejouable hors ligne d'une décision du PDP — requis si et seulement si
/// `event_type == PolicyDecided` (`EventType::requires_decision`, ADR-027).
///
/// `decision_signature`/`decision_signature_key_id` sont recopiés de `decision-seal/v1`
/// (`policyv1.DecisionResponse`) mais **non vérifiés ici** : `audit-seal/v1` atteste que le
/// domaine d'autorité a détenu ce `decision_hash`, pas qu'il vient réellement du PDP — voir la
/// mise en garde en tête de module.
pub struct DecisionInfo {
    pub request_id: RequestId,
    pub decision_hash: [u8; 32],
    pub policy_version: PolicyVersion,
    pub reasons: Vec<Reason>,
    pub granted_ttl_seconds: Option<u32>,
    pub decision_signature: Option<Vec<u8>>,
    pub decision_signature_key_id: Option<ShortText>,
}

/// Contenu complet d'un événement à sceller — `event_id`/`sequence`/`prev_hash` sont fournis par
/// l'appelant (`zs-audit`, via son `AuditChainStore`), ce module ne consulte aucune horloge ni
/// n'alloue de séquence lui-même (déterminisme, testabilité, même principe que
/// `identity_assertion::AssertionClaims`).
pub struct AuditEventFields {
    pub event_id: EventId,
    pub sequence: Sequence,
    pub prev_hash: [u8; 32],
    pub occurred_at: Timestamp,
    pub authority_domain: AuthorityDomain,
    pub event_type: EventType,
    pub actor: Actor,
    pub target: Option<Target>,
    pub outcome: Outcome,
    pub context: Option<Context>,
    pub decision: Option<DecisionInfo>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    #[error("contenu d'événement invalide : champ '{0}'")]
    InvalidFields(&'static str),
    #[error("scellement indisponible")]
    SealingUnavailable,
}

impl From<FieldError> for SealError {
    fn from(e: FieldError) -> Self {
        SealError::InvalidFields(e.0)
    }
}

/// Configuration HSM — recopiée vers `zs_hsm::HsmConfig`, aucun type `zs-hsm` ne traverse la
/// frontière publique (ADR-011).
pub struct HsmSettings {
    pub module_path: std::path::PathBuf,
    pub slot_id: Option<u64>,
    pub pin: secrecy::SecretString,
    pub pool_size: usize,
    pub acquire_timeout: std::time::Duration,
    /// `zs-audit-seal-v1` par convention (ADR-013) — distincte de la clé `identity-assertion`
    /// (ADR-011, deux clés séparées dès H1). La version est dans le label : `audit-seal/v2`
    /// sera une clé neuve, jamais la même clé réutilisée sous deux suites.
    pub key_label: String,
}

/// Scelleur d'événements — encapsule le pool de sessions HSM et la clé de vérification mise en
/// cache au démarrage.
pub struct AuditSealer {
    pool: SessionPool,
    key: KeyRef,
    key_id: String,
}

impl AuditSealer {
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

    /// Scelle `fields` — jamais réessayé sur échec HSM (ADR-011 : ECDSA randomisé, un réessai
    /// produirait une seconde signature valide sur le même contenu, risque de fourche de chaîne
    /// puisque `prev_hash` du prochain événement couvre la signature de celui-ci).
    pub fn seal(&self, fields: AuditEventFields) -> Result<SealedAuditEvent, SealError> {
        validate_decision_coupling(fields.event_type, &fields.decision)?;

        let unsigned = unsigned_document(&fields);
        validate_size(&unsigned, &self.key_id)?;

        let message = signed_message(DOMAIN_PREFIX_V1, &unsigned);
        let digest = common::sha256(&message);

        let signature = self
            .pool
            .sign_digest(&self.key, SigningMechanism::EcdsaP256Sha256, &digest)
            .map_err(opaque)?;

        let mut document = unsigned;
        document.insert(
            "signature".to_string(),
            json!({
                "suite": SUITE_V1,
                "components": [{
                    "component": REQUIRED_COMPONENTS_V1[0],
                    "key_id": self.key_id,
                    "value": common::hex_encode(&signature.0),
                }],
            }),
        );

        Ok(SealedAuditEvent {
            bytes: common::canonical_bytes(&Value::Object(document)),
        })
    }
}

fn opaque(err: zs_hsm::HsmError) -> SealError {
    tracing::warn!(hsm_error = %err, "scellement d'événement d'audit indisponible");
    SealError::SealingUnavailable
}

/// Événement scellé. Aucun `Serialize` dérivé, aucun constructeur public depuis des octets bruts
/// — même garde-fou qu'`identity_assertion::SealedAssertion` : un objet qui a la forme d'un
/// événement d'audit sans preuve de scellement réel serait une trace forgeable par construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAuditEvent {
    bytes: Vec<u8>,
}

impl SealedAuditEvent {
    /// Octets canoniques complets — c'est ce que `zs_audit::chain::ChainEntry::sealed_bytes`
    /// attend : `verify_chain` en hache le contenu (signature incluse) pour former le
    /// `prev_hash` de l'événement suivant.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn suite(&self) -> &'static str {
        SUITE_V1
    }
}

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
    #[error("événement dépasse la taille maximale acceptée")]
    TooLarge,
    #[error("événement n'est pas un JSON valide ou un champ requis manque")]
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

pub struct AcceptancePolicy {
    pub accepted_suites: &'static [&'static str],
    pub expected_authority_domain: String,
}

/// Événement vérifié. Aucun constructeur public — impossible d'obtenir cette valeur sans être
/// passé par `verify`.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedAuditEvent {
    pub event_id: String,
    pub sequence: u64,
    pub prev_hash: [u8; 32],
    pub occurred_at: String,
    pub authority_domain: String,
    pub event_type: EventType,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDocument {
    schema_version: u32,
    event_id: String,
    sequence: u64,
    occurred_at: String,
    authority_domain: String,
    event_type: String,
    actor: WireActor,
    #[serde(default)]
    target: Option<WireTarget>,
    outcome: String,
    #[serde(default)]
    context: Option<WireContext>,
    #[serde(default)]
    decision: Option<WireDecision>,
    prev_hash: String,
    signature: WireSignature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireActor {
    subject_id: String,
    kind: String,
    #[serde(default)]
    aal: Option<String>,
    #[serde(default)]
    auth_method: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTarget {
    #[serde(rename = "type")]
    target_type: String,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireContext {
    #[serde(default)]
    source_network: Option<String>,
    #[serde(default)]
    ticket_ref: Option<String>,
    #[serde(default)]
    justification: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDecision {
    request_id: String,
    decision_hash: String,
    policy_version: String,
    reasons: Vec<String>,
    #[serde(default)]
    granted_ttl_seconds: Option<u64>,
    #[serde(default)]
    decision_signature: Option<String>,
    #[serde(default)]
    decision_signature_key_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSignature {
    suite: String,
    components: Vec<WireSignatureComponent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSignatureComponent {
    component: String,
    key_id: String,
    value: String,
}

/// Vérifie un événement scellé. Même ordre non négociable qu'`identity_assertion::verify` :
/// borne de taille, parse strict, canonicité par re-sérialisation, suite et arité de signature,
/// résolution de clé, vérification sans court-circuit, puis contexte (domaine d'autorité).
///
/// **N'atteste pas la position dans la chaîne** : `sequence`/`prev_hash` sont retournés à
/// l'appelant (`zs_audit::chain::verify_chain`) qui seul sait s'ils sont cohérents avec les
/// événements voisins — la vérification de signature et la vérification de chaîne sont deux
/// contrôles indépendants, la première ne remplace pas la seconde (voir test
/// `deux_evenements_signature_valide_prev_hash_different_est_une_fourche_non_detectee_ici`).
pub fn verify(
    keys: &[AcceptedVerifyingKey],
    bytes: &[u8],
    policy: &AcceptancePolicy,
) -> Result<VerifiedAuditEvent, VerifyError> {
    if bytes.len() > MAX_BYTES {
        return Err(VerifyError::TooLarge);
    }

    let doc: WireDocument =
        serde_json::from_slice(bytes).map_err(|_| VerifyError::MalformedDocument)?;

    if doc.schema_version != 1 {
        return Err(VerifyError::MalformedDocument);
    }
    if !policy
        .accepted_suites
        .contains(&doc.signature.suite.as_str())
    {
        return Err(VerifyError::UnknownSuite);
    }
    let event_type =
        EventType::from_contract_str(&doc.event_type).ok_or(VerifyError::MalformedDocument)?;
    ActorKind::from_contract_str(&doc.actor.kind).ok_or(VerifyError::MalformedDocument)?;
    Outcome::from_contract_str(&doc.outcome).ok_or(VerifyError::MalformedDocument)?;
    // Couplage bidirectionnel (ADR-027) : un vérificateur hors ligne ne doit jamais obtenir un
    // `policy.decided` sans `decision`, ni un autre type avec un `decision` orphelin — quelle
    // que soit la configuration de l'émetteur qui a produit ce document.
    if event_type.requires_decision() != doc.decision.is_some() {
        return Err(VerifyError::MalformedDocument);
    }
    if let Some(d) = &doc.decision {
        if d.reasons.len() > MAX_REASONS {
            return Err(VerifyError::MalformedDocument);
        }
        let hash = common::hex_decode(&d.decision_hash).ok_or(VerifyError::MalformedDocument)?;
        if hash.len() != 32 {
            return Err(VerifyError::MalformedDocument);
        }
    }

    let required = required_components(&doc.signature.suite)?;
    if doc.signature.components.len() != required.len()
        || doc
            .signature
            .components
            .iter()
            .zip(required.iter())
            .any(|(got, want)| got.component != *want)
    {
        return Err(VerifyError::InvalidSignatureArity);
    }

    let unsigned = unsigned_document_from_wire(&doc);
    let mut full = unsigned.clone();
    full.insert(
        "signature".to_string(),
        json!({
            "suite": doc.signature.suite,
            "components": doc.signature.components.iter().map(|c| {
                json!({"component": c.component, "key_id": c.key_id, "value": c.value})
            }).collect::<Vec<_>>(),
        }),
    );
    if common::canonical_bytes(&Value::Object(full)) != bytes {
        return Err(VerifyError::NonCanonical);
    }

    let domain_prefix = domain_prefix_for(&doc.signature.suite)?;
    let message = signed_message(domain_prefix, &unsigned);

    let mut all_valid = true;
    for component in &doc.signature.components {
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

    let prev_hash_bytes =
        common::hex_decode(&doc.prev_hash).ok_or(VerifyError::MalformedDocument)?;
    let mut prev_hash = [0u8; 32];
    if prev_hash_bytes.len() != 32 {
        return Err(VerifyError::MalformedDocument);
    }
    prev_hash.copy_from_slice(&prev_hash_bytes);

    Ok(VerifiedAuditEvent {
        event_id: doc.event_id,
        sequence: doc.sequence,
        prev_hash,
        occurred_at: doc.occurred_at,
        authority_domain: doc.authority_domain,
        event_type,
    })
}

fn required_components(suite: &str) -> Result<&'static [&'static str], VerifyError> {
    match suite {
        SUITE_V1 => Ok(REQUIRED_COMPONENTS_V1),
        _ => Err(VerifyError::UnknownSuite),
    }
}

fn domain_prefix_for(suite: &str) -> Result<&'static str, VerifyError> {
    match suite {
        SUITE_V1 => Ok(DOMAIN_PREFIX_V1),
        _ => Err(VerifyError::UnknownSuite),
    }
}

/// Construit par insertion conditionnelle, pas par `json!` avec un `Option` non mappé : le
/// contrat refuse `null` pour ces propriétés (`type: string`, pas nullable) — un champ interne
/// absent doit être omis, jamais scellé en `null` (même principe que `target`/`context` au
/// niveau supérieur, bug corrigé en même temps que l'ajout de `decision`, ADR-027).
fn actor_value(actor: &Actor) -> Value {
    let mut map = Map::new();
    map.insert("subject_id".to_string(), json!(actor.subject_id.as_str()));
    map.insert("kind".to_string(), json!(actor.kind.as_contract_str()));
    if let Some(aal) = actor.aal {
        map.insert("aal".to_string(), json!(aal.as_str()));
    }
    if let Some(auth_method) = &actor.auth_method {
        map.insert("auth_method".to_string(), json!(auth_method.as_str()));
    }
    Value::Object(map)
}

fn target_value(target: &Target) -> Value {
    json!({ "type": target.target_type.as_str(), "id": target.id.as_str() })
}

/// Voir la mise en garde d'`actor_value` — même correctif.
fn context_value(context: &Context) -> Value {
    let mut map = Map::new();
    if let Some(v) = &context.source_network {
        map.insert("source_network".to_string(), json!(v.as_str()));
    }
    if let Some(v) = &context.ticket_ref {
        map.insert("ticket_ref".to_string(), json!(v.as_str()));
    }
    if let Some(v) = &context.justification {
        map.insert("justification".to_string(), json!(v.as_str()));
    }
    Value::Object(map)
}

/// Voir la mise en garde d'`actor_value` — même construction par insertion conditionnelle.
fn decision_value(decision: &DecisionInfo) -> Value {
    let mut map = Map::new();
    map.insert(
        "request_id".to_string(),
        json!(decision.request_id.as_str()),
    );
    map.insert(
        "decision_hash".to_string(),
        json!(common::hex_encode(&decision.decision_hash)),
    );
    map.insert(
        "policy_version".to_string(),
        json!(decision.policy_version.as_str()),
    );
    map.insert(
        "reasons".to_string(),
        json!(
            decision
                .reasons
                .iter()
                .map(Reason::as_str)
                .collect::<Vec<_>>()
        ),
    );
    if let Some(ttl) = decision.granted_ttl_seconds {
        map.insert("granted_ttl_seconds".to_string(), json!(ttl));
    }
    if let Some(sig) = &decision.decision_signature {
        map.insert(
            "decision_signature".to_string(),
            json!(common::hex_encode(sig)),
        );
    }
    if let Some(key_id) = &decision.decision_signature_key_id {
        map.insert(
            "decision_signature_key_id".to_string(),
            json!(key_id.as_str()),
        );
    }
    Value::Object(map)
}

/// Couplage bidirectionnel `event_type` ↔ `decision` (ADR-027) — JSON Schema seul ne peut pas
/// l'exprimer (`additionalProperties`/`required` ne dépendent pas d'un autre champ du message).
/// Appelé en émission (`AuditSealer::seal`) et en vérification (`verify`), même contrôle des deux
/// côtés : un consommateur hors ligne ne doit jamais pouvoir obtenir un événement `policy.decided`
/// dépourvu de liaison, quelle que soit la configuration de l'émetteur qui l'a produit.
fn validate_decision_coupling(
    event_type: EventType,
    decision: &Option<DecisionInfo>,
) -> Result<(), SealError> {
    if event_type.requires_decision() != decision.is_some() {
        return Err(SealError::InvalidFields("decision"));
    }
    if let Some(d) = decision
        && d.reasons.len() > MAX_REASONS
    {
        return Err(SealError::InvalidFields("decision.reasons"));
    }
    Ok(())
}

/// Garde de taille, indépendante du HSM (testable sans scelleur réel) — `verify()` refuse déjà
/// au-delà de `MAX_BYTES` ; sans ce contrôle en émission, un événement pourrait être scellé et
/// chaîné puis irrémédiablement refusé à la vérification (rupture de chaîne définitive, pas un
/// refus par défaut sain).
fn validate_size(unsigned: &Map<String, Value>, key_id: &str) -> Result<(), SealError> {
    let unsigned_len = common::canonical_bytes(&Value::Object(unsigned.clone())).len();
    if unsigned_len + signature_overhead_bytes(key_id) > MAX_BYTES {
        return Err(SealError::InvalidFields("size"));
    }
    Ok(())
}

/// Mesuré, pas estimé (mise en garde `referent-crypto`) : sérialise un conteneur de signature
/// représentatif (même `key_id` que le scelleur réel, `value` à la longueur exacte d'une
/// signature ECDSA P-256 brute r‖s — 64 octets, 128 caractères hex) et prend la longueur réelle
/// de ses octets canoniques, plutôt que de compter les caractères à la main.
fn signature_overhead_bytes(key_id: &str) -> usize {
    let placeholder = json!({
        "suite": SUITE_V1,
        "components": [{
            "component": REQUIRED_COMPONENTS_V1[0],
            "key_id": key_id,
            "value": "0".repeat(128),
        }],
    });
    // `,"signature":` + la valeur canonicalisée — c'est exactement ce que l'insertion de cette
    // clé ajoute à un objet non vide (le document non signé porte toujours au moins
    // "schema_version", jamais vide).
    1 + "\"signature\":".len() + common::canonical_bytes(&placeholder).len()
}

fn unsigned_document(fields: &AuditEventFields) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("schema_version".to_string(), json!(1));
    map.insert("event_id".to_string(), json!(fields.event_id.as_str()));
    map.insert("sequence".to_string(), json!(fields.sequence.value()));
    map.insert(
        "prev_hash".to_string(),
        json!(common::hex_encode(&fields.prev_hash)),
    );
    map.insert(
        "occurred_at".to_string(),
        json!(fields.occurred_at.as_str()),
    );
    map.insert(
        "authority_domain".to_string(),
        json!(fields.authority_domain.as_str()),
    );
    map.insert(
        "event_type".to_string(),
        json!(fields.event_type.as_contract_str()),
    );
    map.insert("actor".to_string(), actor_value(&fields.actor));
    if let Some(target) = &fields.target {
        map.insert("target".to_string(), target_value(target));
    }
    map.insert(
        "outcome".to_string(),
        json!(fields.outcome.as_contract_str()),
    );
    if let Some(context) = &fields.context {
        map.insert("context".to_string(), context_value(context));
    }
    if let Some(decision) = &fields.decision {
        map.insert("decision".to_string(), decision_value(decision));
    }
    map
}

/// Reconstruit le document non signé depuis un `WireDocument` déjà déserialisé, pour la
/// comparaison de canonicité (`verify`) — insertion conditionnelle des champs internes
/// optionnels, MÊME correctif qu'`actor_value`/`context_value`/`decision_value` : un
/// `json!({"aal": doc.actor.aal})` avec `aal: None` produirait `"aal": null` dans le document
/// reconstruit, qui ne correspondrait alors JAMAIS aux octets d'origine (qui omettent la clé) —
/// tout événement sans `aal`/`auth_method`/champ de `context` interne aurait été refusé en
/// `NonCanonical` à tort. Bug latent partagé avec le côté émission, masqué par les mêmes
/// fixtures de test qui renseignaient toujours ces champs.
fn unsigned_document_from_wire(doc: &WireDocument) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("schema_version".to_string(), json!(doc.schema_version));
    map.insert("event_id".to_string(), json!(doc.event_id));
    map.insert("sequence".to_string(), json!(doc.sequence));
    map.insert("prev_hash".to_string(), json!(doc.prev_hash));
    map.insert("occurred_at".to_string(), json!(doc.occurred_at));
    map.insert("authority_domain".to_string(), json!(doc.authority_domain));
    map.insert("event_type".to_string(), json!(doc.event_type));
    {
        let mut actor = Map::new();
        actor.insert("subject_id".to_string(), json!(doc.actor.subject_id));
        actor.insert("kind".to_string(), json!(doc.actor.kind));
        if let Some(aal) = &doc.actor.aal {
            actor.insert("aal".to_string(), json!(aal));
        }
        if let Some(auth_method) = &doc.actor.auth_method {
            actor.insert("auth_method".to_string(), json!(auth_method));
        }
        map.insert("actor".to_string(), Value::Object(actor));
    }
    if let Some(target) = &doc.target {
        map.insert(
            "target".to_string(),
            json!({"type": target.target_type, "id": target.id}),
        );
    }
    map.insert("outcome".to_string(), json!(doc.outcome));
    if let Some(context) = &doc.context {
        let mut ctx = Map::new();
        if let Some(v) = &context.source_network {
            ctx.insert("source_network".to_string(), json!(v));
        }
        if let Some(v) = &context.ticket_ref {
            ctx.insert("ticket_ref".to_string(), json!(v));
        }
        if let Some(v) = &context.justification {
            ctx.insert("justification".to_string(), json!(v));
        }
        map.insert("context".to_string(), Value::Object(ctx));
    }
    if let Some(decision) = &doc.decision {
        let mut d = Map::new();
        d.insert("request_id".to_string(), json!(decision.request_id));
        d.insert("decision_hash".to_string(), json!(decision.decision_hash));
        d.insert("policy_version".to_string(), json!(decision.policy_version));
        d.insert("reasons".to_string(), json!(decision.reasons));
        if let Some(v) = decision.granted_ttl_seconds {
            d.insert("granted_ttl_seconds".to_string(), json!(v));
        }
        if let Some(v) = &decision.decision_signature {
            d.insert("decision_signature".to_string(), json!(v));
        }
        if let Some(v) = &decision.decision_signature_key_id {
            d.insert("decision_signature_key_id".to_string(), json!(v));
        }
        map.insert("decision".to_string(), Value::Object(d));
    }
    map
}

/// `m = préfixe de domaine || 0x00 || jcs(document sans "signature")`. Le préfixe porte la
/// version de suite puisque `suite` ne vit qu'à l'intérieur de l'objet `signature`, exclu du
/// message — c'est ce qui lie cryptographiquement le document à sa version de suite (voir mise
/// en garde du module).
fn signed_message(domain_prefix: &str, unsigned: &Map<String, Value>) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain_prefix.len() + 1 + 512);
    message.extend_from_slice(domain_prefix.as_bytes());
    message.push(0x00);
    message.extend_from_slice(&common::canonical_bytes(&Value::Object(unsigned.clone())));
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature as P256Signature, SigningKey};

    /// Signeur de test indépendant d'`aws-lc-rs` — légitime uniquement en test (ADR-011/012/013).
    struct MockSigner {
        signing_key: SigningKey,
    }

    impl MockSigner {
        fn new(seed: u8) -> Self {
            Self {
                signing_key: SigningKey::from_bytes(&[seed; 32].into()).unwrap(),
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

        fn sign_document(&self, domain_prefix: &str, unsigned: &Map<String, Value>) -> Vec<u8> {
            let message = signed_message(domain_prefix, unsigned);
            let digest = common::sha256(&message);
            let sig: P256Signature = self.signing_key.sign_prehash(&digest).unwrap();
            sig.to_bytes().to_vec()
        }
    }

    fn sample_fields(sequence: u64, prev_hash: [u8; 32]) -> AuditEventFields {
        AuditEventFields {
            event_id: EventId::new("0198e6c1-0000-7000-8000-000000000000").unwrap(),
            sequence: Sequence::new(sequence).unwrap(),
            prev_hash,
            occurred_at: Timestamp::new("2026-08-23T10:00:00Z").unwrap(),
            authority_domain: AuthorityDomain::new("identity-provider").unwrap(),
            event_type: EventType::AuthenticationSucceeded,
            actor: Actor {
                subject_id: SubjectId::new("subject-1").unwrap(),
                kind: ActorKind::Human,
                aal: Some(AssuranceLevel::Aal2),
                auth_method: Some(AuthMethod::new("webauthn/device-bound").unwrap()),
            },
            target: None,
            outcome: Outcome::Success,
            context: None,
            decision: None,
        }
    }

    fn sample_decision() -> DecisionInfo {
        DecisionInfo {
            request_id: RequestId::new("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
            decision_hash: [0xCDu8; 32],
            policy_version: PolicyVersion::new("db.connect@1").unwrap(),
            reasons: vec![Reason::new("db-connect-production").unwrap()],
            granted_ttl_seconds: Some(900),
            decision_signature: Some(vec![0xEFu8; 64]),
            decision_signature_key_id: Some(ShortText::new("decision-key-1").unwrap()),
        }
    }

    fn sample_policy_decided_fields(sequence: u64, prev_hash: [u8; 32]) -> AuditEventFields {
        AuditEventFields {
            event_type: EventType::PolicyDecided,
            decision: Some(sample_decision()),
            ..sample_fields(sequence, prev_hash)
        }
    }

    fn seal_with_mock(signer: &MockSigner, fields: AuditEventFields) -> SealedAuditEvent {
        let unsigned = unsigned_document(&fields);
        let sig = signer.sign_document(DOMAIN_PREFIX_V1, &unsigned);
        let mut document = unsigned;
        document.insert(
            "signature".to_string(),
            json!({
                "suite": SUITE_V1,
                "components": [{
                    "component": "ecdsa-p256",
                    "key_id": signer.key_id(),
                    "value": common::hex_encode(&sig),
                }],
            }),
        );
        SealedAuditEvent {
            bytes: common::canonical_bytes(&Value::Object(document)),
        }
    }

    fn default_policy() -> AcceptancePolicy {
        AcceptancePolicy {
            accepted_suites: &[SUITE_V1],
            expected_authority_domain: "identity-provider".to_string(),
        }
    }

    // --- cas nominal -----------------------------------------------------------------------
    #[test]
    fn evenement_scelle_est_verifie() {
        let signer = MockSigner::new(0x11);
        let sealed = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        let verified = verify(&[key], sealed.as_bytes(), &default_policy()).unwrap();
        assert_eq!(verified.sequence, 0);
        assert_eq!(verified.event_type, EventType::AuthenticationSucceeded);
    }

    #[test]
    fn champ_optionnel_absent_nest_jamais_null() {
        // Correctif hérité de la version antérieure de zs-audit::canonical (L1.4a) : le contrat
        // refuse "target": null (type object non requis, additionalProperties: false) — un champ
        // optionnel absent doit être omis, jamais scellé en `null`.
        let signer = MockSigner::new(0x11);
        let sealed = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));
        let text = String::from_utf8(sealed.as_bytes().to_vec()).unwrap();
        assert!(!text.contains("null"));
        assert!(!text.contains("\"target\""));
        assert!(!text.contains("\"context\""));
    }

    #[test]
    fn champ_interne_optionnel_absent_nest_jamais_null_meme_objet_present() {
        // Bug préexistant corrigé avec l'ajout de `decision` (ADR-027) : actor_value/
        // context_value construisaient l'objet via json!() avec un Option non mappé — un champ
        // interne absent (aal, auth_method, source_network, ticket_ref, justification) devenait
        // "null" au lieu d'être omis, alors que actor/context restent PRÉSENTS (aal/auth_method
        // ne sont pas None dans sample_fields, mais context.source_network/ticket_ref/
        // justification le sont toujours dans ce test). Masqué jusqu'ici par des fixtures qui
        // renseignaient toujours ces champs.
        let signer = MockSigner::new(0x11);
        let mut fields = sample_fields(0, [0u8; 32]);
        fields.actor.aal = None;
        fields.actor.auth_method = None;
        fields.context = Some(Context::default());
        let sealed = seal_with_mock(&signer, fields);
        let text = String::from_utf8(sealed.as_bytes().to_vec()).unwrap();
        assert!(!text.contains("null"), "document : {text}");
        assert!(text.contains("\"context\":{}"), "document : {text}");

        // Et le document reste vérifiable — preuve que unsigned_document_from_wire reconstruit
        // exactement les mêmes octets (même correctif appliqué des deux côtés).
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();
        assert!(verify(&[key], sealed.as_bytes(), &default_policy()).is_ok());
    }

    #[test]
    fn policy_decided_avec_decision_est_scelle_et_verifie() {
        let signer = MockSigner::new(0x22);
        let sealed = seal_with_mock(&signer, sample_policy_decided_fields(0, [0u8; 32]));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        let verified = verify(&[key], sealed.as_bytes(), &default_policy()).unwrap();
        assert_eq!(verified.event_type, EventType::PolicyDecided);
    }

    #[test]
    fn policy_decided_valide_le_contrat() {
        let schema_text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/events/audit-event.schema.json"
        ))
        .unwrap();
        let schema: Value = serde_json::from_str(&schema_text).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();

        let signer = MockSigner::new(0x22);
        let sealed = seal_with_mock(&signer, sample_policy_decided_fields(0, [0u8; 32]));
        let document: Value = serde_json::from_slice(sealed.as_bytes()).unwrap();

        let errors: Vec<_> = validator.iter_errors(&document).collect();
        assert!(
            errors.is_empty(),
            "événement policy.decided non conforme au contrat : {errors:?}"
        );
    }

    // --- couplage decision <-> event_type (ADR-027) -------------------------------------------

    #[test]
    fn decision_absente_sur_policy_decided_est_refusee_au_scellement() {
        assert_eq!(
            validate_decision_coupling(EventType::PolicyDecided, &None),
            Err(SealError::InvalidFields("decision"))
        );
    }

    #[test]
    fn decision_presente_sur_type_non_policy_decided_est_refusee_au_scellement() {
        assert_eq!(
            validate_decision_coupling(
                EventType::AuthenticationSucceeded,
                &Some(sample_decision())
            ),
            Err(SealError::InvalidFields("decision"))
        );
    }

    #[test]
    fn decision_absente_sur_policy_decided_est_refusee_a_la_verification() {
        // seal_with_mock contourne volontairement validate_decision_coupling (elle construit le
        // document directement) — c'est précisément ce qui permet de prouver que verify() fait
        // AUSSI ce contrôle, indépendamment de ce que l'émetteur aurait dû refuser.
        let signer = MockSigner::new(0x11);
        let mut fields = sample_fields(0, [0u8; 32]);
        fields.event_type = EventType::PolicyDecided;
        let sealed = seal_with_mock(&signer, fields);
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], sealed.as_bytes(), &default_policy()),
            Err(VerifyError::MalformedDocument)
        );
    }

    #[test]
    fn decision_presente_sur_type_non_policy_decided_est_refusee_a_la_verification() {
        let signer = MockSigner::new(0x11);
        let mut fields = sample_fields(0, [0u8; 32]);
        fields.decision = Some(sample_decision());
        let sealed = seal_with_mock(&signer, fields);
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], sealed.as_bytes(), &default_policy()),
            Err(VerifyError::MalformedDocument)
        );
    }

    #[test]
    fn decision_hash_falsifie_est_refuse_par_la_signature() {
        let signer = MockSigner::new(0x22);
        let sealed = seal_with_mock(&signer, sample_policy_decided_fields(0, [0u8; 32]));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        let text = String::from_utf8(sealed.as_bytes().to_vec()).unwrap();
        let injected = text.replacen(&common::hex_encode(&[0xCDu8; 32]), &"0".repeat(64), 1);

        assert_eq!(
            verify(&[key], injected.as_bytes(), &default_policy()),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn request_id_non_uuid_est_refuse() {
        assert_eq!(
            RequestId::new("pas-un-uuid").unwrap_err(),
            FieldError("decision.request_id")
        );
        // Contrairement à EventId, un UUID valide non-v7 est accepté (le contrat ne l'exige pas).
        assert!(RequestId::new("f47ac10b-58cc-4372-a567-0e02b2c3d479").is_ok());
    }

    #[test]
    fn reasons_au_dela_de_max_est_refuse_au_scellement() {
        let mut decision = sample_decision();
        decision.reasons = (0..MAX_REASONS + 1)
            .map(|i| Reason::new(format!("motif-{i}")).unwrap())
            .collect();
        assert_eq!(
            validate_decision_coupling(EventType::PolicyDecided, &Some(decision)),
            Err(SealError::InvalidFields("decision.reasons"))
        );
    }

    #[test]
    fn reasons_au_dela_de_max_est_refuse_a_la_verification() {
        // Même contournement volontaire que decision_absente_sur_policy_decided_..._verification.
        let signer = MockSigner::new(0x22);
        let mut fields = sample_policy_decided_fields(0, [0u8; 32]);
        fields.decision = Some(DecisionInfo {
            reasons: (0..MAX_REASONS + 1)
                .map(|i| Reason::new(format!("motif-{i}")).unwrap())
                .collect(),
            ..sample_decision()
        });
        let sealed = seal_with_mock(&signer, fields);
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert_eq!(
            verify(&[key], sealed.as_bytes(), &default_policy()),
            Err(VerifyError::MalformedDocument)
        );
    }

    #[test]
    fn document_surdimensionne_est_refuse_au_scellement() {
        // validate_size travaille sur le Map déjà construit — pas besoin de passer par des
        // champs bornés individuellement pour prouver l'arithmétique de la garde elle-même.
        let mut unsigned = unsigned_document(&sample_fields(0, [0u8; 32]));
        unsigned.insert("__test_filler__".to_string(), json!("x".repeat(MAX_BYTES)));
        assert_eq!(
            validate_size(&unsigned, "0123456789abcdef"),
            Err(SealError::InvalidFields("size"))
        );
    }

    #[test]
    fn document_de_taille_normale_est_accepte_au_scellement() {
        let unsigned = unsigned_document(&sample_policy_decided_fields(0, [0u8; 32]));
        assert!(validate_size(&unsigned, "0123456789abcdef").is_ok());
    }

    // --- refus obligatoires ------------------------------------------------------------------
    #[test]
    fn signature_modifiee_est_refusee() {
        let signer = MockSigner::new(0x11);
        let sealed = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

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
    fn prev_hash_falsifie_est_refuse_par_la_signature() {
        // prev_hash est un champ signé : le falsifier casse la signature avant même que le
        // chaînage (zs_audit::chain, hors de ce crate) n'ait l'occasion de le vérifier.
        let signer = MockSigner::new(0x11);
        let sealed = seal_with_mock(&signer, sample_fields(1, [0xAAu8; 32]));
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        let text = String::from_utf8(sealed.as_bytes().to_vec()).unwrap();
        let injected = text.replacen(&common::hex_encode(&[0xAAu8; 32]), &"0".repeat(64), 1);

        assert_eq!(
            verify(&[key], injected.as_bytes(), &default_policy()),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn deux_evenements_signature_valide_prev_hash_different_ne_sont_distingues_que_par_le_chainage()
    {
        // Fourche : deux événements de même séquence, chacun individuellement valide en
        // signature, avec des prev_hash différents. verify() ne peut pas et ne doit pas
        // trancher seul lequel est légitime — c'est le rôle de zs_audit::chain::verify_chain
        // (écrivain unique par authority_domain), pas de ce module. Matérialise le risque exact
        // qui interdit le réessai HSM (ADR-011).
        let signer = MockSigner::new(0x11);
        let a = seal_with_mock(&signer, sample_fields(1, [0x01u8; 32]));
        let b = seal_with_mock(&signer, sample_fields(1, [0x02u8; 32]));
        let key_a =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();
        let key_b =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();

        assert!(verify(&[key_a], a.as_bytes(), &default_policy()).is_ok());
        assert!(verify(&[key_b], b.as_bytes(), &default_policy()).is_ok());
    }

    #[test]
    fn evenement_audit_est_refuse_par_identity_assertion_verify() {
        // Un événement d'audit-seal, soumis à identity_assertion::verify, doit être refusé —
        // démontre que la séparation de forme entre les deux suites fonctionne réellement
        // ("signature" objet + "suite" interne vs "signatures" tableau + "suite" au premier
        // niveau), pas seulement qu'elle est affirmée en commentaire (mise en garde
        // referent-crypto, confusion de domaine croisée).
        use crate::identity_assertion;

        let signer = MockSigner::new(0x11);
        let audit_event = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));
        let policy = identity_assertion::AcceptancePolicy {
            accepted_suites: &[identity_assertion::SUITE_V1],
            now: Timestamp::new("2026-08-23T10:01:00Z").unwrap(),
            expected_authority_domain: "identity-provider".to_string(),
        };

        assert!(identity_assertion::verify(&[], audit_event.as_bytes(), &policy).is_err());
    }

    #[test]
    fn suite_inconnue_est_refusee() {
        let signer = MockSigner::new(0x11);
        let key =
            accept_verifying_key(SUITE_V1, &signer.key_id(), &signer.public_key_sec1()).unwrap();
        let policy = AcceptancePolicy {
            accepted_suites: &["autre-suite/v1"],
            ..default_policy()
        };
        let sealed = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));

        assert_eq!(
            verify(&[key], sealed.as_bytes(), &policy),
            Err(VerifyError::UnknownSuite)
        );
    }

    #[test]
    fn arite_de_signature_incorrecte_est_refusee() {
        let signer = MockSigner::new(0x11);
        let fields = sample_fields(0, [0u8; 32]);
        let unsigned = unsigned_document(&fields);
        let sig = signer.sign_document(DOMAIN_PREFIX_V1, &unsigned);
        let mut document = unsigned;
        document.insert(
            "signature".to_string(),
            json!({
                "suite": SUITE_V1,
                "components": [
                    {"component": "ecdsa-p256", "key_id": signer.key_id(), "value": common::hex_encode(&sig)},
                    {"component": "ml-dsa-65", "key_id": "bogus", "value": "00"},
                ],
            }),
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
    fn espace_superflu_est_refuse_comme_non_canonique() {
        let signer = MockSigner::new(0x11);
        let sealed = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));
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
        let signer = MockSigner::new(0x11);
        let sealed = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));
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
    fn domaine_dautorite_inattendu_est_refuse() {
        let signer = MockSigner::new(0x11);
        let sealed = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));
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
        let signer = MockSigner::new(0x11);
        let sealed = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));
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
    fn sequence_au_dela_de_2_puissance_53_est_refusee() {
        assert_eq!(
            Sequence::new(MAX_SAFE_INTEGER + 1).unwrap_err(),
            FieldError("sequence")
        );
        assert!(Sequence::new(MAX_SAFE_INTEGER).is_ok());
    }

    #[test]
    fn cle_publique_malformee_est_refusee() {
        assert_eq!(
            accept_verifying_key(SUITE_V1, "k", &[0u8; 10]).unwrap_err(),
            VerifyError::MalformedKey
        );
    }

    // --- vecteurs de chaînage figés (ADR-013) -----------------------------------------------
    // Produits ici (seul endroit du crate avec accès aux fonctions privées de scellement),
    // consommés par crates/zs-audit/tests/chain_vectors.rs via la seule API publique
    // (audit_seal::verify + zs_audit::chain::verify_chain) — preuve d'intégration bout en bout
    // entre les deux crates, chacun testant son propre rôle.

    fn vectors_path() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/audit-seal-v1/chain.json"
        ))
    }

    /// Construit 3 événements chaînés d'un même domaine avec le signeur de test déterministe
    /// (RFC 6979) — mêmes octets à chaque exécution, ce qui est précisément ce qui rend ces
    /// vecteurs utilisables comme référence de non-régression.
    fn build_chain() -> (MockSigner, Vec<SealedAuditEvent>) {
        let signer = MockSigner::new(0x33);
        // Racine de la chaîne = 64 zéros (contrat, zs_audit::chain::CHAIN_ROOT) — pas
        // sha256(b""), qui n'est pas la racine attendue par verify_chain.
        let e0 = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));
        let h0 = common::sha256(e0.as_bytes());
        let e1 = seal_with_mock(&signer, sample_fields(1, h0));
        let h1 = common::sha256(e1.as_bytes());
        let e2 = seal_with_mock(&signer, sample_fields(2, h1));
        (signer, vec![e0, e1, e2])
    }

    /// Outil de développement, jamais exécuté en CI (`#[ignore]`, comme les tests d'intégration
    /// PKCS#11 réels) : régénère `tests/vectors/audit-seal-v1/chain.json`. À relancer seulement
    /// si le format d'`audit-seal/v1` change délibérément (avec un nouvel ADR) — sinon le fichier
    /// figé cesse de détecter une dérive de canonicalisation, ce qui est tout son intérêt.
    #[test]
    #[ignore]
    fn regenerer_les_vecteurs_de_chainage() {
        let (signer, events) = build_chain();
        let vector = json!({
            "suite": SUITE_V1,
            "public_key_sec1_hex": common::hex_encode(&signer.public_key_sec1()),
            "key_id": signer.key_id(),
            "events_hex": events.iter().map(|e| common::hex_encode(e.as_bytes())).collect::<Vec<_>>(),
        });
        let path = vectors_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
    }

    #[test]
    fn octets_scelles_valident_le_contrat() {
        // Preuve que le format produit par seal() est bien celui que le contrat décrit — pas
        // seulement celui que ce module croit produire (ADR-013).
        let schema_text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/events/audit-event.schema.json"
        ))
        .unwrap();
        let schema: Value = serde_json::from_str(&schema_text).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();

        let signer = MockSigner::new(0x11);
        let sealed = seal_with_mock(&signer, sample_fields(0, [0u8; 32]));
        let document: Value = serde_json::from_slice(sealed.as_bytes()).unwrap();

        let errors: Vec<_> = validator.iter_errors(&document).collect();
        assert!(
            errors.is_empty(),
            "événement scellé non conforme au contrat : {errors:?}"
        );
    }

    #[test]
    fn vecteurs_de_chainage_correspondent_au_fichier_fige() {
        let (_, events) = build_chain();
        let text = std::fs::read_to_string(vectors_path())
            .expect("tests/vectors/audit-seal-v1/chain.json manquant — voir regenerer_les_vecteurs_de_chainage");
        let vector: Value = serde_json::from_str(&text).unwrap();
        let expected: Vec<String> = vector["events_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let actual: Vec<String> = events
            .iter()
            .map(|e| common::hex_encode(e.as_bytes()))
            .collect();
        assert_eq!(
            actual, expected,
            "dérive de canonicalisation détectée — les octets scellés ne correspondent plus \
             au fichier figé (voir mise en garde de regenerer_les_vecteurs_de_chainage)"
        );
    }
}
