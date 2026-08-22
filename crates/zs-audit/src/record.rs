//! Contenu métier d'un événement d'audit (backlog L1.4a), avant scellement. Miroir des champs
//! non signés de `contracts/events/audit-event.schema.json` — `event_id`, `sequence`,
//! `prev_hash` et `signature` n'apparaissent pas ici : ce sont des champs de l'**événement
//! scellé**, qui n'existe pas encore (le scellement exige `zs_crypto::audit_seal`, différé à
//! L1.4b, lui-même bloqué sur l'intégration HSM réelle — voir ADR-010).
//!
//! **Ne dérive volontairement aucune sérialisation.** Un `AuditRecord` sérialisable ressemblerait
//! à un événement d'audit sans en être un (il lui manque la signature et le chaînage qui font sa
//! valeur probante) — même piège que l'assertion non signée refusée en L1.2b. La canonicalisation
//! (`crate::canonical`) reste `pub(crate)` : seul du code de ce crate peut la produire, jamais un
//! appelant externe.

/// Types d'événements couverts par le parcours WebAuthn déjà livré (L1.1/L1.2/L1.3). Sous-ensemble
/// de l'énumération `event_type` du contrat — les types relatifs aux lots ultérieurs (`access.*`,
/// `policy.*`, `credential.*`) seront ajoutés avec les lots qui les produisent, pas par avance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    AuthenticatorRegistered,
    AuthenticatorRevoked,
    AuthenticationAttempted,
    AuthenticationSucceeded,
    AuthenticationFailed,
    RecoveryInitiated,
    QuorumOperation,
}

impl EventType {
    /// Valeur exacte du contrat (`contracts/events/audit-event.schema.json`, propriété
    /// `event_type`) — un seul point de vérité pour cette correspondance, jamais recopiée
    /// ailleurs sous peine de divergence silencieuse.
    pub fn as_contract_str(self) -> &'static str {
        match self {
            EventType::AuthenticatorRegistered => "authenticator.registered",
            EventType::AuthenticatorRevoked => "authenticator.revoked",
            EventType::AuthenticationAttempted => "authentication.attempted",
            EventType::AuthenticationSucceeded => "authentication.succeeded",
            EventType::AuthenticationFailed => "authentication.failed",
            EventType::RecoveryInitiated => "recovery.initiated",
            EventType::QuorumOperation => "quorum.operation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    Human,
    Workload,
    System,
}

impl ActorKind {
    pub fn as_contract_str(self) -> &'static str {
        match self {
            ActorKind::Human => "human",
            ActorKind::Workload => "workload",
            ActorKind::System => "system",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub subject_id: String,
    pub kind: ActorKind,
    /// AAL atteint, si applicable (`authentication.succeeded`, notamment) — chaîne `"AAL1"`,
    /// `"AAL2"` ou `"AAL3"` comme le contrat, pas un type `Aal` réexporté depuis
    /// `zs_webauthn` : ce crate ne dépend pas de `zs-webauthn` (aucune raison de le faire),
    /// l'appelant fait la conversion.
    pub aal: Option<&'static str>,
    pub auth_method: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Denied,
    Error,
}

impl Outcome {
    pub fn as_contract_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Denied => "denied",
            Outcome::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Target {
    pub target_type: String,
    pub id: String,
}

#[derive(Debug, Clone, Default)]
pub struct Context {
    pub source_network: Option<String>,
    pub ticket_ref: Option<String>,
    pub justification: Option<String>,
}

/// Contenu métier d'un événement, avant scellement. `occurred_at` et `authority_domain` sont
/// fournis par l'appelant (pas de dépendance à une horloge système ni à une configuration ici) —
/// même style que `expected_challenge` dans `zs-webauthn` : ce crate ne consulte aucun état
/// ambiant.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub occurred_at: String,
    pub authority_domain: String,
    pub event_type: EventType,
    pub actor: Actor,
    pub target: Option<Target>,
    pub outcome: Outcome,
    pub context: Option<Context>,
}
