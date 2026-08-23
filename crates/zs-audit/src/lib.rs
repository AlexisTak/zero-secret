//! Contenu métier et chaînage des événements d'audit (`contracts/events/`, backlog L1.4). Le
//! scellement réel (canonicalisation, signature) vit dans `zs_crypto::audit_seal` (L1.4b,
//! ADR-013) — ce crate ne canonicalise plus le document complet lui-même (l'ancien module
//! `canonical` construisait le contenu métier seul, sans `event_id`/`sequence`/`prev_hash`/
//! `signature` ; deux implémentations JCS dans le dépôt auraient divergé sans que rien ne le
//! détecte). `AuditRecord` reste le type de contenu métier que l'appelant convertit vers
//! `zs_crypto::audit_seal::AuditEventFields` avant de sceller.

pub mod chain;
pub mod record;
pub mod sink;

pub use chain::{CHAIN_ROOT, ChainEntry, ChainError, hash_sealed_event, verify_chain};
pub use record::{Actor, ActorKind, AuditRecord, Context, EventType, Outcome, Target};
pub use sink::{AuditChainStore, AuditSink, record_or_fail};
