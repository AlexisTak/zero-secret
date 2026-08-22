//! Construction, chaînage et scellement des événements d'audit (`contracts/events/`,
//! backlog L1.4). **Scellement réel non implémenté** — voir ADR-010 : `audit-seal/v1` est une
//! suite d'émission soumise à l'invariant HSM de `zs-crypto` (aucune clé privée hors HSM), donc
//! bloquée tant que `crates/zs-hsm` reste un stub. Ce crate livre pour l'instant ce qui ne
//! dépend d'aucun scellement : construction du contenu métier, sérialisation canonique
//! (RFC 8785), vérification de chaîne, et les ports de stockage nécessaires — traits seuls.

mod canonical;
pub mod chain;
pub mod record;
pub mod sink;

pub use chain::{CHAIN_ROOT, ChainEntry, ChainError, hash_sealed_event, verify_chain};
pub use record::{Actor, ActorKind, AuditRecord, Context, EventType, Outcome, Target};
pub use sink::{AuditChainStore, AuditSink, record_or_fail};
