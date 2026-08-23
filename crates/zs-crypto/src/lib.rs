//! Façade cryptographique unique du projet. Voir `crates/zs-crypto/CLAUDE.md`.
//!
//! Suites implémentées : `authenticator_proof` (ADR-006), `identity_assertion` (ADR-007/008/011,
//! scellement réel ADR-012). Le reste (`seal_audit_event`, `establish_channel`) se prépare avec
//! le sous-agent `referent-crypto` et une validation explicite avant tout code.

pub mod authenticator_proof;
pub mod identity_assertion;
