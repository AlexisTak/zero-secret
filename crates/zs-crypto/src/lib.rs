//! Façade cryptographique unique du projet. Voir `crates/zs-crypto/CLAUDE.md`.
//!
//! Suites implémentées : `authenticator_proof` (ADR-006), `identity_assertion` (ADR-007/008/011,
//! scellement réel ADR-012), `audit_seal` (ADR-010/011, scellement réel ADR-013),
//! `decision_binding` (ADR-015 — empreintes d'intégrité, pas une suite de signature). Le reste
//! (`establish_channel`) se prépare avec le sous-agent `referent-crypto` et une validation
//! explicite avant tout code.

pub mod audit_seal;
pub mod authenticator_proof;
mod common;
pub mod decision_binding;
pub mod identity_assertion;
