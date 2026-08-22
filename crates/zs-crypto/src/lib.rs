//! Façade cryptographique unique du projet. Voir `crates/zs-crypto/CLAUDE.md`.
//!
//! Suites implémentées : `authenticator_proof` (ADR-006). Le reste (`seal_audit_event`,
//! `establish_channel`, `sign_decision`, `identity-assertion` — ADR-007) se prépare avec le
//! sous-agent `referent-crypto` et une validation explicite avant tout code.

pub mod authenticator_proof;
