//! Façade cryptographique unique du projet. Voir `crates/zs-crypto/CLAUDE.md`.
//!
//! Aucune suite n'est encore implémentée : toute API exposée ici (`seal_audit_event`,
//! `establish_channel`, `sign_decision`, ...) se prépare avec le sous-agent `referent-crypto`
//! et une validation explicite avant tout code.
