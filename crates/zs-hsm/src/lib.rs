//! Intégration PKCS#11 (SoftHSM2 en dev, HSM matériel en prod). Seul point d'accès au HSM,
//! **utilisé exclusivement par `crates/zs-crypto`** (ADR-010, ADR-011 — corrige une doc
//! antérieure qui mentionnait `apps/credential-issuer`, obsolète depuis la décision de faire
//! passer toute émission par la façade `zs-crypto`). Aucun autre crate n'importe `zs-hsm`
//! directement — vérifié par `tools/lib/check-webauthn-no-hsm.sh`.
//!
//! `#![allow(unsafe_code)]` : seul crate du workspace où `unsafe_code` n'est pas `forbid` (FFI
//! PKCS#11 via `cryptoki`/`cryptoki-sys`, justifié par ADR-001). L'`unsafe` reste interne à
//! `cryptoki-sys` — ce module ne contient lui-même aucun bloc `unsafe`.

mod error;
mod mechanism;
mod pool;
mod signer;

pub use error::HsmError;
pub use mechanism::SigningMechanism;
pub use pool::{HsmConfig, SessionPool};
pub use signer::{HsmSigner, KeyRef, PublicKeyDer, Signature};
