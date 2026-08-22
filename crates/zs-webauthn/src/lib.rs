//! Vérification WebAuthn/FIDO2 (RFC 8809, spec W3C). Enregistrement d'authentificateur
//! (backlog L1.1). Toute vérification de signature passe par `zs_crypto` (ADR-006) — ce crate
//! ne fait que décoder des structures (CBOR/COSE, JSON) et orchestrer la cérémonie.

pub mod client_data;
pub mod cose;
pub mod policy;
pub mod registration;

pub use policy::AttestationPolicy;
pub use registration::{
    RegistrationCeremonyInput, RegistrationError, RegistrationOutcome, verify_registration_ceremony,
};
