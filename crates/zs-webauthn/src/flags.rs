//! Bits de `authenticatorData.flags` (spec WebAuthn §6.1) utilisés par plusieurs cérémonies.
//! Centralisés ici pour éviter que `registration.rs` et `authentication.rs` redéfinissent les
//! mêmes constantes avec un risque de divergence silencieuse.

pub(crate) const FLAG_USER_PRESENT: u8 = 0x01;
pub(crate) const FLAG_USER_VERIFIED: u8 = 0x04;
pub(crate) const FLAG_ATTESTED_CRED_DATA: u8 = 0x40;
