//! Types générés du contrat `identity.v1` (`contracts/proto/identity/v1/assertion_verification.proto`,
//! H3). Sert `apps/identity-provider` — vérification d'assertion `identity-assertion/v1`,
//! consommée par `access-broker` (L2.3, Go) via gRPC (ADR-001 : frontière Rust/Go réseau, jamais
//! FFI).

pub mod identity {
    pub mod v1 {
        #![allow(clippy::all)]
        include!(concat!(env!("OUT_DIR"), "/identity.v1.rs"));
    }
}
