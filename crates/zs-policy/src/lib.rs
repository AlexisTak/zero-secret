//! Types et évaluation partagés du PDP (`apps/policy-engine`). Sans état, sans appel réseau
//! pendant l'évaluation — voir `docs/architecture.md`. Évaluation Cedar réelle : `pdp` (L2.2,
//! ADR-015).

pub mod pdp;

pub mod policy {
    pub mod v1 {
        #![allow(clippy::all)]
        include!(concat!(env!("OUT_DIR"), "/policy.v1.rs"));
    }
}
