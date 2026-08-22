//! Types et évaluation partagés du PDP (`apps/policy-engine`). Sans état, sans appel réseau
//! pendant l'évaluation — voir `docs/architecture.md`. Évaluation non implémentée (backlog L2+).

pub mod policy {
    pub mod v1 {
        #![allow(clippy::all)]
        include!(concat!(env!("OUT_DIR"), "/policy.v1.rs"));
    }
}
