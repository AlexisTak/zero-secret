//! Types générés du contrat `audit.v1` (`contracts/proto/audit/v1/sealing.proto`) — pont
//! d'audit Rust<->Go. Sert `apps/audit-sealer` (serveur) ; consommé par `apps/audit-collector`
//! (Go, client) via gRPC sur socket Unix — jamais un port réseau ouvert (voir l'ADR de ce lot :
//! exposer `zs-audit-seal-v1` comme oracle de signature accessible à quiconque atteint un port
//! détruirait la non-répudiation de tout le journal).

pub mod audit {
    pub mod v1 {
        #![allow(clippy::all)]
        include!(concat!(env!("OUT_DIR"), "/audit.v1.rs"));
    }
}
