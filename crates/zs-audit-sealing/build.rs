//! Génère les types Rust depuis `contracts/proto/audit/v1/sealing.proto` à la compilation —
//! même patron que `crates/zs-identity/build.rs` (ADR-004) : `tonic-prost-build` directement,
//! pas `buf generate` côté Rust. Code généré non committé, reproductibilité garantie par le
//! contrat figé et `Cargo.lock`.
//!
//! `collection.proto` n'est PAS généré ici — il n'a aucun consommateur Rust
//! (`AuditCollectionService` est servi et appelé exclusivement côté Go).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../contracts/proto/audit/v1/sealing.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_prost_build::compile_protos(proto)?;
    Ok(())
}
