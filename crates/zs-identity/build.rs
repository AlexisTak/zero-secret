//! Génère les types Rust depuis `contracts/proto/identity/v1/assertion_verification.proto` à la
//! compilation — même patron que `crates/zs-policy/build.rs` (ADR-004) : `tonic-prost-build`
//! directement, pas `buf generate` côté Rust (incompatibilité protoc-gen-prost/protoc-gen-tonic
//! constatée sur ce poste). Code généré non committé, reproductibilité garantie par le contrat
//! figé et `Cargo.lock`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../contracts/proto/identity/v1/assertion_verification.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_prost_build::compile_protos(proto)?;
    Ok(())
}
