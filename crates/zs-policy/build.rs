//! Génère les types Rust depuis `contracts/proto/policy/v1/decision.proto` à la compilation.
//!
//! Pas de `buf generate` côté Rust : protoc-gen-prost + protoc-gen-tonic (invoqués séparément
//! par buf, sortie en deux fichiers reliés par include!/#[path]) produisent une erreur de
//! compilation reproductible (E0428, symbole défini plusieurs fois) sur cette combinaison de
//! versions — cause non identifiée après investigation. tonic-prost-build (ce fichier) invoque
//! protoc une seule fois et combine messages + service dans un seul fichier généré : pas de
//! problème. Voir ADR-004.
//!
//! Conséquence assumée : le code Rust généré n'est PAS committé (il l'est côté Go, voir
//! contracts/buf.gen.yaml). Reproductibilité garantie par le contrat figé et Cargo.lock, pas
//! par une inspection statique du fichier généré.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../contracts/proto/policy/v1/decision.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_prost_build::compile_protos(proto)?;
    Ok(())
}
