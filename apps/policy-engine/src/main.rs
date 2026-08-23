//! Binaire mince : charge le `Pdp` (chemins configurables par variable d'environnement) puis
//! délègue à `policy_engine::serve`. La logique du service vit dans `src/lib.rs` — voir son
//! commentaire de module pour le contexte complet.

use std::net::SocketAddr;
use std::path::PathBuf;

use zs_policy::pdp::Pdp;

fn env_path(var: &str, default: &str) -> PathBuf {
    std::env::var(var).map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(default))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let schema_path = env_path(
        "ZS_POLICY_ENGINE_SCHEMA",
        "contracts/cedar/schema.cedarschema.json",
    );
    let policies_dir = env_path("ZS_POLICY_ENGINE_POLICIES_DIR", "policies/access");

    let pdp = match Pdp::load(&schema_path, &policies_dir) {
        Ok(pdp) => pdp,
        Err(e) => {
            // Échec dur au démarrage si le corpus est absent ou invalide — jamais un PDP qui
            // démarre en servant des refus par accident sans que l'opérateur le sache (R2 : le
            // refus doit être délibéré, pas un symptôme de corpus manquant passé inaperçu).
            eprintln!("policy-engine: échec du chargement du PDP : {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(policy_version = %pdp.policy_version(), "PDP chargé");

    let addr: SocketAddr = std::env::var("ZS_POLICY_ENGINE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50061".to_string())
        .parse()
        .expect("ZS_POLICY_ENGINE_ADDR invalide");

    tracing::info!(%addr, "policy-engine en écoute");
    if let Err(e) = policy_engine::serve(addr, pdp).await {
        eprintln!("policy-engine: erreur serveur : {e}");
        std::process::exit(1);
    }
}
