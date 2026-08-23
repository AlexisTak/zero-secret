//! Binaire mince : charge le `Pdp` et le scelleur de décisions `decision-seal/v1` (H4) puis
//! délègue à `policy_engine::serve`. La logique du service vit dans `src/lib.rs` — voir son
//! commentaire de module pour le contexte complet.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use secrecy::SecretString;
use zs_crypto::decision_seal::{DecisionSealer, HsmSettings};
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

    // Mêmes variables d'environnement que crates/zs-hsm/tests/pkcs11_integration.rs (H1) : un
    // seul module PKCS#11 par poste, pas de convention distincte par service.
    let module_path = env_path("ZS_HSM_MODULE", "/usr/lib/softhsm/libsofthsm2.so");
    let pin = SecretString::from(
        std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234test5678".to_string()),
    );
    let key_label = std::env::var("ZS_POLICY_ENGINE_HSM_KEY_LABEL")
        .unwrap_or_else(|_| "zs-decision-seal-v1".to_string());

    let sealer = match DecisionSealer::open(HsmSettings {
        module_path,
        slot_id: None,
        pin,
        pool_size: 4,
        acquire_timeout: Duration::from_secs(5),
        key_label,
    }) {
        Ok(sealer) => sealer,
        Err(e) => {
            eprintln!("policy-engine: échec de l'ouverture du scelleur de décisions : {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(key_id = sealer.key_id(), "scelleur decision-seal/v1 ouvert");

    let addr: SocketAddr = std::env::var("ZS_POLICY_ENGINE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50061".to_string())
        .parse()
        .expect("ZS_POLICY_ENGINE_ADDR invalide");

    tracing::info!(%addr, "policy-engine en écoute");
    if let Err(e) = policy_engine::serve(addr, pdp, sealer).await {
        eprintln!("policy-engine: erreur serveur : {e}");
        std::process::exit(1);
    }
}
