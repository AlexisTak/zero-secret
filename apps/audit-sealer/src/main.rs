//! Binaire mince : ouvre le scelleur d'audit (`zs_crypto::audit_seal::AuditSealer`, HSM) puis
//! sert `AuditSealingService` sur un socket Unix — jamais un port réseau (voir `src/lib.rs`
//! pour le contexte complet et la justification).
//!
//! Cible de déploiement Unix uniquement (`tokio::net::UnixListener` n'existe que sous ce cfg,
//! pas une limitation de fonctionnalité Cargo). La logique réelle est isolée dans le module
//! `unix_main`, gardé par `#[cfg(unix)]`, pour que `cargo build --workspace` reste utilisable sur
//! un poste de développement Windows — seul ce binaire refuse alors de démarrer, le reste du
//! workspace compile normalement. À vérifier en CI Linux, non exécutable sur cette plateforme.

#[cfg(unix)]
mod unix_main {
    use std::path::PathBuf;
    use std::time::Duration;

    use secrecy::SecretString;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::transport::Server;

    use audit_sealer::SealerService;
    use zs_audit_sealing::audit::v1::audit_sealing_service_server::AuditSealingServiceServer;
    use zs_crypto::audit_seal::{AuditSealer, HsmSettings};

    fn require_env(var: &str) -> String {
        std::env::var(var).unwrap_or_else(|_| {
            eprintln!("audit-sealer: variable d'environnement manquante : {var}");
            std::process::exit(1);
        })
    }

    fn env_path(var: &str, default: &str) -> PathBuf {
        std::env::var(var)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(default))
    }

    pub async fn run() {
        // Mêmes variables d'environnement que crates/zs-hsm/tests/pkcs11_integration.rs (H1) :
        // un seul module PKCS#11 par poste.
        let module_path = env_path("ZS_HSM_MODULE", "/usr/lib/softhsm/libsofthsm2.so");
        // Aucun repli sur un PIN par défaut (règle absolue #1) — échec dur si absent, même
        // discipline que apps/identity-provider et apps/policy-engine (correctif PR #32).
        let pin = SecretString::from(require_env("SOFTHSM2_PIN"));
        let key_label = std::env::var("ZS_AUDIT_SEALER_HSM_KEY_LABEL")
            .unwrap_or_else(|_| "zs-audit-seal-v1".to_string());
        let socket_path = require_env("ZS_AUDIT_SEALER_SOCKET");

        let sealer = match AuditSealer::open(HsmSettings {
            module_path,
            slot_id: None,
            pin,
            pool_size: 4,
            acquire_timeout: Duration::from_secs(5),
            key_label,
        }) {
            Ok(sealer) => sealer,
            Err(e) => {
                eprintln!("audit-sealer: échec de l'ouverture du scelleur : {e}");
                std::process::exit(1);
            }
        };

        // Le socket ne doit jamais survivre à un ancien process mort — un fichier de socket
        // orphelin bloquerait le bind au redémarrage (refus par défaut, pas un contournement
        // silencieux : on supprime explicitement seulement AVANT de lier un nouveau socket).
        let _ = std::fs::remove_file(&socket_path);

        let listener = match tokio::net::UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("audit-sealer: liaison du socket {socket_path} impossible : {e}");
                std::process::exit(1);
            }
        };
        let incoming = UnixListenerStream::new(listener);

        eprintln!(
            "audit-sealer: en écoute sur le socket Unix {socket_path} — jamais un port réseau \
             (colocalisation avec audit-collector, voir l'ADR de ce lot)"
        );
        if let Err(e) = Server::builder()
            .add_service(AuditSealingServiceServer::new(SealerService::new(sealer)))
            .serve_with_incoming(incoming)
            .await
        {
            eprintln!("audit-sealer: erreur serveur : {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
mod unix_main {
    pub async fn run() {
        eprintln!(
            "audit-sealer: binaire non disponible sur cette plateforme — nécessite un socket \
             Unix (tokio::net::UnixListener), déploiement Linux uniquement."
        );
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() {
    unix_main::run().await;
}
