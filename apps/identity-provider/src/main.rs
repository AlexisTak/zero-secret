//! Binaire : démarre les deux entrées réseau d'`identity-provider` en parallèle sur un seul
//! runtime tokio — le serveur gRPC de vérification d'assertion (H3, ADR-016, inchangé) et le
//! serveur HTTP de cérémonie WebAuthn (H5, ADR-023). Voir `src/lib.rs` pour le contexte complet.
//!
//! Échec dur au démarrage sur toute ressource manquante (HSM, base de données, clé de
//! vérification) — jamais un service qui démarre en dégradant silencieusement une garantie de
//! sécurité (R2, même discipline que `apps/policy-engine`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;

use zs_crypto::audit_seal::{AuditSealer, HsmSettings as AuditHsmSettings};
use zs_crypto::identity_assertion::{
    AssertionSealer, HsmSettings as AssertionHsmSettings, accept_verifying_key,
};

use identity_provider::httpapi::{self, AppState};
use identity_provider::store::{AuditStore, IdentityStore};

fn require_env(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| {
        eprintln!("identity-provider: variable d'environnement manquante : {var}");
        std::process::exit(1);
    })
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

fn env_i64_or(var: &str, default: i64) -> i64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn main() {
    let key_hex = require_env("ZS_IDP_VERIFYING_KEY_HEX");
    let key_id = require_env("ZS_IDP_VERIFYING_KEY_ID");
    let raw = hex_decode(&key_hex).unwrap_or_else(|| {
        eprintln!("identity-provider: ZS_IDP_VERIFYING_KEY_HEX n'est pas un hexadécimal valide");
        std::process::exit(1);
    });
    let verifying_key =
        accept_verifying_key(zs_crypto::identity_assertion::SUITE_V1, &key_id, &raw)
            .unwrap_or_else(|e| {
                eprintln!("identity-provider: clé de vérification invalide : {e}");
                std::process::exit(1);
            });

    let grpc_addr: SocketAddr = env_or("ZS_IDP_ADDR", "127.0.0.1:50062")
        .parse()
        .expect("ZS_IDP_ADDR invalide");
    let http_addr: SocketAddr = env_or("ZS_IDP_HTTP_ADDR", "127.0.0.1:50063")
        .parse()
        .expect("ZS_IDP_HTTP_ADDR invalide");

    // Deux rôles Postgres distincts, jamais le même pool pour les deux (règle d'architecture :
    // aucun rôle applicatif en écriture sur plus d'un schéma).
    let identity_database_url = require_env("ZS_IDP_IDENTITY_DATABASE_URL");
    let audit_database_url = require_env("ZS_IDP_AUDIT_DATABASE_URL");

    // Deux clés HSM distinctes (ADR-011) — identity-assertion/v1 (émission) et audit-seal/v1
    // (scellement d'événement), jamais la même clé sous deux suites.
    let hsm_module_path: std::path::PathBuf =
        env_or("ZS_HSM_MODULE", "/usr/lib/softhsm/libsofthsm2.so").into();
    let hsm_pin = SecretString::from(require_env("SOFTHSM2_PIN"));
    let assertion_key_label = env_or("ZS_IDP_ASSERTION_HSM_KEY_LABEL", "zs-identity-assertion-v1");
    let audit_key_label = env_or("ZS_IDP_AUDIT_HSM_KEY_LABEL", "zs-audit-seal-v1");

    let rp_id = require_env("ZS_IDP_RP_ID");
    let origin = require_env("ZS_IDP_ORIGIN");
    let authority_domain = env_or("ZS_IDP_AUTHORITY_DOMAIN", "identity-provider");
    let audience = require_env("ZS_IDP_ASSERTION_AUDIENCE");
    let challenge_ttl_seconds = env_i64_or("ZS_IDP_CHALLENGE_TTL_SECONDS", 120);
    let assertion_ttl_seconds = env_i64_or("ZS_IDP_ASSERTION_TTL_SECONDS", 120);

    let runtime = tokio::runtime::Runtime::new().expect("création du runtime tokio");
    runtime.block_on(async {
        let assertion_sealer = AssertionSealer::open(AssertionHsmSettings {
            module_path: hsm_module_path.clone(),
            slot_id: None,
            pin: hsm_pin.clone(),
            pool_size: 4,
            acquire_timeout: Duration::from_secs(5),
            key_label: assertion_key_label,
        })
        .unwrap_or_else(|e| {
            eprintln!("identity-provider: échec de l'ouverture du scelleur d'assertions : {e}");
            std::process::exit(1);
        });
        eprintln!(
            "identity-provider: scelleur identity-assertion/v1 ouvert (key_id masqué, jamais journalisé)"
        );

        let audit_sealer = AuditSealer::open(AuditHsmSettings {
            module_path: hsm_module_path,
            slot_id: None,
            pin: hsm_pin,
            pool_size: 4,
            acquire_timeout: Duration::from_secs(5),
            key_label: audit_key_label,
        })
        .unwrap_or_else(|e| {
            eprintln!("identity-provider: échec de l'ouverture du scelleur d'audit : {e}");
            std::process::exit(1);
        });
        eprintln!("identity-provider: scelleur audit-seal/v1 ouvert");

        let identity_store = IdentityStore::connect(&identity_database_url)
            .await
            .unwrap_or_else(|e| {
                eprintln!("identity-provider: connexion identity_app indisponible : {e}");
                std::process::exit(1);
            });
        let audit_store = AuditStore::connect(&audit_database_url)
            .await
            .unwrap_or_else(|e| {
                eprintln!("identity-provider: connexion audit_writer indisponible : {e}");
                std::process::exit(1);
            });

        let state = Arc::new(AppState {
            identity_store,
            audit_store,
            assertion_sealer,
            audit_sealer,
            rp_id,
            origin,
            authority_domain,
            audience,
            challenge_ttl_seconds,
            assertion_ttl_seconds,
        });

        let http_listener = tokio::net::TcpListener::bind(http_addr)
            .await
            .unwrap_or_else(|e| {
                eprintln!("identity-provider: liaison HTTP {http_addr} impossible : {e}");
                std::process::exit(1);
            });

        eprintln!(
            "identity-provider: gRPC en écoute sur {grpc_addr}, HTTP (cérémonie WebAuthn) sur \
             {http_addr} — en clair, mTLS/TLS hors périmètre H3/H5"
        );

        let grpc = identity_provider::serve(grpc_addr, verifying_key);
        let http = axum::serve(http_listener, httpapi::router(state));

        tokio::select! {
            result = grpc => {
                if let Err(e) = result {
                    eprintln!("identity-provider: erreur serveur gRPC : {e}");
                    std::process::exit(1);
                }
            }
            result = http => {
                if let Err(e) = result {
                    eprintln!("identity-provider: erreur serveur HTTP : {e}");
                    std::process::exit(1);
                }
            }
        }
    });
}
