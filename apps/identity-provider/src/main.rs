//! Binaire mince : charge la clé de vérification acceptée depuis l'environnement (H3, ADR-016 —
//! distribution réelle de la clé publique hors périmètre, provisoire), puis délègue à
//! `identity_provider::serve`. Voir `src/lib.rs` pour le contexte complet.

use std::net::SocketAddr;

use zs_crypto::identity_assertion::accept_verifying_key;

fn require_env(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| {
        eprintln!("identity-provider: variable d'environnement manquante : {var}");
        std::process::exit(1);
    })
}

fn main() {
    let key_hex = require_env("ZS_IDP_VERIFYING_KEY_HEX");
    let key_id = require_env("ZS_IDP_VERIFYING_KEY_ID");

    let raw = match hex_decode(&key_hex) {
        Some(bytes) => bytes,
        None => {
            eprintln!("identity-provider: ZS_IDP_VERIFYING_KEY_HEX n'est pas un hexadécimal valide");
            std::process::exit(1);
        }
    };

    let key = match accept_verifying_key(
        zs_crypto::identity_assertion::SUITE_V1,
        &key_id,
        &raw,
    ) {
        Ok(key) => key,
        Err(e) => {
            // Échec dur au démarrage — jamais un service qui démarre en refusant toute
            // vérification par accident sans que l'opérateur le sache (R2).
            eprintln!("identity-provider: clé de vérification invalide : {e}");
            std::process::exit(1);
        }
    };

    let addr: SocketAddr = std::env::var("ZS_IDP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50062".to_string())
        .parse()
        .expect("ZS_IDP_ADDR invalide");

    let runtime = tokio::runtime::Runtime::new().expect("création du runtime tokio");
    runtime.block_on(async {
        eprintln!("identity-provider: en écoute sur {addr} (gRPC en clair — mTLS hors périmètre H3)");
        if let Err(e) = identity_provider::serve(addr, key).await {
            eprintln!("identity-provider: erreur serveur : {e}");
            std::process::exit(1);
        }
    });
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}
