//! Test d'intégration réel (L2.2) : démarre deux instances distinctes du service gRPC
//! `PolicyDecisionService` sur deux ports séparés, les interroge avec un vrai client `tonic`
//! (pas un double), et vérifie que la même requête produit exactement le même `decision_hash`/
//! `policy_version`/`effect` sur les deux — déterminisme inter-processus, pas seulement
//! inter-appel (critère d'acceptation de `docs/backlog.md` L2.2).
//!
//! **Régression de couverture assumée (H4/ADR-019)** : jusqu'à H4, ce test tournait réellement
//! sur ce poste (pas de dépendance externe). Depuis que `policy_engine::serve` scelle chaque
//! décision via `zs_crypto::decision_seal::DecisionSealer` (HSM réel, `zs-hsm`), ce test exige
//! SoftHSM2 — indisponible ici (Podman bloqué), même limite que
//! `crates/zs-hsm/tests/pkcs11_integration.rs` (H1). `#[ignore]`, `ZS_HSM_MODULE` requis pour
//! l'exécuter (CI/Jenkins Linux, ou un humain avec SoftHSM2 disponible) — signalé explicitement,
//! pas contourné par un double qui masquerait ce que H4 a réellement changé.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use policy_engine::PolicyDecisionServiceClient;
use secrecy::SecretString;
use zs_crypto::decision_seal::{DecisionSealer, HsmSettings};
use zs_policy::pdp::Pdp;
use zs_policy::policy::v1::{
    Action, Approval, Context, DecisionRequest, DevicePosture, Effect, Principal, Resource,
};

/// Construit un scelleur réel depuis `ZS_HSM_MODULE`/`SOFTHSM2_PIN` — mêmes variables que
/// `crates/zs-hsm/tests/pkcs11_integration.rs`. Panique avec un message explicite si absent :
/// ce test ne doit jamais se dérober silencieusement (même discipline que H1).
fn open_sealer(key_label: &str) -> DecisionSealer {
    let module_path = PathBuf::from(std::env::var("ZS_HSM_MODULE").expect(
        "ZS_HSM_MODULE doit pointer vers le module PKCS#11 SoftHSM2 — ce test exige un HSM réel",
    ));
    let pin = SecretString::from(
        std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234test5678".to_string()),
    );
    DecisionSealer::open(HsmSettings {
        module_path,
        slot_id: None,
        pin,
        pool_size: 2,
        acquire_timeout: Duration::from_secs(5),
        key_label: key_label.to_string(),
    })
    .expect("ouverture du scelleur decision-seal/v1")
}

fn repo_root() -> PathBuf {
    // apps/policy-engine -> racine du dépôt
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_pdp() -> Pdp {
    Pdp::load(
        &repo_root().join("contracts/cedar/schema.cedarschema.json"),
        &repo_root().join("policies/access"),
    )
    .expect("chargement du PDP")
}

fn ts(seconds: i64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds, nanos: 0 }
}

fn nominal_request() -> DecisionRequest {
    let mut attrs = HashMap::new();
    attrs.insert("environment".to_string(), "production".to_string());

    DecisionRequest {
        request_id: "req-integration-1".to_string(),
        principal: Some(Principal {
            subject_id: "sub-6b2f9c".to_string(),
            aal: 3,
            auth_method: "webauthn/device-bound".to_string(),
            authenticated_at: Some(ts(1_787_500_680)),
            roles: vec!["dba".to_string()],
            authority_domain: "corp.eu-west".to_string(),
        }),
        action: Some(Action { verb: "db.connect".to_string() }),
        resource: Some(Resource {
            r#type: "Database".to_string(),
            id: "db-billing-prod".to_string(),
            authority_domain: "corp.eu-west".to_string(),
            attributes: attrs,
        }),
        context: Some(Context {
            requested_at: Some(ts(1_787_500_800)),
            source_network: "10.42.0.0/16".to_string(),
            posture: Some(DevicePosture {
                managed: true,
                disk_encrypted: true,
                agent_version: "2.4.1".to_string(),
                evaluated_at: Some(ts(1_787_499_000)),
            }),
            ticket_ref: "INC-482913".to_string(),
            justification: "Correctif de données sur incident de facturation".to_string(),
            approvals: vec![Approval {
                approver_id: "sub-a1f2e8".to_string(),
                approved_at: Some(ts(1_787_500_200)),
                signature: vec![],
            }],
        }),
        policy_version: String::new(),
    }
}

async fn spawn_server(addr: SocketAddr, key_label: &str) {
    let pdp = load_pdp();
    let sealer = open_sealer(key_label);
    tokio::spawn(async move {
        policy_engine::serve(addr, pdp, sealer).await.expect("serveur policy-engine");
    });
    // Attente courte que le port soit lié — pas de sonde de disponibilité dédiée dans ce dépôt à
    // ce stade, borné pour éviter un test qui traîne indéfiniment en cas d'échec réel de bind.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
#[ignore = "exige SoftHSM2 réel (ZS_HSM_MODULE) — indisponible sur ce poste, H4/ADR-019"]
async fn deux_instances_distinctes_du_service_produisent_la_meme_decision() {
    let addr_a: SocketAddr = "127.0.0.1:51601".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:51602".parse().unwrap();
    spawn_server(addr_a, "zs-decision-seal-v1-test-a").await;
    spawn_server(addr_b, "zs-decision-seal-v1-test-a").await;

    let mut client_a = PolicyDecisionServiceClient::connect(format!("http://{addr_a}"))
        .await
        .expect("connexion instance A");
    let mut client_b = PolicyDecisionServiceClient::connect(format!("http://{addr_b}"))
        .await
        .expect("connexion instance B");

    let response_a =
        client_a.decide(nominal_request()).await.expect("appel gRPC instance A").into_inner();
    let response_b =
        client_b.decide(nominal_request()).await.expect("appel gRPC instance B").into_inner();

    assert_eq!(response_a.effect, Effect::Allow as i32);
    assert_eq!(response_a.effect, response_b.effect);
    assert_eq!(response_a.decision_hash, response_b.decision_hash);
    assert_eq!(response_a.policy_version, response_b.policy_version);
    assert_eq!(response_a.reasons, response_b.reasons);
    assert!(response_a.reasons.contains(&"db-connect-production".to_string()));
}

#[tokio::test]
#[ignore = "exige SoftHSM2 réel (ZS_HSM_MODULE) — indisponible sur ce poste, H4/ADR-019"]
async fn requete_refusee_sur_le_reseau_reste_une_reponse_normale_pas_une_erreur_grpc() {
    let addr: SocketAddr = "127.0.0.1:51603".parse().unwrap();
    spawn_server(addr, "zs-decision-seal-v1-test-b").await;

    let mut client =
        PolicyDecisionServiceClient::connect(format!("http://{addr}")).await.expect("connexion");

    let mut req = nominal_request();
    req.principal.as_mut().unwrap().aal = 2; // AAL2 : refus attendu, pas une erreur de transport.

    let response = client.decide(req).await.expect("l'appel gRPC réussit").into_inner();
    assert_eq!(response.effect, Effect::Deny as i32);
}
