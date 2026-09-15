//! Harnais de mesure pour l'objectif de service « évaluation de politique (p99) < 25 ms »
//! (`docs/architecture.md`). `CLAUDE.md` §11 : « une métrique ne peut être présentée comme
//! atteinte que si elle a été réellement mesurée » — ce fichier produit la mesure, il ne
//! l'affirme pas. Le résultat imprimé par ce test doit être recopié à la main dans
//! `docs/architecture.md` (avec le matériel et la date), jamais généré automatiquement dans la
//! documentation sans revue humaine.
//!
//! `Pdp::decide` est pur — aucun HSM, aucun réseau, aucune I/O (voir `crates/zs-policy/src/pdp.rs`)
//! — ce harnais ne nécessite donc pas `make up`, contrairement aux tests d'intégration H4/L2.2.
//!
//! `#[ignore]` par défaut, comme les autres harnais coûteux de ce dépôt (H1, H4, conformité
//! crypto) : une mesure de latence n'a pas sa place dans le cycle rapide `cargo nextest run`, et
//! ferait varier le temps de CI sans bénéfice pour la plupart des contributions. Exécuter avec :
//! `cargo test -p zs-policy --test decide_p99_bench -- --ignored --nocapture`.
//!
//! Pas de nouvelle dépendance (`criterion` ou équivalent) pour ce besoin étroit — mesure de
//! latence par `std::time::Instant`, tri et percentiles calculés à la main (règle absolue #10,
//! même raisonnement que le calcul RFC 3339 manuel d'`apps/identity-provider`/`apps/policy-engine`).

use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zs_policy::pdp::Pdp;
use zs_policy::policy::v1::{
    Action, Approval, Context, DecisionRequest, DevicePosture, Effect, Principal, Resource,
};

const WARMUP_ITERATIONS: usize = 200;
const MEASURED_ITERATIONS: usize = 10_000;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_pdp() -> Pdp {
    Pdp::load(
        &repo_root().join("contracts/cedar/schema.cedarschema.json"),
        &repo_root().join("policies/access"),
    )
    .expect("chargement du PDP — corpus policies/access/")
}

fn ts(seconds: i64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds, nanos: 0 }
}

/// Même requête nominale que `apps/policy-engine/tests/decide_integration.rs` — un seul corpus
/// de référence pour l'intégration et la mesure de latence, pas deux qui pourraient diverger.
fn nominal_request() -> DecisionRequest {
    let mut attrs = std::collections::HashMap::new();
    attrs.insert("environment".to_string(), "production".to_string());

    DecisionRequest {
        request_id: "req-bench-1".to_string(),
        principal: Some(Principal {
            subject_id: "sub-6b2f9c".to_string(),
            aal: 3,
            auth_method: "webauthn/device-bound".to_string(),
            authenticated_at: Some(ts(1_787_500_680)),
            roles: vec!["dba".to_string()],
            authority_domain: "corp.eu-west".to_string(),
        }),
        action: Some(Action {
            verb: "db.connect".to_string(),
        }),
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

fn percentile(sorted_durations: &[Duration], p: f64) -> Duration {
    let idx = ((sorted_durations.len() as f64 - 1.0) * p).round() as usize;
    sorted_durations[idx]
}

#[test]
#[ignore = "harnais de mesure, pas un test de correction — cargo test -p zs-policy --test decide_p99_bench -- --ignored --nocapture"]
fn decide_p99_sur_la_requete_nominale() {
    let pdp = load_pdp();
    let request = nominal_request();

    // Sanity check : le harnais doit mesurer un vrai ALLOW, pas un chemin de refus rapide qui
    // fausserait la latence mesurée à la baisse.
    let sanity = pdp.decide(&request);
    assert_eq!(
        sanity.effect,
        Effect::Allow as i32,
        "la requête nominale doit être ALLOW — sinon ce harnais mesure un autre chemin de code"
    );

    for _ in 0..WARMUP_ITERATIONS {
        black_box(pdp.decide(black_box(&request)));
    }

    let mut durations = Vec::with_capacity(MEASURED_ITERATIONS);
    for _ in 0..MEASURED_ITERATIONS {
        let start = Instant::now();
        black_box(pdp.decide(black_box(&request)));
        durations.push(start.elapsed());
    }
    durations.sort();

    let p50 = percentile(&durations, 0.50);
    let p95 = percentile(&durations, 0.95);
    let p99 = percentile(&durations, 0.99);
    let max = *durations.last().expect("au moins une itération mesurée");

    println!("--- decide_p99_bench (Pdp::decide, requête nominale db.connect) ---");
    println!("itérations mesurées : {MEASURED_ITERATIONS} (+{WARMUP_ITERATIONS} d'échauffement)");
    println!(
        "rustc               : noter la sortie de `rustc --version` à côté de ce résultat (CLAUDE.md §11)"
    );
    println!(
        "profil de build     : {}",
        if cfg!(debug_assertions) {
            "debug (non représentatif — relancer avec --release)"
        } else {
            "release"
        }
    );
    println!("p50 : {p50:?}");
    println!("p95 : {p95:?}");
    println!("p99 : {p99:?}");
    println!("max : {max:?}");
    println!(
        "objectif docs/architecture.md : < 25 ms p99 — {}",
        if p99 < Duration::from_millis(25) {
            "atteint sur cette mesure, sur cette machine — pas une garantie de production"
        } else {
            "NON atteint sur cette mesure — à investiguer avant de documenter l'objectif comme tenu"
        }
    );
    println!(
        "Recopier ce résultat à la main dans docs/architecture.md avec le matériel et la date \
         (CLAUDE.md §11) — ce test ne met à jour aucune documentation automatiquement."
    );
}
