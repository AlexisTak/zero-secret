//! `policy-engine` — PDP. Sans état, déterministe, rejouable hors ligne. Aucun appel réseau
//! pendant l'évaluation (règle absolue #5 du `CLAUDE.md` racine — voir plus bas pour sa portée
//! exacte). Adaptateur mince : la logique d'évaluation vit dans `zs_policy::pdp` (L2.2, ADR-015)
//! — ce crate charge le `Pdp` et une session HSM une fois, les branche sur le service gRPC
//! `PolicyDecisionService` (`contracts/proto/policy/v1/decision.proto`).
//!
//! Premier serveur réseau réel du dépôt : `identity-provider` (L1.1) a été délibérément cantonné
//! à une bibliothèque. Pas d'authentification mTLS de l'appelant ici — aucune intégration
//! SPIFFE/SPIRE n'existe encore dans le dépôt, prérequis d'infrastructure hors périmètre.
//!
//! **Scellement `decision-seal/v1` (H4, ADR-019)** : `Decide()` évalue via `Pdp::decide` (reste
//! pur, sans HSM — la règle absolue #5 porte sur les ENTRÉES de la décision, pas sur le
//! scellement de la réponse qui suit) puis scelle systématiquement (ALLOW et DENY) avant de
//! renvoyer — échec de scellement = erreur gRPC (pas un refus métier : la décision n'existe pas
//! sans scellement, `credential-issuer` refuserait de toute façon une réponse non signée).
//! `VerifyDecision()` héberge la vérification à côté de la signature — même patron que H3
//! (`identity-provider` héberge déjà vérification et future émission ensemble), compromis de
//! défense en profondeur assumé (signataire = vérificateur).
//!
//! `lib.rs`/`main.rs` séparés uniquement pour que `tests/` puisse démarrer de vraies instances du
//! service en process (client `tonic` réel, pas un double) — pas une dépendance croisée `apps/`.

use std::net::SocketAddr;
use std::sync::Arc;

use tonic::{Request, Response, Status, transport::Server};

use zs_crypto::decision_seal::{AcceptedVerifyingKey, DecisionFields, DecisionSealer};
use zs_policy::pdp::Pdp;
pub use zs_policy::policy::v1::policy_decision_service_client::PolicyDecisionServiceClient;
use zs_policy::policy::v1::policy_decision_service_server::{
    PolicyDecisionService, PolicyDecisionServiceServer,
};
use zs_policy::policy::v1::{
    DecisionRequest, DecisionResponse, VerifyDecisionRequest, VerifyDecisionResponse,
};

pub struct PolicyEngine {
    pdp: Pdp,
    // Arc, pas DecisionSealer directement : decide() doit passer l'appel HSM (bloquant, ADR-011)
    // par spawn_blocking, ce qui exige un handle 'static déplaçable dans la tâche bloquante —
    // un &self emprunté à la durée de la requête ne suffit pas (correctif signalé pendant H5,
    // ADR-023 : identity-provider suit déjà cette discipline, policy-engine ne l'avait pas).
    sealer: Arc<DecisionSealer>,
    verifying_key: AcceptedVerifyingKey,
}

impl PolicyEngine {
    /// `policy-engine` vérifie ses propres décisions : la clé de vérification est dérivée de la
    /// clé de signature du scelleur, pas fournie séparément (H4/ADR-019).
    pub fn new(
        pdp: Pdp,
        sealer: DecisionSealer,
    ) -> Result<Self, zs_crypto::decision_seal::VerifyError> {
        let verifying_key = sealer.accepted_verifying_key()?;
        Ok(Self {
            pdp,
            sealer: Arc::new(sealer),
            verifying_key,
        })
    }
}

#[tonic::async_trait]
impl PolicyDecisionService for PolicyEngine {
    async fn decide(
        &self,
        request: Request<DecisionRequest>,
    ) -> Result<Response<DecisionResponse>, Status> {
        // decide() ne retourne jamais d'erreur Rust pour un refus MÉTIER (P2) — mais un échec de
        // scellement n'est pas un refus métier : la décision elle-même n'existe pas sans lui, une
        // erreur gRPC est le seul chemin honnête ici (l'appelant ne doit jamais recevoir une
        // DecisionResponse non signée en la croyant valide).
        let mut response = self.pdp.decide(request.get_ref());

        let issued_at_str = rfc3339_now();
        let fields = decision_fields(&response, &issued_at_str)
            .map_err(|e| Status::internal(format!("horodatage de décision invalide : {e}")))?;

        // zs-hsm expose une API bloquante (ADR-011) : jamais d'appel direct depuis un handler
        // async partageant le runtime avec le reste du service (même discipline que
        // apps/identity-provider/src/httpapi.rs, H5/ADR-023).
        let sealer = Arc::clone(&self.sealer);
        let (signature, key_id) = tokio::task::spawn_blocking(move || sealer.seal(&fields))
            .await
            .map_err(|e| Status::internal(format!("tâche de scellement interrompue : {e}")))?
            .map_err(|e| {
                Status::unavailable(format!("scellement de la décision indisponible : {e}"))
            })?;

        response.issued_at = Some(prost_types::Timestamp {
            seconds: request_time_from_rfc3339(&issued_at_str),
            nanos: 0,
        });
        response.decision_signature = signature;
        response.decision_signature_key_id = key_id;

        Ok(Response::new(response))
    }

    async fn verify_decision(
        &self,
        request: Request<VerifyDecisionRequest>,
    ) -> Result<Response<VerifyDecisionResponse>, Status> {
        let decision = match request.into_inner().decision {
            Some(d) => d,
            None => {
                return Ok(Response::new(VerifyDecisionResponse {
                    valid: false,
                    reason: "decision_absente".to_string(),
                }));
            }
        };

        let issued_at_str = match decision.issued_at.as_ref() {
            Some(ts) => rfc3339_from_seconds(ts.seconds),
            None => {
                return Ok(Response::new(VerifyDecisionResponse {
                    valid: false,
                    reason: "issued_at_absent".to_string(),
                }));
            }
        };
        let fields = match decision_fields(&decision, &issued_at_str) {
            Ok(f) => f,
            Err(_) => {
                return Ok(Response::new(VerifyDecisionResponse {
                    valid: false,
                    reason: "issued_at_invalide".to_string(),
                }));
            }
        };

        let response = match zs_crypto::decision_seal::verify(
            std::slice::from_ref(&self.verifying_key),
            &fields,
            &decision.decision_signature_key_id,
            &decision.decision_signature,
        ) {
            Ok(()) => VerifyDecisionResponse {
                valid: true,
                reason: String::new(),
            },
            Err(e) => VerifyDecisionResponse {
                valid: false,
                reason: e.to_string(),
            },
        };
        Ok(Response::new(response))
    }
}

// Retourne une erreur plutôt que de paniquer : `issued_at_str` peut provenir de
// `rfc3339_from_seconds` appliqué à une valeur `seconds` reçue du réseau (`verify_decision`),
// que `Timestamp::new` peut légitimement refuser (année hors plage, largeur non conforme) — voir
// audit.md §3.1. Les deux appelants traduisent l'erreur en refus explicite, jamais en panique.
fn decision_fields(
    response: &DecisionResponse,
    issued_at_str: &str,
) -> Result<DecisionFields, String> {
    let issued_at = zs_crypto::identity_assertion::Timestamp::new(issued_at_str.to_string())
        .map_err(|e| e.to_string())?;
    Ok(DecisionFields {
        request_id: String::new(), // request_id n'est pas porté par DecisionResponse (par design,
        // decision.proto) — voir note ADR-019 : absent du scellement pour cette raison, jamais
        // "oublié" silencieusement.
        decision_hash: response.decision_hash.clone(),
        policy_version: response.policy_version.clone(),
        effect_allow: response.effect == zs_policy::policy::v1::Effect::Allow as i32,
        reasons: response.reasons.clone(),
        max_ttl_seconds: response
            .max_ttl
            .as_ref()
            .map(|d| d.seconds.max(0) as u64)
            .unwrap_or(0),
        constraints: response.constraints.clone(),
        issued_at,
    })
}

/// Démarre le service gRPC sur `addr` et bloque jusqu'à arrêt (échec réseau ou signal).
///
/// # Panics
/// Si la dérivation de la clé de vérification depuis le scelleur échoue — ne devrait jamais
/// arriver en pratique (`DecisionSealer::open` a déjà réussi à résoudre la même clé publique).
pub async fn serve(
    addr: SocketAddr,
    pdp: Pdp,
    sealer: DecisionSealer,
) -> Result<(), tonic::transport::Error> {
    let service = PolicyEngine::new(pdp, sealer).expect("dérivation de la clé de vérification");
    Server::builder()
        .add_service(PolicyDecisionServiceServer::new(service))
        .serve(addr)
        .await
}

/// Horodatage RFC 3339 UTC strict de l'instant courant — même algorithme que
/// `apps/identity-provider` (civil_from_days, Howard Hinnant), dupliqué plutôt que partagé : deux
/// occurrences indépendantes d'un calcul fixe et étroit, pas une justification suffisante pour un
/// nouveau crate partagé (règle absolue #10 — cohérent avec `hex_decode` déjà dupliqué ailleurs
/// dans ce dépôt, ex. `zs-audit/tests/chain_vectors.rs`).
fn rfc3339_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("horloge système antérieure à 1970");
    rfc3339_from_seconds(now.as_secs() as i64)
}

fn rfc3339_from_seconds(total_seconds: i64) -> String {
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn request_time_from_rfc3339(s: &str) -> i64 {
    // Reconstruit les secondes epoch depuis la chaîne déjà produite par rfc3339_now() dans le
    // même appel — évite un second calcul d'horloge entre la construction du message signé et
    // l'assignation du champ proto (la valeur DOIT être strictement identique aux deux endroits).
    let bytes = s.as_bytes();
    let year: i64 = std::str::from_utf8(&bytes[0..4]).unwrap().parse().unwrap();
    let month: i64 = std::str::from_utf8(&bytes[5..7]).unwrap().parse().unwrap();
    let day: i64 = std::str::from_utf8(&bytes[8..10]).unwrap().parse().unwrap();
    let hour: i64 = std::str::from_utf8(&bytes[11..13])
        .unwrap()
        .parse()
        .unwrap();
    let minute: i64 = std::str::from_utf8(&bytes[14..16])
        .unwrap()
        .parse()
        .unwrap();
    let second: i64 = std::str::from_utf8(&bytes[17..19])
        .unwrap()
        .parse()
        .unwrap();
    days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_aller_retour_est_stable() {
        let s = rfc3339_now();
        let seconds = request_time_from_rfc3339(&s);
        assert_eq!(rfc3339_from_seconds(seconds), s);
    }

    #[test]
    fn decision_fields_refuse_annee_hors_plage_au_lieu_de_paniquer() {
        // Régression audit.md §3.1 : `seconds` provient de `VerifyDecisionRequest.decision.
        // issued_at`, contrôlé par l'appelant gRPC (`verify_decision`). Une valeur extrême produit
        // une chaîne RFC 3339 de largeur non conforme (année sur plus ou moins de 4 chiffres) ;
        // `decision_fields` doit refuser explicitement, jamais paniquer via `.expect()`.
        let response = DecisionResponse::default();
        for seconds in [i64::MAX, i64::MIN] {
            let issued_at_str = rfc3339_from_seconds(seconds);
            assert!(
                decision_fields(&response, &issued_at_str).is_err(),
                "seconds={seconds} (chaîne \"{issued_at_str}\") devait être refusé, pas accepté ni paniquer"
            );
        }
    }
}
