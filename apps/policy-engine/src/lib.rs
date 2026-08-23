//! `policy-engine` — PDP. Sans état, déterministe, rejouable hors ligne. Aucun appel réseau
//! pendant l'évaluation (règle absolue #5 du `CLAUDE.md` racine). Adaptateur mince : la logique
//! d'évaluation vit dans `zs_policy::pdp` (L2.2, ADR-015) — ce crate ne fait que charger le `Pdp`
//! une fois et le brancher sur le service gRPC `PolicyDecisionService`
//! (`contracts/proto/policy/v1/decision.proto`).
//!
//! Premier serveur réseau réel du dépôt : `identity-provider` (L1.1) a été délibérément cantonné
//! à une bibliothèque. Pas d'authentification mTLS de l'appelant ici — aucune intégration
//! SPIFFE/SPIRE n'existe encore dans le dépôt, prérequis d'infrastructure hors périmètre de L2.2
//! (signalé, pas oublié).
//!
//! `lib.rs`/`main.rs` séparés uniquement pour que `tests/` puisse démarrer de vraies instances du
//! service en process (client `tonic` réel, pas un double) — pas une dépendance croisée `apps/`.

use std::net::SocketAddr;

use tonic::{Request, Response, Status, transport::Server};

use zs_policy::pdp::Pdp;
pub use zs_policy::policy::v1::policy_decision_service_client::PolicyDecisionServiceClient;
use zs_policy::policy::v1::policy_decision_service_server::{
    PolicyDecisionService, PolicyDecisionServiceServer,
};
use zs_policy::policy::v1::{DecisionRequest, DecisionResponse};

pub struct PolicyEngine {
    pdp: Pdp,
}

impl PolicyEngine {
    pub fn new(pdp: Pdp) -> Self {
        Self { pdp }
    }
}

#[tonic::async_trait]
impl PolicyDecisionService for PolicyEngine {
    async fn decide(
        &self,
        request: Request<DecisionRequest>,
    ) -> Result<Response<DecisionResponse>, Status> {
        // decide() ne retourne jamais d'erreur Rust (P2 : le refus est la réponse) — aucun
        // chemin d'erreur gRPC ici à part une requête protobuf malformée, que tonic refuse déjà
        // avant d'atteindre ce point.
        Ok(Response::new(self.pdp.decide(request.get_ref())))
    }
}

/// Démarre le service gRPC sur `addr` et bloque jusqu'à arrêt (échec réseau ou signal). Aucun
/// appel réseau n'a lieu pendant l'évaluation elle-même — seule l'écoute HTTP/2 est un service
/// réseau, cohérent avec la frontière posée par la règle absolue #5 (le PDP en tant que service
/// est joignable par le réseau ; le PDP en train d'évaluer ne l'appelle jamais).
pub async fn serve(addr: SocketAddr, pdp: Pdp) -> Result<(), tonic::transport::Error> {
    let service = PolicyEngine::new(pdp);
    Server::builder().add_service(PolicyDecisionServiceServer::new(service)).serve(addr).await
}
