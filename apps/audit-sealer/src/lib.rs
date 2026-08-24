//! `audit-sealer` — scellement d'événements d'audit (`audit-seal/v1`), pont Rust<->Go. Sans
//! état, sans accès Postgres, une seule opération cryptographique : reçoit des champs déjà
//! calculés (`sequence`/`prev_hash` déterminés par `audit-collector`), appelle
//! `zs_crypto::audit_seal::AuditSealer::seal`, retourne les octets scellés.
//!
//! Servi sur un **socket Unix**, jamais un port réseau ouvert (voir l'ADR de ce lot) : exposer
//! la clé `zs-audit-seal-v1` comme un oracle de signature accessible à quiconque atteint un
//! port détruirait la non-répudiation de tout le journal — `identity-provider` (H5) garde sa
//! propre clé de scellement strictement intra-process, ce composant est le premier à la
//! partager en service dédié, donc la colocalisation par socket Unix remplace le mTLS absent.
//!
//! Porte désormais le champ `decision` (ADR-027) — `policy.decided` peut être scellé via ce
//! pont, ainsi que `credential.issued` depuis ADR-029 (même forme de `decision`).

use tonic::{Request, Response, Status};

use zs_audit_sealing::audit::v1::{
    Actor as ProtoActor, Context as ProtoContext, Decision as ProtoDecision, HashPreviousRequest,
    HashPreviousResponse, SealRequest, SealResponse, Target as ProtoTarget,
    audit_sealing_service_server::AuditSealingService,
};
use zs_crypto::audit_seal::{
    self, ActorKind, AuditEventFields, AuditSealer, EventType, Outcome, Sequence,
};
use zs_crypto::identity_assertion::AssuranceLevel;

pub struct SealerService {
    sealer: AuditSealer,
}

impl SealerService {
    pub fn new(sealer: AuditSealer) -> Self {
        Self { sealer }
    }
}

#[tonic::async_trait]
impl AuditSealingService for SealerService {
    async fn seal(&self, request: Request<SealRequest>) -> Result<Response<SealResponse>, Status> {
        let fields = fields_from_request(request.into_inner()).map_err(Status::invalid_argument)?;

        let sealed = self
            .sealer
            .seal(fields)
            .map_err(|e| Status::unavailable(format!("scellement indisponible : {e}")))?;

        Ok(Response::new(SealResponse {
            sealed_bytes: sealed.as_bytes().to_vec(),
        }))
    }

    /// Hache les octets scellés d'un événement déjà persisté, pour que `audit-collector` (Go)
    /// puisse calculer le `prev_hash` de l'événement suivant sans importer de bibliothèque de
    /// hachage directement (règle absolue #4). `zs_audit::hash_sealed_event` est une simple
    /// façade vers `zs_crypto::authenticator_proof::sha256` — aucune nouvelle opération
    /// cryptographique, pas d'entrée CBOM requise.
    async fn hash_previous(
        &self,
        request: Request<HashPreviousRequest>,
    ) -> Result<Response<HashPreviousResponse>, Status> {
        let digest = zs_audit::hash_sealed_event(&request.into_inner().sealed_bytes);
        Ok(Response::new(HashPreviousResponse {
            digest: digest.to_vec(),
        }))
    }
}

fn fields_from_request(req: SealRequest) -> Result<AuditEventFields, String> {
    let event_type = event_type_from_str(&req.event_type)
        .ok_or_else(|| "event_type_inconnu_ou_non_supporte".to_string())?;
    let outcome = outcome_from_str(&req.outcome).ok_or_else(|| "outcome_inconnu".to_string())?;

    let prev_hash: [u8; 32] = req
        .prev_hash
        .try_into()
        .map_err(|_| "prev_hash_doit_faire_32_octets".to_string())?;

    let occurred_at = req
        .occurred_at
        .ok_or_else(|| "occurred_at_absent".to_string())?;
    let occurred_at_str = rfc3339_from_seconds(occurred_at.seconds);

    let actor = req.actor.ok_or_else(|| "actor_absent".to_string())?;
    let actor = actor_from_proto(actor)?;

    let target = req.target.map(target_from_proto).transpose()?;
    let context = req.context.map(context_from_proto).transpose()?;
    let decision = req.decision.map(decision_from_proto).transpose()?;

    Ok(AuditEventFields {
        event_id: audit_seal::EventId::new(req.event_id).map_err(|e| e.to_string())?,
        sequence: Sequence::new(req.sequence).map_err(|e| e.to_string())?,
        prev_hash,
        occurred_at: audit_seal::Timestamp::new(occurred_at_str).map_err(|e| e.to_string())?,
        authority_domain: audit_seal::AuthorityDomain::new(req.authority_domain)
            .map_err(|e| e.to_string())?,
        event_type,
        actor,
        target,
        outcome,
        context,
        decision,
    })
}

fn actor_from_proto(actor: ProtoActor) -> Result<audit_seal::Actor, String> {
    let kind = actor_kind_from_str(&actor.kind).ok_or_else(|| "actor_kind_inconnu".to_string())?;
    let aal = actor
        .aal
        .map(|s| assurance_level_from_str(&s).ok_or_else(|| "aal_inconnu".to_string()))
        .transpose()?;
    let auth_method = actor
        .auth_method
        .map(zs_crypto::identity_assertion::AuthMethod::new)
        .transpose()
        .map_err(|e| e.to_string())?;

    Ok(audit_seal::Actor {
        subject_id: zs_crypto::identity_assertion::SubjectId::new(actor.subject_id)
            .map_err(|e| e.to_string())?,
        kind,
        aal,
        auth_method,
    })
}

fn target_from_proto(target: ProtoTarget) -> Result<audit_seal::Target, String> {
    Ok(audit_seal::Target {
        target_type: audit_seal::ShortText::new(target.r#type).map_err(|e| e.to_string())?,
        id: audit_seal::ShortText::new(target.id).map_err(|e| e.to_string())?,
    })
}

fn decision_from_proto(decision: ProtoDecision) -> Result<audit_seal::DecisionInfo, String> {
    let decision_hash: [u8; 32] = decision
        .decision_hash
        .try_into()
        .map_err(|_| "decision_hash_doit_faire_32_octets".to_string())?;
    let reasons = decision
        .reasons
        .into_iter()
        .map(audit_seal::Reason::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    Ok(audit_seal::DecisionInfo {
        request_id: audit_seal::RequestId::new(decision.request_id).map_err(|e| e.to_string())?,
        decision_hash,
        policy_version: audit_seal::PolicyVersion::new(decision.policy_version)
            .map_err(|e| e.to_string())?,
        reasons,
        granted_ttl_seconds: decision.granted_ttl_seconds,
        decision_signature: decision.decision_signature,
        decision_signature_key_id: decision
            .decision_signature_key_id
            .map(audit_seal::ShortText::new)
            .transpose()
            .map_err(|e| e.to_string())?,
    })
}

fn context_from_proto(context: ProtoContext) -> Result<audit_seal::Context, String> {
    Ok(audit_seal::Context {
        source_network: context
            .source_network
            .map(audit_seal::ShortText::new)
            .transpose()
            .map_err(|e| e.to_string())?,
        ticket_ref: context
            .ticket_ref
            .map(audit_seal::ShortText::new)
            .transpose()
            .map_err(|e| e.to_string())?,
        justification: context
            .justification
            .map(audit_seal::Justification::new)
            .transpose()
            .map_err(|e| e.to_string())?,
    })
}

/// Duplique volontairement `EventType::from_contract_str` (privée à `zs-crypto`, invisible hors
/// crate) — mapping trivial de 8 chaînes vers des variantes d'énumération publiques, aucun
/// risque de divergence de canonicalisation contrairement à une réimplémentation JCS (même
/// raisonnement que la duplication de `civil_from_days` entre `policy-engine`/`identity-
/// provider` : un calcul fixe et étroit ne justifie pas un nouveau crate partagé, règle #10).
fn event_type_from_str(s: &str) -> Option<EventType> {
    Some(match s {
        "authenticator.registered" => EventType::AuthenticatorRegistered,
        "authenticator.revoked" => EventType::AuthenticatorRevoked,
        "authentication.attempted" => EventType::AuthenticationAttempted,
        "authentication.succeeded" => EventType::AuthenticationSucceeded,
        "authentication.failed" => EventType::AuthenticationFailed,
        "recovery.initiated" => EventType::RecoveryInitiated,
        "quorum.operation" => EventType::QuorumOperation,
        "audit.chain_verified" => EventType::AuditChainVerified,
        "policy.decided" => EventType::PolicyDecided,
        "credential.issued" => EventType::CredentialIssued,
        _ => return None,
    })
}

fn actor_kind_from_str(s: &str) -> Option<ActorKind> {
    Some(match s {
        "human" => ActorKind::Human,
        "workload" => ActorKind::Workload,
        "system" => ActorKind::System,
        _ => return None,
    })
}

fn outcome_from_str(s: &str) -> Option<Outcome> {
    Some(match s {
        "success" => Outcome::Success,
        "denied" => Outcome::Denied,
        "error" => Outcome::Error,
        _ => return None,
    })
}

fn assurance_level_from_str(s: &str) -> Option<AssuranceLevel> {
    Some(match s {
        "AAL1" => AssuranceLevel::Aal1,
        "AAL2" => AssuranceLevel::Aal2,
        "AAL3" => AssuranceLevel::Aal3,
        _ => return None,
    })
}

/// Horodatage RFC 3339 UTC strict depuis des secondes epoch — même algorithme dupliqué que
/// `apps/policy-engine`/`apps/identity-provider` (`civil_from_days`, Howard Hinnant), même
/// raisonnement de non-partage (règle absolue #10). Les nanosecondes du `Timestamp` proto sont
/// ignorées : le format attendu par `zs_crypto::common::Timestamp::new` n'a pas de fraction de
/// seconde.
fn rfc3339_from_seconds(total_seconds: i64) -> String {
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_epoch_est_1970_01_01() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn event_type_inconnu_est_refuse() {
        // access.requested/access.approved/access.denied/credential.expired/credential.revoked/
        // policy.modified sont dans le contrat (contracts/events/audit-event.schema.json) mais
        // n'ont aucun producteur ni variante d'EventType à ce jour (pas d'anticipation).
        assert!(event_type_from_str("access.requested").is_none());
        assert!(event_type_from_str("n_importe_quoi").is_none());
    }

    #[test]
    fn event_type_connu_est_accepte() {
        assert!(event_type_from_str("quorum.operation").is_some());
        assert!(event_type_from_str("authentication.succeeded").is_some());
        assert!(event_type_from_str("policy.decided").is_some());
        assert!(event_type_from_str("credential.issued").is_some());
    }

    fn sample_actor() -> ProtoActor {
        ProtoActor {
            subject_id: "subject-1".to_string(),
            kind: "human".to_string(),
            aal: None,
            auth_method: None,
        }
    }

    fn sample_decision() -> ProtoDecision {
        ProtoDecision {
            request_id: "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
            decision_hash: vec![0xCDu8; 32],
            policy_version: "db.connect@1".to_string(),
            reasons: vec!["db-connect-production".to_string()],
            granted_ttl_seconds: Some(900),
            decision_signature: Some(vec![0xEFu8; 64]),
            decision_signature_key_id: Some("decision-key-1".to_string()),
        }
    }

    #[test]
    fn fields_from_request_refuse_un_prev_hash_de_mauvaise_longueur() {
        let req = SealRequest {
            event_id: "0198e6c1-0000-7000-8000-000000000000".to_string(),
            sequence: 0,
            prev_hash: vec![0u8; 31],
            occurred_at: Some(prost_types::Timestamp {
                seconds: 1_777_000_000,
                nanos: 0,
            }),
            authority_domain: "identity-provider".to_string(),
            event_type: "quorum.operation".to_string(),
            actor: Some(sample_actor()),
            target: None,
            outcome: "success".to_string(),
            context: None,
            decision: None,
        };
        match fields_from_request(req) {
            Err(reason) => assert_eq!(reason, "prev_hash_doit_faire_32_octets"),
            Ok(_) => panic!("attendu un refus"),
        }
    }

    #[test]
    fn fields_from_request_refuse_un_event_type_non_supporte() {
        let req = SealRequest {
            event_id: "0198e6c1-0000-7000-8000-000000000000".to_string(),
            sequence: 0,
            prev_hash: vec![0u8; 32],
            occurred_at: Some(prost_types::Timestamp {
                seconds: 1_777_000_000,
                nanos: 0,
            }),
            authority_domain: "identity-provider".to_string(),
            event_type: "access.requested".to_string(),
            actor: Some(sample_actor()),
            target: None,
            outcome: "success".to_string(),
            context: None,
            decision: None,
        };
        match fields_from_request(req) {
            Err(reason) => assert_eq!(reason, "event_type_inconnu_ou_non_supporte"),
            Ok(_) => panic!("attendu un refus"),
        }
    }

    #[test]
    fn fields_from_request_accepte_policy_decided_avec_decision() {
        let req = SealRequest {
            event_id: "0198e6c1-0000-7000-8000-000000000000".to_string(),
            sequence: 0,
            prev_hash: vec![0u8; 32],
            occurred_at: Some(prost_types::Timestamp {
                seconds: 1_777_000_000,
                nanos: 0,
            }),
            authority_domain: "access-broker".to_string(),
            event_type: "policy.decided".to_string(),
            actor: Some(sample_actor()),
            target: None,
            outcome: "success".to_string(),
            context: None,
            decision: Some(sample_decision()),
        };
        assert!(fields_from_request(req).is_ok());
    }

    #[test]
    fn fields_from_request_refuse_policy_decided_sans_decision() {
        // Le couplage bidirectionnel (zs_crypto::audit_seal::EventType::requires_decision) est
        // vérifié par AuditSealer::seal, pas par fields_from_request lui-même — mais
        // fields_from_request doit au moins produire un AuditEventFields cohérent (decision:
        // None ici), pas paniquer ni inventer une valeur. Le refus réel est couvert côté
        // zs-crypto (decision_absente_sur_policy_decided_est_refusee_au_scellement).
        let req = SealRequest {
            event_id: "0198e6c1-0000-7000-8000-000000000000".to_string(),
            sequence: 0,
            prev_hash: vec![0u8; 32],
            occurred_at: Some(prost_types::Timestamp {
                seconds: 1_777_000_000,
                nanos: 0,
            }),
            authority_domain: "access-broker".to_string(),
            event_type: "policy.decided".to_string(),
            actor: Some(sample_actor()),
            target: None,
            outcome: "success".to_string(),
            context: None,
            decision: None,
        };
        let fields = fields_from_request(req).expect("construction réussie, decision absente");
        assert!(fields.decision.is_none());
    }

    #[test]
    fn fields_from_request_accepte_credential_issued_avec_decision() {
        let req = SealRequest {
            event_id: "0198e6c1-0000-7000-8000-000000000000".to_string(),
            sequence: 0,
            prev_hash: vec![0u8; 32],
            occurred_at: Some(prost_types::Timestamp {
                seconds: 1_777_000_000,
                nanos: 0,
            }),
            authority_domain: "credential-issuer".to_string(),
            event_type: "credential.issued".to_string(),
            actor: Some(sample_actor()),
            target: None,
            outcome: "success".to_string(),
            context: None,
            decision: Some(sample_decision()),
        };
        assert!(fields_from_request(req).is_ok());
    }

    #[test]
    fn decision_from_proto_refuse_un_decision_hash_de_mauvaise_longueur() {
        let mut decision = sample_decision();
        decision.decision_hash = vec![0u8; 31];
        match decision_from_proto(decision) {
            Err(reason) => assert_eq!(reason, "decision_hash_doit_faire_32_octets"),
            Ok(_) => panic!("attendu un refus"),
        }
    }
}
