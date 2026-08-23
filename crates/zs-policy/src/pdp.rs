//! Point de décision de politique (PDP) : `Decide(DecisionRequest) → DecisionResponse`
//! (`contracts/proto/policy/v1/decision.proto`), évalué contre le corpus Cedar de
//! `policies/access/` et `contracts/cedar/schema.cedarschema.json` (L2.1, ADR-014).
//!
//! Sans état, déterministe, aucun appel réseau pendant l'évaluation (règle absolue #5 du
//! `CLAUDE.md` racine). Un refus est une `DecisionResponse` normale (`effect: EFFECT_DENY`),
//! jamais une erreur Rust — P2 : le refus par défaut EST la réponse, pas une voie d'exception
//! séparée que l'appelant devrait décider de traduire.
//!
//! `decision_hash`/`policy_version` passent par `zs_crypto::decision_binding` (ADR-015,
//! consultation `referent-crypto`) — jamais un hash calculé ici, pour la même raison que le
//! double-hachage `aws-lc-rs` découvert en L1.2c : deux canonicalisations indépendantes d'un même
//! contenu divergent silencieusement.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context as CedarContext, Decision, Entities, Entity, EntityId, EntityTypeName,
    EntityUid, PolicySet, Request as CedarRequest, RestrictedExpression, Schema,
};

use crate::policy::v1::{
    Context as ProtoContext, DecisionRequest, DecisionResponse, Effect,
    Principal as ProtoPrincipal, Resource as ProtoResource,
};

const NAMESPACE: &str = "ZeroSecret";
// Version déclarée du moteur d'évaluation, entrant dans `policy_version` (ADR-015) : un upgrade
// du crate change la sémantique d'évaluation à corpus textuellement identique. Cargo.lock fait
// foi en cas de dérive avec cette constante — à tenir synchronisée à chaque bump de dépendance.
const CEDAR_ENGINE_VERSION: &str = "4.12.0";

#[derive(Debug, thiserror::Error)]
pub enum PdpLoadError {
    #[error("lecture du schéma Cedar : {0}")]
    ReadSchema(std::io::Error),
    #[error("schéma Cedar invalide : {0}")]
    Schema(String),
    #[error("lecture du corpus de politiques : {0}")]
    ReadCorpus(std::io::Error),
    #[error("corpus de politiques invalide : {0}")]
    Policies(String),
    #[error("empreinte de corpus : {0}")]
    Binding(#[from] zs_crypto::decision_binding::CorpusBindingError),
}

/// Point de décision de politique, chargé une fois, réutilisé pour chaque appel `decide`.
pub struct Pdp {
    schema: Schema,
    policies: PolicySet,
    policy_version: String,
    authorizer: Authorizer,
}

impl Pdp {
    /// Charge le schéma et le corpus de `policies/access/*.cedar` — lecture locale uniquement,
    /// aucun appel réseau, cohérent avec « sans état, rejouable hors ligne ». `policy_version`
    /// est calculé une fois ici et réutilisé pour chaque décision tant que le processus vit :
    /// le PDP sert une seule version à la fois, jamais un magasin multi-version en mémoire — un
    /// rejeu contre une version archivée relance ce même code déterministe sur les fichiers du
    /// commit historique correspondant, ce n'est pas une fonctionnalité du serveur vivant.
    pub fn load(schema_path: &Path, policies_dir: &Path) -> Result<Self, PdpLoadError> {
        let schema_json = fs::read_to_string(schema_path).map_err(PdpLoadError::ReadSchema)?;
        let schema =
            Schema::from_json_str(&schema_json).map_err(|e| PdpLoadError::Schema(e.to_string()))?;

        let mut cedar_files: Vec<(String, String)> = Vec::new();
        for entry in fs::read_dir(policies_dir).map_err(PdpLoadError::ReadCorpus)? {
            let entry = entry.map_err(PdpLoadError::ReadCorpus)?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("cedar") {
                continue;
            }
            let contents = fs::read_to_string(&path).map_err(PdpLoadError::ReadCorpus)?;
            let relative = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            cedar_files.push((relative, contents));
        }
        // Tri par chemin octet par octet, pas par ordre du système de fichiers (non garanti
        // stable entre plateformes) — cohérent avec bind_policy_corpus qui trie aussi lui-même,
        // mais un ordre d'entrée déjà trié rend le comportement lisible ici sans dépendre
        // silencieusement du tri interne de la fonction appelée.
        cedar_files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        if cedar_files.is_empty() {
            return Err(PdpLoadError::Policies(
                "aucun fichier .cedar dans le corpus".to_string(),
            ));
        }

        let bundle = cedar_files
            .iter()
            .map(|(_, c)| c.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let policies = bundle
            .parse::<PolicySet>()
            .map_err(|e| PdpLoadError::Policies(e.to_string()))?;

        let corpus_files: Vec<zs_crypto::decision_binding::CorpusFile<'_>> = cedar_files
            .iter()
            .map(|(name, contents)| zs_crypto::decision_binding::CorpusFile {
                relative_path: name.as_str(),
                contents: contents.as_str(),
            })
            .collect();
        let binding = zs_crypto::decision_binding::bind_policy_corpus(
            &schema_json,
            CEDAR_ENGINE_VERSION,
            &corpus_files,
        )?;

        Ok(Self {
            schema,
            policies,
            policy_version: binding.to_hex_string(),
            authorizer: Authorizer::new(),
        })
    }

    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Évalue une décision. Ne retourne jamais d'erreur Rust : un refus (traduction impossible,
    /// version de politique demandée indisponible, ou refus Cedar) est une `DecisionResponse`
    /// normale à `effect: EFFECT_DENY` (P2).
    pub fn decide(&self, request: &DecisionRequest) -> DecisionResponse {
        let decision_hash = zs_crypto::decision_binding::bind_request(&request_to_json(request))
            .as_bytes()
            .to_vec();

        if !request.policy_version.is_empty() && request.policy_version != self.policy_version {
            // Jamais un repli silencieux sur la version actuellement chargée (P2) : la version
            // demandée n'est pas honorée si elle n'est pas exactement celle servie ici.
            return deny(
                vec!["policy_version_indisponible".to_string()],
                decision_hash,
                self.policy_version.clone(),
            );
        }

        let (cedar_request, entities) = match translate(request, &self.schema) {
            Ok(pair) => pair,
            Err(reason) => return deny(vec![reason], decision_hash, self.policy_version.clone()),
        };

        let response = self
            .authorizer
            .is_authorized(&cedar_request, &self.policies, &entities);
        let effect = match response.decision() {
            Decision::Allow => Effect::Allow,
            Decision::Deny => Effect::Deny,
        };
        // `PolicySet::from_str` attribue des identifiants auto-générés ("policy0", "policy1", …)
        // — l'annotation `@id("...")` du corpus (policies/CLAUDE.md, en-tête obligatoire) n'est
        // PAS l'identifiant interne, seulement une métadonnée. Sans ce remappage, les raisons
        // exposées ici divergeraient des identifiants stables référencés par les règles Sigma de
        // L2.1 (ex. `guardrail-authority-domain-isolation`) — traçabilité cassée silencieusement.
        let reasons = response
            .diagnostics()
            .reason()
            .map(|id| {
                self.policies
                    .annotation(id, "id")
                    .map(str::to_string)
                    .unwrap_or_else(|| id.to_string())
            })
            .collect();

        DecisionResponse {
            effect: effect as i32,
            reasons,
            max_ttl: None,
            constraints: vec![],
            decision_hash,
            policy_version: self.policy_version.clone(),
            // Scellement decision-seal/v1 (H4) : pas ici — Pdp::decide reste pur, sans HSM
            // (règle absolue #5). apps/policy-engine scelle après cet appel, avant de renvoyer.
            issued_at: None,
            decision_signature: vec![],
            decision_signature_key_id: String::new(),
        }
    }
}

fn deny(reasons: Vec<String>, decision_hash: Vec<u8>, policy_version: String) -> DecisionResponse {
    DecisionResponse {
        effect: Effect::Deny as i32,
        reasons,
        max_ttl: None,
        constraints: vec![],
        decision_hash,
        policy_version,
        issued_at: None,
        decision_signature: vec![],
        decision_signature_key_id: String::new(),
    }
}

fn entity_uid(type_name: &str, id: &str) -> Result<EntityUid, String> {
    let type_name = format!("{NAMESPACE}::{type_name}")
        .parse::<EntityTypeName>()
        .map_err(|e| format!("type_entite_invalide:{e}"))?;
    let entity_id = EntityId::from_str(id)
        .map_err(|e: std::convert::Infallible| format!("identifiant_invalide:{e}"))?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

fn auth_level_to_str(aal: i32) -> &'static str {
    // Miroir de policy.v1.AuthLevel (decision.proto) : UNSPECIFIED=0 → chaîne vide, jamais
    // interprétée comme un niveau valide (P2, déjà le comportement testé en L2.1).
    match aal {
        1 => "AAL1",
        2 => "AAL2",
        3 => "AAL3",
        _ => "",
    }
}

fn principal_entity(p: &ProtoPrincipal) -> Result<Entity, String> {
    let uid = entity_uid("Principal", &p.subject_id)?;
    let authenticated_at = p
        .authenticated_at
        .as_ref()
        .ok_or_else(|| "principal_authenticated_at_absent".to_string())?
        .seconds;

    let mut attrs = HashMap::new();
    attrs.insert(
        "subject_id".to_string(),
        RestrictedExpression::new_string(p.subject_id.clone()),
    );
    attrs.insert(
        "aal".to_string(),
        RestrictedExpression::new_string(auth_level_to_str(p.aal).to_string()),
    );
    attrs.insert(
        "auth_method".to_string(),
        RestrictedExpression::new_string(p.auth_method.clone()),
    );
    attrs.insert(
        "authenticated_at".to_string(),
        RestrictedExpression::new_long(authenticated_at),
    );
    attrs.insert(
        "roles".to_string(),
        RestrictedExpression::new_set(
            p.roles
                .iter()
                .map(|r| RestrictedExpression::new_string(r.clone())),
        ),
    );
    attrs.insert(
        "authority_domain".to_string(),
        RestrictedExpression::new_string(p.authority_domain.clone()),
    );

    Entity::new(uid, attrs, HashSet::new()).map_err(|e| format!("entite_principal_invalide:{e}"))
}

fn database_entity(r: &ProtoResource) -> Result<Entity, String> {
    let uid = entity_uid("Database", &r.id)?;
    let environment = r
        .attributes
        .get("environment")
        .ok_or_else(|| "resource_attribute_environment_absent".to_string())?;

    let mut attrs = HashMap::new();
    attrs.insert(
        "authority_domain".to_string(),
        RestrictedExpression::new_string(r.authority_domain.clone()),
    );
    attrs.insert(
        "environment".to_string(),
        RestrictedExpression::new_string(environment.clone()),
    );

    Entity::new(uid, attrs, HashSet::new()).map_err(|e| format!("entite_resource_invalide:{e}"))
}

fn build_context(c: &ProtoContext) -> Result<CedarContext, String> {
    let requested_at = c
        .requested_at
        .as_ref()
        .ok_or_else(|| "context_requested_at_absent".to_string())?
        .seconds;
    let posture = c
        .posture
        .as_ref()
        .ok_or_else(|| "context_posture_absent".to_string())?;
    let evaluated_at = posture
        .evaluated_at
        .as_ref()
        .ok_or_else(|| "posture_evaluated_at_absent".to_string())?
        .seconds;

    let posture_record = RestrictedExpression::new_record([
        (
            "managed".to_string(),
            RestrictedExpression::new_bool(posture.managed),
        ),
        (
            "disk_encrypted".to_string(),
            RestrictedExpression::new_bool(posture.disk_encrypted),
        ),
        (
            "agent_version".to_string(),
            RestrictedExpression::new_string(posture.agent_version.clone()),
        ),
        (
            "evaluated_at".to_string(),
            RestrictedExpression::new_long(evaluated_at),
        ),
    ])
    .map_err(|e| format!("contexte_posture_invalide:{e}"))?;

    let mut approvals = Vec::new();
    for a in &c.approvals {
        let approved_at = a
            .approved_at
            .as_ref()
            .ok_or_else(|| "approbation_approved_at_absente".to_string())?
            .seconds;
        // Approval.signature exclue délibérément (contracts/cedar/README.md, écarts assumés) :
        // déjà vérifiée avant l'appel au PDP, jamais réévaluée ici.
        let rec = RestrictedExpression::new_record([
            (
                "approver_id".to_string(),
                RestrictedExpression::new_string(a.approver_id.clone()),
            ),
            (
                "approved_at".to_string(),
                RestrictedExpression::new_long(approved_at),
            ),
        ])
        .map_err(|e| format!("contexte_approbation_invalide:{e}"))?;
        approvals.push(rec);
    }

    CedarContext::from_pairs([
        (
            "requested_at".to_string(),
            RestrictedExpression::new_long(requested_at),
        ),
        (
            "source_network".to_string(),
            RestrictedExpression::new_string(c.source_network.clone()),
        ),
        ("posture".to_string(), posture_record),
        (
            "ticket_ref".to_string(),
            RestrictedExpression::new_string(c.ticket_ref.clone()),
        ),
        (
            "justification".to_string(),
            RestrictedExpression::new_string(c.justification.clone()),
        ),
        (
            "approvals".to_string(),
            RestrictedExpression::new_set(approvals),
        ),
    ])
    .map_err(|e| format!("contexte_invalide:{e}"))
}

/// Traduit un `DecisionRequest` en `(Request, Entities)` Cedar. Un `Resource.type` inconnu ou un
/// attribut manquant produit un refus explicite (chaîne de raison), jamais une entité partielle
/// (`contracts/cedar/README.md`). La validation contre `schema` (passée à `Entities::from_entities`
/// et `Request::new`) couvre aussi une `Action.verb` non déclarée dans le schéma — même principe :
/// une action non encore instruite est un refus explicite de traduction, pas un refus Cedar
/// implicite par absence de politique correspondante.
fn translate(
    request: &DecisionRequest,
    schema: &Schema,
) -> Result<(CedarRequest, Entities), String> {
    let principal = request
        .principal
        .as_ref()
        .ok_or_else(|| "principal_absent".to_string())?;
    let resource = request
        .resource
        .as_ref()
        .ok_or_else(|| "resource_absent".to_string())?;
    let action = request
        .action
        .as_ref()
        .ok_or_else(|| "action_absent".to_string())?;
    let context = request
        .context
        .as_ref()
        .ok_or_else(|| "context_absent".to_string())?;

    if resource.r#type != "Database" {
        return Err(format!("resource_type_inconnu:{}", resource.r#type));
    }

    let principal_uid = entity_uid("Principal", &principal.subject_id)?;
    let principal_ent = principal_entity(principal)?;
    let resource_uid = entity_uid("Database", &resource.id)?;
    let resource_ent = database_entity(resource)?;
    let action_uid = entity_uid("Action", &action.verb)?;
    let cedar_context = build_context(context)?;

    let entities = Entities::from_entities([principal_ent, resource_ent], Some(schema))
        .map_err(|e| format!("entites_invalides:{e}"))?;

    let cedar_request = CedarRequest::new(
        principal_uid,
        action_uid,
        resource_uid,
        cedar_context,
        Some(schema),
    )
    .map_err(|e| format!("requete_invalide:{e}"))?;

    Ok((cedar_request, entities))
}

/// Sous-ensemble canonique du `DecisionRequest`, hors `signature` d'approbation (jamais
/// réévaluée) — sert de base à `decision_hash` (ADR-015). Construit à la main plutôt que via
/// `Serialize` sur les types générés prost (non dérivé ici) : rend explicite quels champs entrent
/// dans l'empreinte, plutôt que de dépendre d'un dérivé qui inclurait tout silencieusement.
fn request_to_json(r: &DecisionRequest) -> serde_json::Value {
    serde_json::json!({
        "request_id": r.request_id,
        "principal": r.principal.as_ref().map(|p| serde_json::json!({
            "subject_id": p.subject_id,
            "aal": p.aal,
            "auth_method": p.auth_method,
            "authenticated_at": p.authenticated_at.as_ref().map(|t| t.seconds),
            "roles": p.roles,
            "authority_domain": p.authority_domain,
        })),
        "action": r.action.as_ref().map(|a| serde_json::json!({ "verb": a.verb })),
        "resource": r.resource.as_ref().map(|res| serde_json::json!({
            "type": res.r#type,
            "id": res.id,
            "authority_domain": res.authority_domain,
            "attributes": res.attributes,
        })),
        "context": r.context.as_ref().map(|c| serde_json::json!({
            "requested_at": c.requested_at.as_ref().map(|t| t.seconds),
            "source_network": c.source_network,
            "posture": c.posture.as_ref().map(|p| serde_json::json!({
                "managed": p.managed,
                "disk_encrypted": p.disk_encrypted,
                "agent_version": p.agent_version,
                "evaluated_at": p.evaluated_at.as_ref().map(|t| t.seconds),
            })),
            "ticket_ref": c.ticket_ref,
            "justification": c.justification,
            "approvals": c.approvals.iter().map(|a| serde_json::json!({
                "approver_id": a.approver_id,
                "approved_at": a.approved_at.as_ref().map(|t| t.seconds),
            })).collect::<Vec<_>>(),
        })),
        "policy_version": r.policy_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::v1::{Action, Approval, Context, DevicePosture, Principal, Resource};
    use std::collections::HashMap as StdHashMap;

    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn schema_path() -> std::path::PathBuf {
        repo_root().join("contracts/cedar/schema.cedarschema.json")
    }

    fn policies_dir() -> std::path::PathBuf {
        repo_root().join("policies/access")
    }

    fn ts(seconds: i64) -> prost_types::Timestamp {
        prost_types::Timestamp { seconds, nanos: 0 }
    }

    fn nominal_request() -> DecisionRequest {
        let mut attrs = StdHashMap::new();
        attrs.insert("environment".to_string(), "production".to_string());

        DecisionRequest {
            request_id: "req-1".to_string(),
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

    #[test]
    fn requete_nominale_est_autorisee() {
        let pdp = Pdp::load(&schema_path(), &policies_dir()).expect("chargement du PDP");
        let response = pdp.decide(&nominal_request());
        assert_eq!(response.effect, Effect::Allow as i32);
        assert!(
            response
                .reasons
                .contains(&"db-connect-production".to_string())
        );
        assert_eq!(response.decision_hash.len(), 32);
        assert_eq!(response.policy_version, pdp.policy_version());
    }

    #[test]
    fn requete_aal2_est_refusee() {
        let pdp = Pdp::load(&schema_path(), &policies_dir()).expect("chargement du PDP");
        let mut req = nominal_request();
        req.principal.as_mut().unwrap().aal = 2;
        let response = pdp.decide(&req);
        assert_eq!(response.effect, Effect::Deny as i32);
    }

    #[test]
    fn type_de_ressource_inconnu_est_refuse_avant_evaluation_cedar() {
        let pdp = Pdp::load(&schema_path(), &policies_dir()).expect("chargement du PDP");
        let mut req = nominal_request();
        req.resource.as_mut().unwrap().r#type = "SshHost".to_string();
        let response = pdp.decide(&req);
        assert_eq!(response.effect, Effect::Deny as i32);
        assert!(response.reasons[0].starts_with("resource_type_inconnu"));
        // Aucun identifiant de politique Cedar : le refus vient de la traduction, pas de
        // l'évaluation (distinction vérifiée explicitement, pas seulement l'effet DENY).
    }

    #[test]
    fn attribut_environment_manquant_est_refuse() {
        let pdp = Pdp::load(&schema_path(), &policies_dir()).expect("chargement du PDP");
        let mut req = nominal_request();
        req.resource.as_mut().unwrap().attributes.clear();
        let response = pdp.decide(&req);
        assert_eq!(response.effect, Effect::Deny as i32);
    }

    #[test]
    fn principal_absent_est_refuse() {
        let pdp = Pdp::load(&schema_path(), &policies_dir()).expect("chargement du PDP");
        let mut req = nominal_request();
        req.principal = None;
        let response = pdp.decide(&req);
        assert_eq!(response.effect, Effect::Deny as i32);
        assert_eq!(response.reasons, vec!["principal_absent".to_string()]);
    }

    #[test]
    fn policy_version_demandee_indisponible_est_refusee() {
        let pdp = Pdp::load(&schema_path(), &policies_dir()).expect("chargement du PDP");
        let mut req = nominal_request();
        req.policy_version =
            "decision-binding/v1:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string();
        let response = pdp.decide(&req);
        assert_eq!(response.effect, Effect::Deny as i32);
        assert_eq!(
            response.reasons,
            vec!["policy_version_indisponible".to_string()]
        );
        // La réponse rapporte quand même la version réellement chargée, jamais celle demandée.
        assert_eq!(response.policy_version, pdp.policy_version());
    }

    #[test]
    fn deux_instances_distinctes_produisent_le_meme_decision_hash() {
        let pdp_a = Pdp::load(&schema_path(), &policies_dir()).expect("chargement du PDP a");
        let pdp_b = Pdp::load(&schema_path(), &policies_dir()).expect("chargement du PDP b");
        let req = nominal_request();
        let response_a = pdp_a.decide(&req);
        let response_b = pdp_b.decide(&req);
        assert_eq!(response_a.decision_hash, response_b.decision_hash);
        assert_eq!(response_a.policy_version, response_b.policy_version);
        assert_eq!(response_a.effect, response_b.effect);
    }
}
