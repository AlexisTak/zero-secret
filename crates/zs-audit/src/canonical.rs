//! Sérialisation canonique (RFC 8785, JSON Canonicalization Scheme) du contenu d'un événement.
//! **`pub(crate)` seulement** — voir la mise en garde de `record.rs` : aucun appelant externe ne
//! doit pouvoir obtenir ces octets tant que le scellement (`zs_crypto::audit_seal`, L1.4b)
//! n'existe pas, sous peine de produire un objet qui a la forme d'une preuve sans en être une.
//!
//! Construction manuelle de `serde_json::Value` (jamais de `#[derive(Serialize)]` sur
//! `AuditRecord`, voir `record.rs`) : `serde_json::Map` est adossée à une `BTreeMap` par défaut
//! (sans la fonctionnalité cargo `preserve_order`, absente de ce workspace — vérifié) donc les
//! clés sont déjà triées à la sérialisation ; `serde_json::to_vec` ne produit aucun espace
//! superflu. Ces deux propriétés suffisent à la conformité JCS pour un schéma ne contenant que
//! des chaînes, entiers et booléens (pas de nombre à virgule flottante, dont la canonicalisation
//! ECMAScript serait plus délicate).

// Non utilisée hors des tests tant que L1.4b (scellement réel) n'existe pas — c'est le point
// exact de cette contribution (voir mise en garde du crate) : `canonical_bytes` attend son
// premier appelant de production (`zs_crypto::audit_seal::seal`), pas encore écrit.
#![allow(dead_code)]

use crate::record::{AuditRecord, Context, Target};
use serde_json::{Map, Value, json};

pub(crate) fn canonical_bytes(record: &AuditRecord) -> Vec<u8> {
    serde_json::to_vec(&to_canonical_value(record)).expect(
        "la sérialisation d'un AuditRecord ne peut échouer : pas de type non représentable en JSON",
    )
}

fn to_canonical_value(record: &AuditRecord) -> Value {
    let mut map = Map::new();
    map.insert("occurred_at".to_string(), json!(record.occurred_at.clone()));
    map.insert(
        "authority_domain".to_string(),
        json!(record.authority_domain.clone()),
    );
    map.insert(
        "event_type".to_string(),
        json!(record.event_type.as_contract_str()),
    );
    map.insert(
        "actor".to_string(),
        json!({
            "subject_id": record.actor.subject_id,
            "kind": record.actor.kind.as_contract_str(),
            "aal": record.actor.aal,
            "auth_method": record.actor.auth_method,
        }),
    );
    map.insert(
        "target".to_string(),
        record
            .target
            .as_ref()
            .map(target_value)
            .unwrap_or(Value::Null),
    );
    map.insert(
        "outcome".to_string(),
        json!(record.outcome.as_contract_str()),
    );
    map.insert(
        "context".to_string(),
        record
            .context
            .as_ref()
            .map(context_value)
            .unwrap_or(Value::Null),
    );
    Value::Object(map)
}

fn target_value(target: &Target) -> Value {
    json!({ "type": target.target_type, "id": target.id })
}

fn context_value(context: &Context) -> Value {
    json!({
        "source_network": context.source_network,
        "ticket_ref": context.ticket_ref,
        "justification": context.justification,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Actor, ActorKind, EventType, Outcome};

    fn sample() -> AuditRecord {
        AuditRecord {
            occurred_at: "2026-08-22T10:00:00Z".to_string(),
            authority_domain: "identity-provider".to_string(),
            event_type: EventType::AuthenticatorRegistered,
            actor: Actor {
                subject_id: "subject-1".to_string(),
                kind: ActorKind::Human,
                aal: None,
                auth_method: None,
            },
            target: None,
            outcome: Outcome::Success,
            context: None,
        }
    }

    #[test]
    fn deux_appels_sur_le_meme_contenu_produisent_des_octets_identiques() {
        let a = canonical_bytes(&sample());
        let b = canonical_bytes(&sample());
        assert_eq!(a, b);
    }

    #[test]
    fn les_cles_sont_triees_independamment_de_lordre_dinsertion() {
        // Propriété structurelle, pas un détail d'implémentation : si serde_json passait un
        // jour à IndexMap par défaut (feature preserve_order activée ailleurs dans le
        // workspace), ce test échouerait avant que la chaîne d'audit ne devienne
        // silencieusement non déterministe.
        let bytes = canonical_bytes(&sample());
        let text = String::from_utf8(bytes).unwrap();
        let pos_actor = text.find("\"actor\"").unwrap();
        let pos_authority = text.find("\"authority_domain\"").unwrap();
        let pos_occurred = text.find("\"occurred_at\"").unwrap();
        // Ordre lexicographique attendu : actor < authority_domain < occurred_at.
        assert!(pos_actor < pos_authority);
        assert!(pos_authority < pos_occurred);
    }

    #[test]
    fn aucun_espace_superflu() {
        let bytes = canonical_bytes(&sample());
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains(", "));
        assert!(!text.contains(": "));
        assert!(!text.contains('\n'));
    }
}
