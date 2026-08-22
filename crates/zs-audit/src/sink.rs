//! Réception d'un événement d'audit — trait seulement, **aucune implémentation ici** (même
//! scope-cut que `zs-webauthn::store` : bibliothèque, pas de pilote DB/réseau réel). La
//! sémantique d'atomicité de l'ajout à la chaîne (`AuditChainStore`) est posée maintenant, sur
//! le même modèle que `SignCounterStore` (L1.2) — comparer et écrire en une seule opération,
//! jamais un `get` puis `set` séparés, sinon deux écrivains concurrents peuvent forker la chaîne
//! silencieusement (chaque branche individuellement valide).

use crate::record::AuditRecord;

/// Puits d'un événement d'audit. `record` prend possession du contenu métier — l'implémentation
/// réelle (non fournie ici) est responsable de le canonicaliser, le sceller
/// (`zs_crypto::audit_seal`, L1.4b) et l'ajouter à la chaîne via `AuditChainStore`.
pub trait AuditSink {
    type Error;
    type Receipt;

    fn record(&self, record: AuditRecord) -> Result<Self::Receipt, Self::Error>;
}

/// Ajout atomique à la chaîne d'un domaine d'autorité. **Doit comparer et écrire en une seule
/// opération** (ex. `INSERT ... WHERE sequence = $expected` avec contrainte d'unicité sur
/// `(authority_domain, sequence)`), jamais un `get` du dernier `prev_hash` puis un `set` séparés
/// — la fenêtre TOCTOU entre les deux permettrait à deux écrivains concurrents d'obtenir le même
/// `prev_hash` et de forker la chaîne, chaque branche restant individuellement valide pour
/// `crate::chain::verify_chain`.
pub trait AuditChainStore {
    type Error;

    /// Renvoie `Err` si `expected_prev_hash` ne correspond plus à la tête réelle de la chaîne du
    /// domaine au moment de l'écriture (conflit de concurrence) — à traiter comme un refus par
    /// l'appelant, **jamais un ré-essai silencieux qui renumérotwerait** l'événement (cf.
    /// mise en garde `referent-crypto` : un ré-essai qui réattribue une séquence produit un trou
    /// ou un doublon).
    fn append(
        &self,
        authority_domain: &str,
        expected_prev_hash: [u8; 32],
        sealed_bytes: Vec<u8>,
    ) -> Result<u64, Self::Error>;
}

/// Enregistre un événement via un puits donné, sans avaler silencieusement une erreur — c'est
/// le point exact du critère d'acceptation du backlog L1.4 : *aucune action ne réussit sans
/// produire son événement d'audit*. Ce petit adaptateur existe pour que ce soit vrai par
/// construction (l'erreur se propage) plutôt que par discipline d'appel.
pub fn record_or_fail<S: AuditSink>(sink: &S, record: AuditRecord) -> Result<S::Receipt, S::Error> {
    sink.record(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Actor, ActorKind, EventType, Outcome};
    use std::cell::RefCell;

    fn sample_record(event_type: EventType) -> AuditRecord {
        AuditRecord {
            occurred_at: "2026-08-22T10:00:00Z".to_string(),
            authority_domain: "identity-provider".to_string(),
            event_type,
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

    /// Double de test qui compte les événements reçus — jamais utilisé hors des tests, jamais
    /// exporté. Prouve le critère d'acceptation par comptage, pas par relecture.
    struct CountingSink {
        received: RefCell<Vec<EventType>>,
    }

    impl CountingSink {
        fn new() -> Self {
            Self {
                received: RefCell::new(Vec::new()),
            }
        }
    }

    impl AuditSink for CountingSink {
        type Error = ();
        type Receipt = ();

        fn record(&self, record: AuditRecord) -> Result<(), ()> {
            self.received.borrow_mut().push(record.event_type);
            Ok(())
        }
    }

    /// Double de test qui échoue systématiquement — preuve que l'échec du puits n'est jamais
    /// avalé silencieusement.
    struct FailingSink;

    impl AuditSink for FailingSink {
        type Error = &'static str;
        type Receipt = ();

        fn record(&self, _record: AuditRecord) -> Result<(), &'static str> {
            Err("puits d'audit indisponible")
        }
    }

    // --- critère d'acceptation backlog L1.4 : compté, pas relu ------------------------------
    #[test]
    fn chaque_type_devenement_du_parcours_est_compte() {
        let sink = CountingSink::new();
        let event_types = [
            EventType::AuthenticatorRegistered,
            EventType::AuthenticatorRevoked,
            EventType::AuthenticationAttempted,
            EventType::AuthenticationSucceeded,
            EventType::AuthenticationFailed,
            EventType::RecoveryInitiated,
            EventType::QuorumOperation,
        ];

        for event_type in event_types {
            record_or_fail(&sink, sample_record(event_type)).unwrap();
        }

        assert_eq!(sink.received.borrow().len(), event_types.len());
        for event_type in event_types {
            assert!(sink.received.borrow().contains(&event_type));
        }
    }

    // --- refus obligatoire : un puits en échec ne doit jamais laisser croire à un succès ----
    #[test]
    fn echec_du_puits_nest_jamais_avale_silencieusement() {
        let sink = FailingSink;
        let result = record_or_fail(&sink, sample_record(EventType::AuthenticationFailed));
        assert_eq!(result.unwrap_err(), "puits d'audit indisponible");
    }
}
