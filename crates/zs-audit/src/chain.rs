//! Vérification de chaîne (backlog L1.4a). Opère sur des octets **opaques** — les octets
//! canoniques complets d'un événement déjà scellé, signature incluse (`contracts/events/
//! audit-event.schema.json::prev_hash`) — sans connaître leur structure interne : la vérification
//! de chaîne ne dépend d'aucune primitive de signature et reste testable avant que le scellement
//! (`zs_crypto::audit_seal`, L1.4b) n'existe. Les tests fabriquent ces octets directement (jamais
//! via une API publique qui les ferait passer pour un événement réel — voir `record.rs`).
//!
//! Le hachage lui-même passe par `zs_crypto` (règle absolue #4 du `CLAUDE.md` racine) :
//! `authenticator_proof::sha256` est déjà une façade générique ("toute opération cryptographique,
//! y compris le hachage, passe par cette façade" — doc du module), réutilisée ici plutôt que
//! dupliquée sous un autre nom.

use std::collections::HashMap;

/// Racine de la chaîne : 64 zéros (`contracts/events/audit-event.schema.json::prev_hash`).
pub const CHAIN_ROOT: [u8; 32] = [0u8; 32];

/// Empreinte d'un événement déjà scellé, avec la position qu'il occupe dans sa chaîne de
/// domaine. `sealed_bytes` est opaque pour ce module (voir mise en garde du module).
#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub authority_domain: String,
    pub sequence: u64,
    pub prev_hash: [u8; 32],
    pub sealed_bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("chaîne vide")]
    Empty,
    #[error("le premier événement du domaine '{0}' n'a pas la racine attendue (64 zéros)")]
    InvalidRoot(String),
    #[error("le premier événement du domaine '{0}' n'a pas la séquence 0 (trouvé {1})")]
    FirstSequenceNotZero(String, u64),
    #[error(
        "séquence non strictement croissante dans le domaine '{domain}' : {previous} -> {found}"
    )]
    SequenceGap {
        domain: String,
        previous: u64,
        found: u64,
    },
    #[error("prev_hash incohérent au rang {index} du domaine '{domain}' — chaîne rompue")]
    BrokenLink { domain: String, index: usize },
}

/// Empreinte SHA-256 des octets canoniques d'un événement scellé — la façade de hachage vit dans
/// `zs-crypto` (règle absolue #4), ce module ne fait que l'invoquer.
pub fn hash_sealed_event(sealed_bytes: &[u8]) -> [u8; 32] {
    zs_crypto::authenticator_proof::sha256(sealed_bytes)
}

/// Vérifie l'intégrité d'une chaîne d'événements, domaine d'autorité par domaine d'autorité :
/// racine correcte pour le premier événement de chaque domaine, séquence strictement croissante
/// à partir de 0, `prev_hash` cohérent avec l'empreinte de l'événement précédent du même domaine.
///
/// **Ce que cette fonction ne détecte pas, par construction** (limite assumée, pas un oubli) :
/// une troncature en queue de chaîne (supprimer les N derniers événements d'un domaine laisse
/// une chaîne parfaitement valide à ses propres yeux). Seul un ancrage périodique publié à
/// l'extérieur (`event_type: "audit.chain_verified"`, déjà réservé au contrat) peut la détecter
/// — hors périmètre L1.4a.
pub fn verify_chain(entries: &[ChainEntry]) -> Result<(), ChainError> {
    if entries.is_empty() {
        return Err(ChainError::Empty);
    }

    let mut last_by_domain: HashMap<&str, (u64, Vec<u8>)> = HashMap::new();

    for (index, entry) in entries.iter().enumerate() {
        match last_by_domain.get(entry.authority_domain.as_str()) {
            None => {
                if entry.prev_hash != CHAIN_ROOT {
                    return Err(ChainError::InvalidRoot(entry.authority_domain.clone()));
                }
                if entry.sequence != 0 {
                    return Err(ChainError::FirstSequenceNotZero(
                        entry.authority_domain.clone(),
                        entry.sequence,
                    ));
                }
            }
            Some((prev_sequence, prev_sealed_bytes)) => {
                if entry.sequence != prev_sequence + 1 {
                    return Err(ChainError::SequenceGap {
                        domain: entry.authority_domain.clone(),
                        previous: *prev_sequence,
                        found: entry.sequence,
                    });
                }
                if entry.prev_hash != hash_sealed_event(prev_sealed_bytes) {
                    return Err(ChainError::BrokenLink {
                        domain: entry.authority_domain.clone(),
                        index,
                    });
                }
            }
        }
        last_by_domain.insert(
            &entry.authority_domain,
            (entry.sequence, entry.sealed_bytes.clone()),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(domain: &str, sequence: u64, prev_hash: [u8; 32], payload: &[u8]) -> ChainEntry {
        ChainEntry {
            authority_domain: domain.to_string(),
            sequence,
            prev_hash,
            sealed_bytes: payload.to_vec(),
        }
    }

    // --- cas nominal -------------------------------------------------------------------------
    #[test]
    fn chaine_valide_est_acceptee() {
        let e0 = entry("identity-provider", 0, CHAIN_ROOT, b"evenement-0-scelle");
        let h0 = hash_sealed_event(&e0.sealed_bytes);
        let e1 = entry("identity-provider", 1, h0, b"evenement-1-scelle");
        let h1 = hash_sealed_event(&e1.sealed_bytes);
        let e2 = entry("identity-provider", 2, h1, b"evenement-2-scelle");

        assert!(verify_chain(&[e0, e1, e2]).is_ok());
    }

    #[test]
    fn deux_domaines_independants_sont_acceptes() {
        let a0 = entry("identity-provider", 0, CHAIN_ROOT, b"a-0");
        let b0 = entry("policy-engine", 0, CHAIN_ROOT, b"b-0");
        let ha0 = hash_sealed_event(&a0.sealed_bytes);
        let a1 = entry("identity-provider", 1, ha0, b"a-1");

        assert!(verify_chain(&[a0, b0, a1]).is_ok());
    }

    // --- refus obligatoires ------------------------------------------------------------------
    #[test]
    fn chaine_vide_est_refusee() {
        assert_eq!(verify_chain(&[]).unwrap_err(), ChainError::Empty);
    }

    #[test]
    fn racine_incorrecte_est_refusee() {
        let bogus_root = [0xAAu8; 32];
        let e0 = entry("identity-provider", 0, bogus_root, b"e0");
        assert_eq!(
            verify_chain(&[e0]).unwrap_err(),
            ChainError::InvalidRoot("identity-provider".to_string())
        );
    }

    #[test]
    fn premiere_sequence_non_nulle_est_refusee() {
        let e0 = entry("identity-provider", 5, CHAIN_ROOT, b"e0");
        assert_eq!(
            verify_chain(&[e0]).unwrap_err(),
            ChainError::FirstSequenceNotZero("identity-provider".to_string(), 5)
        );
    }

    #[test]
    fn trou_de_sequence_est_refuse() {
        let e0 = entry("identity-provider", 0, CHAIN_ROOT, b"e0");
        let h0 = hash_sealed_event(&e0.sealed_bytes);
        let e2 = entry("identity-provider", 2, h0, b"e2"); // saute la séquence 1

        assert_eq!(
            verify_chain(&[e0, e2]).unwrap_err(),
            ChainError::SequenceGap {
                domain: "identity-provider".to_string(),
                previous: 0,
                found: 2,
            }
        );
    }

    #[test]
    fn sequence_dupliquee_est_refusee() {
        let e0 = entry("identity-provider", 0, CHAIN_ROOT, b"e0");
        let h0 = hash_sealed_event(&e0.sealed_bytes);
        let e0_bis = entry("identity-provider", 0, h0, b"e0-bis"); // rejoue la séquence 0

        assert_eq!(
            verify_chain(&[e0, e0_bis]).unwrap_err(),
            ChainError::SequenceGap {
                domain: "identity-provider".to_string(),
                previous: 0,
                found: 0,
            }
        );
    }

    #[test]
    fn prev_hash_incoherent_est_refuse() {
        let e0 = entry("identity-provider", 0, CHAIN_ROOT, b"e0");
        let mauvais_hash = [0x11u8; 32]; // ne correspond pas à hash_sealed_event(e0.sealed_bytes)
        let e1 = entry("identity-provider", 1, mauvais_hash, b"e1");

        assert_eq!(
            verify_chain(&[e0, e1]).unwrap_err(),
            ChainError::BrokenLink {
                domain: "identity-provider".to_string(),
                index: 1,
            }
        );
    }

    #[test]
    fn troncature_en_queue_de_chaine_nest_pas_detectee() {
        // Limite assumée et documentée, pas un oubli : une chaîne tronquée reste valide à ses
        // propres yeux. Ce test prouve que la limite existe réellement (pas seulement affirmée
        // en commentaire), pour qu'un futur changement de comportement soit visible.
        let e0 = entry("identity-provider", 0, CHAIN_ROOT, b"e0");
        let h0 = hash_sealed_event(&e0.sealed_bytes);
        let e1 = entry("identity-provider", 1, h0, b"e1");
        let h1 = hash_sealed_event(&e1.sealed_bytes);
        let e2 = entry("identity-provider", 2, h1, b"e2");

        // La chaîne complète est valide...
        assert!(verify_chain(&[e0.clone(), e1.clone(), e2]).is_ok());
        // ... et la chaîne tronquée (e2 supprimé) l'est tout autant, indétectable par ce
        // vérificateur seul.
        assert!(verify_chain(&[e0, e1]).is_ok());
    }
}
