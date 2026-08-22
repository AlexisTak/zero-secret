//! Récupération à quorum (backlog L1.3). Une récupération n'est jamais déclenchée par un seul
//! porteur : elle exige `threshold` porteurs **distincts**, chacun ayant produit sa propre
//! preuve d'authentification WebAuthn valide (`verify_authentication_ceremony`, L1.2). Aucune
//! nouvelle opération cryptographique n'est ajoutée à `zs-crypto` par ce module — le quorum
//! réutilise `authenticator-proof/v1` telle quelle, une approbation par porteur.
//!
//! **Liaison à une requête de récupération précise : responsabilité de l'appelant.** Ce module
//! ne garantit que la distinction des porteurs et le seuil ; il ne sait pas — et ne peut pas
//! savoir, la primitive `Challenge` de `zs-crypto` n'exposant aucun constructeur déterministe
//! (volontaire, ADR-006 : un challenge est un CSPRNG, jamais dérivé) — que N approbations
//! portent bien sur la même récupération. C'est à l'appelant (`identity-provider`, à construire)
//! de garantir cette liaison, par exemple en associant chaque challenge d'approbation à un
//! identifiant de requête de récupération dans son propre stockage. Documenté explicitement,
//! pas caché — même style de coupure de périmètre que `crate::store` (ports sans implémentation).
//!
//! **Scellement de l'événement de récupération : différé à L1.4** (audit du parcours). Ce
//! module produit un résultat qui doit être traité comme systématiquement alarmant par
//! l'appelant (`RecoveryOutcome` ne peut être ignoré silencieusement : il ne dérive pas
//! `#[must_use]` par accident, c'est une décision — voir `verify_quorum`), mais ne signe ni ne
//! chaîne aucun événement lui-même : `zs-audit` est un stub vide à ce jour.

use crate::authentication::AuthenticationClaims;
use std::collections::HashSet;

/// Seuil minimal absolu, imposé par ce module et non contournable par l'appelant : même un
/// appelant qui passerait `threshold = 1` par erreur de configuration se voit refuser — c'est
/// le critère d'acceptation du backlog L1.3 (« un seul porteur ne peut jamais déclencher une
/// récupération »), tenu structurellement, pas par convention d'appel.
const MINIMUM_THRESHOLD: usize = 2;

/// Approbation d'un porteur. **Ne peut être construite qu'à partir de `AuthenticationClaims`
/// réellement produites par `verify_authentication_ceremony`** — aucun constructeur ne permet de
/// fabriquer une approbation sans authentification WebAuthn réelle et vérifiée.
pub struct RecoveryApproval(AuthenticationClaims);

impl RecoveryApproval {
    /// Construit une approbation à partir de claims déjà vérifiées. Le seul point d'entrée :
    /// pas de `From<Vec<u8>>` ni d'équivalent qui permettrait de fabriquer une approbation à
    /// partir d'un simple identifiant de porteur sans preuve d'authentification associée.
    pub fn from_verified_authentication(claims: AuthenticationClaims) -> Self {
        Self(claims)
    }

    fn credential_id(&self) -> &[u8] {
        &self.0.credential_id
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecoveryError {
    #[error("seuil de récupération inférieur au minimum absolu ({MINIMUM_THRESHOLD}) — refusé")]
    ThresholdBelowMinimum,
    #[error("quorum non atteint : {distinct} porteur(s) distinct(s) sur {threshold} requis")]
    QuorumNotReached { distinct: usize, threshold: usize },
}

/// Résultat d'une vérification de quorum réussie. **Systématiquement alarmant** : toute
/// récupération, même autorisée, est un événement à traiter comme critique par l'appelant
/// (scellement/chaînage réel différé à L1.4 — voir mise en garde du module). Ce type ne porte
/// intentionnellement aucune méthode qui masquerait cette criticité (pas de `Default`, pas de
/// construction hors de `verify_quorum`).
#[derive(Debug)]
#[must_use = "une récupération autorisée doit être traitée comme un événement critique — voir la mise en garde du module recovery"]
pub struct RecoveryOutcome {
    pub approving_credential_ids: Vec<Vec<u8>>,
}

/// Vérifie qu'un ensemble d'approbations atteint le quorum requis, avec des porteurs
/// **distincts** : un même porteur qui approuverait deux fois (même `credential_id`, par
/// exemple deux ceremonies WebAuthn successives sur le même authentificateur) ne compte qu'une
/// fois — la déduplication est structurelle (`HashSet`), pas une vérification qu'un appelant
/// pourrait oublier de faire.
pub fn verify_quorum(
    approvals: &[RecoveryApproval],
    threshold: usize,
) -> Result<RecoveryOutcome, RecoveryError> {
    if threshold < MINIMUM_THRESHOLD {
        return Err(RecoveryError::ThresholdBelowMinimum);
    }

    let distinct: HashSet<&[u8]> = approvals
        .iter()
        .map(RecoveryApproval::credential_id)
        .collect();

    if distinct.len() < threshold {
        return Err(RecoveryError::QuorumNotReached {
            distinct: distinct.len(),
            threshold,
        });
    }

    Ok(RecoveryOutcome {
        approving_credential_ids: distinct.into_iter().map(|c| c.to_vec()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::Aal;

    fn claims(credential_id: &[u8]) -> AuthenticationClaims {
        AuthenticationClaims {
            subject_id: "subject-1".to_string(),
            credential_id: credential_id.to_vec(),
            aal: Aal::Aal2,
            method: "webauthn/device-bound",
            new_sign_count: 1,
        }
    }

    // --- cas nominal -----------------------------------------------------------------------
    #[test]
    fn quorum_atteint_avec_porteurs_distincts_est_accepte() {
        let approvals = vec![
            RecoveryApproval::from_verified_authentication(claims(b"porteur-a")),
            RecoveryApproval::from_verified_authentication(claims(b"porteur-b")),
        ];

        let outcome = verify_quorum(&approvals, 2).unwrap();
        assert_eq!(outcome.approving_credential_ids.len(), 2);
    }

    // --- refus obligatoires ------------------------------------------------------------------
    #[test]
    fn un_seul_porteur_ne_peut_jamais_declencher_une_recuperation() {
        // Critère d'acceptation du backlog L1.3, tenu même si le seuil est mal configuré.
        let approvals = vec![RecoveryApproval::from_verified_authentication(claims(
            b"porteur-a",
        ))];

        // Même avec threshold=1 explicitement demandé par l'appelant, refusé : le plancher
        // MINIMUM_THRESHOLD n'est pas contournable par configuration.
        assert_eq!(
            verify_quorum(&approvals, 1).unwrap_err(),
            RecoveryError::ThresholdBelowMinimum
        );
    }

    #[test]
    fn meme_porteur_repete_ne_compte_quune_fois() {
        // Deux approbations du même credential_id (ex. deux cérémonies successives sur le même
        // authentificateur) ne doivent jamais faire progresser le quorum : ce n'est toujours
        // qu'un seul porteur.
        let approvals = vec![
            RecoveryApproval::from_verified_authentication(claims(b"porteur-a")),
            RecoveryApproval::from_verified_authentication(claims(b"porteur-a")),
        ];

        assert_eq!(
            verify_quorum(&approvals, 2).unwrap_err(),
            RecoveryError::QuorumNotReached {
                distinct: 1,
                threshold: 2,
            }
        );
    }

    #[test]
    fn quorum_insuffisant_est_refuse() {
        let approvals = vec![RecoveryApproval::from_verified_authentication(claims(
            b"porteur-a",
        ))];

        assert_eq!(
            verify_quorum(&approvals, 2).unwrap_err(),
            RecoveryError::QuorumNotReached {
                distinct: 1,
                threshold: 2,
            }
        );
    }

    #[test]
    fn seuil_zero_est_refuse() {
        let approvals: Vec<RecoveryApproval> = vec![];
        assert_eq!(
            verify_quorum(&approvals, 0).unwrap_err(),
            RecoveryError::ThresholdBelowMinimum
        );
    }
}
