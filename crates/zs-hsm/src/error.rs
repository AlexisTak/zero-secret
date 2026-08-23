//! Sémantique de refus (ADR-011). Aucune variante n'est rattrapable en « autoriser quand même » —
//! toute erreur remonte jusqu'à l'appelant métier et fait échouer l'action (règles absolues #2
//! et #9 du `CLAUDE.md` racine). Pas de `Debug` dérivé sur les types qui pourraient exposer un
//! PIN — vérifié ci-dessous champ par champ, pas supposé.

use crate::mechanism::SigningMechanism;

#[derive(Debug, thiserror::Error)]
pub enum HsmError {
    #[error("contexte PKCS#11 non initialisé")]
    NotInitialized,
    #[error("jeton absent ou retiré")]
    TokenAbsent,
    #[error("session perdue — reconnexion à la prochaine acquisition, jamais en cours d'opération")]
    SessionLost,
    #[error("non authentifié auprès du jeton (PIN incorrect ou session non ouverte)")]
    NotLoggedIn,
    #[error("clé '{0}' absente du jeton ou non unique")]
    KeyNotFound(String),
    #[error("mécanisme {0:?} non offert par ce jeton")]
    MechanismUnsupported(SigningMechanism),
    #[error("pool de sessions saturé — délai d'acquisition dépassé")]
    PoolExhausted,
    #[error("erreur matérielle ou pilote PKCS#11")]
    DeviceError,
}
