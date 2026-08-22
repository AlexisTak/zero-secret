//! Contrats de persistance requis par une cérémonie WebAuthn — traits seulement, **aucune
//! implémentation ici** (scope-cut cohérent avec L1.1 : bibliothèque seule, pas de pilote DB
//! réel ni de serveur HTTP). Posés maintenant sur mise en garde `referent-crypto` : la
//! sémantique exacte (atomicité) est une exigence de sécurité, pas un détail d'implémentation
//! à trancher plus tard.
//!
//! `identity-provider` (ou tout appelant) doit fournir une implémentation réelle avant de
//! brancher `verify_authentication_ceremony` sur un vrai flux réseau ; ce crate ne l'exige
//! pas comme paramètre (la fonction reste pure — même style que `verify_registration_ceremony`,
//! qui ne consulte pas non plus de challenge store lui-même).

use zs_crypto::authenticator_proof::Challenge;

/// Consommation d'un challenge de cérémonie. **Doit être une opération atomique unique**
/// (ex. `UPDATE ... WHERE used_at IS NULL RETURNING ...` côté PostgreSQL), jamais un
/// `get` puis `set` séparés : c'est exactement la fenêtre TOCTOU qui rend le rejeu de
/// challenge réellement exploitable en concurrence, pas une négligence de style
/// (mise en garde `referent-crypto`, cf. commentaire de `deploy/migrations/003_*`).
pub trait ChallengeStore {
    type Error;

    /// Consomme le challenge s'il existe, n'a pas expiré et n'a jamais été utilisé. Toute
    /// autre situation (absent, expiré, déjà consommé) doit renvoyer `Ok(None)` — un refus,
    /// jamais une erreur qui distinguerait les cas pour un attaquant (pas d'oracle).
    fn consume(&self, challenge: &Challenge) -> Result<Option<()>, Self::Error>;
}

/// Avance atomique du compteur de signature. **Doit comparer et écrire en une seule opération**
/// (ex. `UPDATE ... SET sign_count = $received WHERE sign_count < $received RETURNING ...`),
/// jamais un `get` puis `set` séparés — même risque TOCTOU que `ChallengeStore::consume`, mais
/// sur le signal qui détecte un clonage d'authentificateur plutôt que sur le rejeu.
pub trait SignCounterStore {
    type Error;

    /// Renvoie `Ok(true)` si l'avance a été acceptée et écrite, `Ok(false)` si `received` ne
    /// représente pas une progression stricte (régression ou compteur identique — clonage
    /// suspecté, à traiter comme un refus par l'appelant, pas une simple non-avance silencieuse).
    fn advance(&self, credential_id: &[u8], received: u32) -> Result<bool, Self::Error>;
}
