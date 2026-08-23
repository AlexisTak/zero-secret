//! Mécanismes de signature autorisés — énumérés, jamais un `cryptoki::mechanism::Mechanism`
//! réexporté (ADR-011) : si `zs-crypto` choisissait un algorithme via ce type, l'invariant 2 de
//! `zs-crypto/CLAUDE.md` (« l'API expose des intentions, pas des algorithmes ») serait contourné
//! par ce crate plutôt que respecté. Ajouter une variante ici est une modification de suite —
//! validation humaine et ADR requis, comme pour toute évolution de `zs-crypto`.

/// Fermé volontairement à `EcdsaP256Sha256` en v1. `MlDsa65` sera ajoutée avec la cible
/// hybride `v2` (ADR-007/010) — pas avant, et pas par un contributeur qui l'ajouterait seul.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMechanism {
    EcdsaP256Sha256,
}
