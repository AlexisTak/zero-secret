//! Politique d'attestation — backlog L1.1 : « configurable, refus par défaut si non satisfaite ».

/// Politique d'acceptation de l'attestation à l'enregistrement.
///
/// `Required` est l'option la plus stricte : une attestation `fmt: "none"` (aucune preuve de
/// provenance du matériel) est refusée. `Any` accepte `none` ou `packed`. Il n'existe pas de
/// variante « désactivée » qui accepterait un format non supporté : les formats hors `none`
/// et `packed` sont toujours refusés, quelle que soit la politique (ADR-006) — la politique ne
/// choisit pas les formats supportés, seulement si `none` suffit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttestationPolicy {
    /// Accepte `none` (aucune attestation) ou `packed`.
    #[default]
    Any,
    /// Exige une attestation `packed` — refuse `none`.
    Required,
}
