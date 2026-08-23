# Inventaire cryptographique (CBOM)

Trajectoire post-quantique du projet, exigée par le CRA et l'échéance ANSSI 2027 (à partir de
2027, l'ANSSI cesse d'accepter en qualification les produits sans composante post-quantique —
voir `crates/zs-crypto/CLAUDE.md`).

## Fichiers

- **`suites.toml`** — source de vérité, éditée à la main, revue humaine. Une suite ajoutée à
  `crates/zs-crypto` sans entrée ici fait échouer `make test-arch`
  (`tools/lib/check-cbom-coverage.sh`, ADR-011) — invariant 9 de `crates/zs-crypto/CLAUDE.md`.
- **`cbom.json`** — dérivé, format CycloneDX 1.6 (`cryptographic-asset`). Régénéré par
  `make sbom` (`tools/generate-cbom.sh`). **Ne jamais l'éditer directement** : toute modification
  manuelle sera écrasée à la prochaine régénération et divergera silencieusement de `suites.toml`
  en attendant.

## Qui met à jour

Quiconque ajoute ou modifie une suite dans `crates/zs-crypto` (nouvelle intention, changement
d'algorithme, passage à une version hybride `v2`) — dans la même contribution que le code,
jamais après coup. Toute modification de `zs-crypto` passe par `referent-crypto` et une
validation humaine explicite (voir `crates/zs-crypto/CLAUDE.md`).

## Comment lire

Chaque suite déclare son rôle (`verification` ou `emission` — seules les suites d'émission sont
pleinement soumises à l'invariant d'hybridation stricte, voir ADR-006 pour l'exception
`authenticator-proof`), son environnement d'exécution (`software` ou `hardware` — `hardware`
matérialise l'invariant 7 : aucune clé privée ne quitte le HSM), et son statut de conformité
ANSSI 2027 (`anssi_2027_compliant`). Les trois suites `v1` actuelles sortent toutes `false` —
**c'est voulu et lisible** : le CBOM doit rendre la dette PQC visible, pas la maquiller. C'est le
document qu'un CESTI ou un RSSI lira en premier.
