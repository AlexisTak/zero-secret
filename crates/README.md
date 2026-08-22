# crates/

Bibliothèques Rust internes, partagées entre les composants de `apps/`. Édition 2024,
`#![forbid(unsafe_code)]` partout sauf `zs-hsm` (FFI PKCS#11, justifié par ADR).

| Crate | Rôle |
|---|---|
| `zs-crypto` | Façade unique vers les bibliothèques cryptographiques auditées. Toute opération crypto du dépôt passe par ici — voir [zs-crypto/CLAUDE.md](zs-crypto/CLAUDE.md) |
| `zs-webauthn` | Vérification WebAuthn/FIDO2 : attestation, assertion, challenge |
| `zs-policy` | Types et évaluation partagés du moteur de politiques (Cedar) |
| `zs-audit` | Construction, chaînage et signature des événements d'audit |
| `zs-hsm` | Intégration PKCS#11 (SoftHSM2 en dev). Seul crate autorisé à l'`unsafe` (FFI) |

Aucun autre module du dépôt n'importe `ring`, `rustls`, `aws-lc-rs`, `p256`, `ed25519-*` ou
équivalent directement — le hook `no-direct-crypto` bloque la violation.
