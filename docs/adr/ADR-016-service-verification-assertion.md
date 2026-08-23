# ADR-016 — Service de vérification d'assertion d'identité (H3, prérequis L2.3)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique

## Contexte

L2.3 (`access-broker`, Go) doit vérifier `Approval.signature` — décision déjà actée de réutiliser
`identity-assertion/v1` : l'approbateur s'authentifie en WebAuthn comme n'importe quel principal,
produit une assertion signée. Mais ADR-001 pose la frontière Rust/Go comme **réseau (gRPC), jamais
FFI** — `access-broker` ne peut donc jamais appeler `zs_crypto::identity_assertion::verify()`
directement. `identity-provider`, propriétaire de cette suite depuis L1.2c, était jusqu'ici un
stub vide : aucun contrat proto, aucun serveur réel. H3 livre exactement ce que L2.2 a livré pour
`policy-engine`, mais côté vérification d'assertion.

## Décisions

### Nouveau contrat `identity.v1` : `AssertionVerificationService.VerifyAssertion`

`contracts/proto/identity/v1/assertion_verification.proto`. Même discipline que `decision.proto`
(ADR-015) : un refus cryptographique n'est **jamais** une erreur gRPC (P2 — le refus est la
réponse), seulement `valid: false` + `reason` catégorisée (mêmes catégories que
`identity_assertion::VerifyError`, traduites en chaînes stables — jamais un message qui
exposerait un détail exploitable pour affiner une attaque). Erreur gRPC réservée à une requête
protobuf malformée, déjà écartée par `tonic` avant d'atteindre le code applicatif.

### Nouveau crate `crates/zs-identity`, miroir exact de `zs-policy`

Types générés uniquement (`tonic-prost-build`, même patron qu'ADR-004 pour `zs-policy`), aucune
logique. `apps/identity-provider` porte la traduction et appelle
`zs_crypto::identity_assertion::verify` — **aucune ligne de cryptographie nouvelle**, uniquement
du câblage gRPC autour d'une fonction déjà existante et testée (L1.2c).

### Clé de vérification par variables d'environnement — provisoire, signalé

`ZS_IDP_VERIFYING_KEY_HEX`/`ZS_IDP_VERIFYING_KEY_ID` (point SEC1 non compressé, hex) au démarrage,
échec dur si absentes/malformées (même patron que `policy-engine::Pdp::load`, R2). **La
distribution réelle de cette clé publique (rotation, bundle de confiance entre composants) n'est
pas conçue ici** — mécanisme opérationnel à instruire plus tard, vraisemblablement par
`admin-api`/une PKI interne, pas improvisé dans ce lot pour ne pas figer un choix non instruit.

### `identity-provider` prend le patron `lib.rs`/`main.rs` de `policy-engine`

Logique dans `lib.rs` (`serve(addr, key)`), binaire mince dans `main.rs` — permet à `tests/` de
démarrer une vraie instance et de l'interroger avec un vrai client `tonic`, sans dépendance
croisée `apps/`. Deuxième serveur réseau réel du dépôt après `policy-engine` (L2.2).

### `AcceptancePolicy.now` construit depuis l'horloge système, pas reçu en entrée

Différence assumée avec le PDP (L2.2), où tout le contexte arrive en entrée (règle absolue #5,
rejeu hors ligne). Une vérification d'assertion en ligne **est** l'appel réseau : sa fraîcheur
dépend nécessairement de l'instant de l'appel, pas d'une valeur fournie par l'appelant (qui
pourrait sinon prétendre vérifier « à » une date choisie pour contourner l'expiration). Aucune
dépendance de calendrier (`chrono`/`time`) ajoutée pour formater cet horodatage : le format RFC
3339 exigé par `zs_crypto::common::Timestamp` est fixe et étroit
(`AAAA-MM-JJThh:mm:ssZ`, UTC, sans fraction), couvert par un calcul manuel
(`civil_from_days`, algorithme public Howard Hinnant), testé sur l'epoch et une date connue —
pas de calcul calendaire général requis pour justifier une nouvelle dépendance (règle absolue
#10).

### gRPC en clair — mTLS explicitement hors périmètre de H3

Aucune intégration SPIFFE/SPIRE n'existe dans le dépôt. Décision validée par l'utilisateur :
servir ce lot en gRPC non chiffré (dev/local uniquement), signalé dans le code (`main.rs`) et ici
— jamais un déploiement de production sans mTLS. Prérequis distinct, à traiter avant l'ouverture
réelle de L2.3 côté `access-broker` ou dans un H-lot dédié.

### Fixture de test signée sans dépendance `sha2` supplémentaire dans le test

Le test d'intégration (`apps/identity-provider/tests/verify_assertion_integration.rs`) reconstruit
un document `identity-assertion/v1` à la main (le harnais `MockSigner` de
`crates/zs-crypto/src/identity_assertion.rs` est privé à ce crate, non réutilisable tel quel
depuis un autre crate). Signature produite via `p256::ecdsa::signature::Signer::sign` (hache en
SHA-256 puis signe le prehash, RFC 6979) plutôt que `sign_prehash` + un digest calculé à la main —
équivalent mathématiquement, évite une dépendance `sha2` supplémentaire dans le test pour la
signature elle-même (`sha2` reste utilisé pour la dérivation de `key_id`, seul endroit où un hash
explicite est nécessaire). Bloc confiné dans `mod tests { ... }` : exemption documentée de
`tools/lib/check-no-direct-crypto.sh` (un test qui simule un acteur externe peut légitimement
fabriquer une signature de test).

## Conséquences

**Positives** — `access-broker` (L2.3) aura un service réel à appeler, pas une esquisse. Le
patron `lib.rs`/`main.rs` + test d'intégration réel (établi en L2.2) se répète, cohérent dans tout
le dépôt. Aucune nouvelle ligne de cryptographie : la surface auditable de `zs-crypto` reste
inchangée.

**Négatives** — la distribution de la clé de vérification par variable d'environnement est un
mécanisme provisoire qui devra être remplacé avant toute mise en production réelle (rotation
absente, pas de révocation). gRPC en clair reste un vrai gap de sécurité en dehors du
développement local — acceptable seulement parce qu'aucun déploiement réel ne s'appuie encore sur
ce service.

**Surface d'attaque** — `AssertionVerificationService` est exposé à un appelant réseau non
authentifié dans ce lot ; acceptable uniquement en développement local, jamais au-delà.

## Critère de réexamen

Réexaminer la distribution de clé et le chiffrement de transport à l'ouverture réelle de L2.3
(`access-broker` consommant ce service en dehors d'un environnement de développement) — mTLS/SPIFFE
devient alors un prérequis bloquant, pas une note en marge.
