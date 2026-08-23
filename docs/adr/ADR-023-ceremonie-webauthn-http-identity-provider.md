# ADR-023 — Endpoints HTTP de cérémonie WebAuthn (`identity-provider`, H5)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

L2.6 (`console-web`) vient d'être débloqué (ADR-022, PR #29) mais l'exploration a révélé un
trou structurel : `identity-provider` ne fait que **vérifier** une assertion
`identity-assertion/v1` déjà produite (gRPC `AssertionVerificationService`, H3, ADR-016).
`crates/zs-webauthn` ne contient que des vérificateurs de cérémonie
(`verify_registration_ceremony`/`verify_authentication_ceremony`, fonctions pures) et des
traits de store sans implémentation (`ChallengeStore::consume`, `SignCounterStore::advance`,
`crates/zs-webauthn/src/store.rs`). Aucun composant du dépôt n'émet de challenge WebAuthn ni
n'accepte le résultat de `navigator.credentials.create()`/`.get()` par HTTP — sans ça,
`console-web` ne peut faire authentifier aucun utilisateur réel. H5 livre ce prérequis avant
d'ouvrir L2.6.

## Décisions

### `sqlx` — premier driver Postgres du dépôt

Validé avec `referent-crypto` : paramètres liés systématiques (pas de concaténation possible),
TLS via `rustls` (pas d'OpenSSL dans le graphe), scopé à `apps/identity-provider`. Requêtes non
préparées à la compilation (`sqlx::query`, pas `query!`) — l'alternative `query!` exigerait une
infrastructure `.sqlx` (cache hors ligne ou base disponible au build) non encore mise en place
dans ce dépôt ; report à une contribution dédiée si le besoin se généralise. `rustls` n'apparaît
dans aucun motif de `tools/lib/check-no-direct-crypto.sh` — dépendance transitive de `sqlx`,
jamais importée directement par ce crate, aucune extension du hook nécessaire (vérifié).

### Deux pools Postgres, deux rôles, jamais le même pool pour les deux schémas

`identity_app` (schéma `identity` : challenges, authentificateurs) et `audit_writer` (schéma
`audit`, ajout seul) — règle d'architecture déjà actée (`docs/architecture.md` : « aucun rôle
applicatif en écriture sur plus d'un schéma », migration 001). `apps/identity-provider/src/
store.rs` expose `IdentityStore` et `AuditStore`, chacun connecté séparément
(`ZS_IDP_IDENTITY_DATABASE_URL` / `ZS_IDP_AUDIT_DATABASE_URL`).

### `accept_challenge` ajoutée à `crates/zs-crypto::authenticator_proof` (validation explicite)

`Challenge` n'avait qu'un émetteur (`new_challenge`, CSPRNG) — aucun moyen de le reconstruire
depuis des octets persistés. H5 introduit le premier serveur WebAuthn sans état vis-à-vis du
challenge (émis, stocké en base, potentiellement relu par une autre instance après un
redémarrage) : sans constructeur de réhydratation, `ChallengeStore::consume` et les fonctions de
cérémonie sont concrètement inappelables depuis un vrai serveur HTTP. `referent-crypto` a
proposé `accept_challenge(suite, bytes: Vec<u8>) -> Result<Challenge, Error>` (validation de
longueur et de suite, `bytes` pris par valeur pour que l'effacement au drop couvre le tampon lu
en base sans copie intermédiaire non effacée) — validation humaine explicite obtenue avant
implémentation (règle du `CLAUDE.md` de `crates/zs-crypto`). Voir addendum d'ADR-006.

### `axum` — premier serveur HTTP Rust du dépôt

Même esprit qu'ADR-022 côté Go (`net/http` standard, pas de framework de routage lourd) :
`axum` reste minimal (4 routes, extracteurs JSON), retenu plutôt que `hyper` nu parce que la
validation de corps JSON et l'intégration `tokio`/`sqlx` auraient exigé de réimplémenter ce
qu'`axum` fournit déjà. `tonic` (gRPC existant) et `axum` coexistent dans le même binaire via
`tokio::select!` sur un seul runtime multi-thread.

### Authentification par assertion : hors périmètre du bootstrap, angle mort documenté

`RegistrationChallengeRequest.subject_id` est accepté tel quel — aucun mécanisme d'invitation
ou de première authentification n'est instruit dans ce dépôt. Le trancher sans instruction
supplémentaire aurait inventé une politique non voulue (même discipline que H2 : pas de
mécanisme non instruit improvisé). Signalé dans `security/threat-models/identity-provider.md`
et dans le contrat OpenAPI lui-même.

### Scellement de l'assertion **et** de l'événement d'audit dans le même lot (règle #9)

Décidé explicitement avec l'utilisateur : pas de dette « assertion scellée, événement d'audit
différé » — `AuditSealer` (déjà existant, `crates/zs-crypto::audit_seal`, ADR-010/013) est
câblé pour la première fois en appelant réel, même patron que `AssertionSealer` dans
`apps/policy-engine` (H4/ADR-019) pour `DecisionSealer`. Deux clés HSM distinctes, deux
ouvertures au démarrage, deux `key_id` journalisés séparément (jamais la clé elle-même).
Ordre non négociable (R7) : `audit_event_id` (UUIDv7) généré avant le scellement de
l'assertion ; l'événement d'audit qui le couvre porte `SHA-256(assertion)`
(`SealedAssertion::digest()`) en `target`. Si l'ajout à la chaîne d'audit échoue après que
l'assertion a été scellée en mémoire, l'assertion n'est **jamais** renvoyée à l'appelant (503) —
aucune action ne réussit sans son événement d'audit, y compris au sens strict de la réponse
HTTP retournée.

### `audit.events.sealed_bytes` — nouvelle colonne (migration 005)

`audit.events` (migration 002) décompose l'événement en colonnes structurées mais ne conservait
pas les octets canoniques exacts que `zs_audit::chain::hash_sealed_event` doit rehacher pour
calculer le `prev_hash` de l'événement suivant. Les reconstruire depuis les colonnes
décomposées exigerait une seconde implémentation de la canonicalisation JCS hors de
`zs-crypto` — exactement le risque de divergence silencieuse déjà signalé dans le commentaire
de module d'`audit_seal.rs`. Stocker l'opaque (`sealed_bytes bytea`) l'évite : le module de
chaînage ne connaît déjà que des octets opaques. Table vide avant H5 (aucun écrivain réel
n'existait) : ajout sans backfill.

### Rejeu de challenge : consommation atomique, avant toute vérification

`UPDATE identity.challenges SET used_at = now() WHERE challenge = $1 AND ceremony_kind = $2
AND used_at IS NULL AND expires_at > now() RETURNING subject_id` — consommé **avant** l'appel à
`verify_registration_ceremony`/`verify_authentication_ceremony`, jamais après (un échec de
vérification ne doit pas laisser le challenge rejouable). `Ok(None)` couvre absent/expiré/déjà
consommé sans distinction dans la réponse HTTP (pas d'oracle).

### `sign_count` : avance atomique et autoritative, indépendante de la vérification en mémoire

`verify_authentication_ceremony` contrôle déjà la régression sur la valeur lue avant l'appel ;
`IdentityStore::advance_sign_count` (`UPDATE ... WHERE sign_count < $new`) est l'écriture
authoritative qui tranche en dernier ressort sous concurrence (fenêtre TOCTOU entre la lecture
et cette écriture). Un échec ici — alors même que la vérification en mémoire avait réussi —
scelle un événement d'audit dédié (`authentication.failed`, contexte « clonage suspecté »,
requis explicitement par `referent-crypto`) et refuse la requête, même si la cérémonie
cryptographique était par ailleurs valide.

### `zs-hsm` bloquant : `spawn_blocking` autour de chaque appel `seal()`

`zs-hsm` expose une API bloquante (ADR-011). `apps/policy-engine` appelle `seal()` directement
dans son handler gRPC async, sans `spawn_blocking` — un défaut préexistant, hors périmètre de ce
lot, signalé mais non corrigé ici (changerait un composant que ce lot ne touche pas autrement).
H5 n'hérite pas de ce défaut : chaque appel à `AssertionSealer::seal`/`AuditSealer::seal` passe
par `tokio::task::spawn_blocking`, pour ne jamais bloquer le runtime multi-thread partagé avec
le serveur gRPC existant.

### Pas de TLS/mTLS dans ce lot

Même limite que partout ailleurs (L2.2/H3/H4/ADR-022), signalée explicitement dans
`main.rs` et le modèle de menaces.

## Conséquences

**Positives** — `identity-provider` a un vrai chemin d'émission de bout en bout (enregistrement
→ authentification → assertion scellée), testé par un fichier d'intégration réel
(`apps/identity-provider/tests/http_ceremony.rs`, `#[ignore]`, SoftHSM2 + Postgres réels — même
discipline que `crates/zs-hsm/tests/pkcs11_integration.rs`). Aucune primitive cryptographique
nouvelle : composition de fonctions déjà vérifiées (`zs-webauthn`) et scellement déjà existant
(`zs-crypto`), sauf l'ajout ciblé et validé `accept_challenge`.

**Négatives** — pas de TLS. Bootstrap du premier facteur non résolu (angle mort assumé). Pas de
`query!` compile-checked pour `sqlx` (dette d'outillage, pas de sécurité). Le défaut
`spawn_blocking` manquant de `policy-engine` reste non corrigé.

**Surface d'attaque** — nouvelle : 4 endpoints HTTP non authentifiés au niveau transport. Le
risque le plus direct (falsification du `subject_id` d'authentification) est neutralisé par
construction : le `subject_id` d'une assertion vient toujours du credential résolu en base,
jamais du corps de requête. Le risque de panique/blocage HSM non récupéré est absent par
construction (`spawn_blocking` + propagation d'erreur 503, pas de `panic!` atteignable depuis
une entrée réseau).

## Critère de réexamen

Réexaminer le bootstrap du premier facteur dès qu'un mécanisme d'invitation/admin est instruit
(probablement avec L2.6 ou une contribution dédiée). Réexaminer le TLS/mTLS dès que
SPIFFE/SPIRE est câblé. Réexaminer `sqlx::query!`/mode hors ligne si d'autres composants Rust
adoptent Postgres et qu'une infrastructure `.sqlx` partagée devient rentable.
