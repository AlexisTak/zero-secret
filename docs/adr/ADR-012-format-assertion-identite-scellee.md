# ADR-012 — Format de l'assertion d'identité scellée (`identity-assertion/v1`)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

ADR-007 réserve la suite `identity-assertion` sans fixer le contenu exact de l'assertion.
ADR-008 pose deux rappels pour son implémentation : R7 (ordre de chaînage avec l'audit,
`audit_event_id` généré avant, assertion scellée le portant, événement scellé portant
`SHA-256(assertion)`) et R8 (le conteneur de signature doit être à N composantes dès `v1`, pour
que l'hybridation `v2` n'y casse rien). ADR-011 livre l'intégration HSM et pose la frontière :
`zs_crypto::identity_assertion::seal` appelle `zs-hsm` en interne, aucun type `zs-hsm`
n'apparaît dans la surface publique de `zs-crypto`.

L1.2c implémente ce scellement réel. Consulté avant toute modification de `zs-crypto`,
`referent-crypto` a produit le format complet ; les points structurants ont été soumis à
validation humaine.

## Décisions

### Format : JSON canonique RFC 8785 (JCS)

Pas CBOR/COSE : `zs-audit` canonicalise déjà en JCS (L1.4a), le contrat d'audit est en JSON
Schema, et un vérificateur Go (`access-broker`, pas encore construit) devra réimplémenter la
vérification — deux formats canoniques dans le même chemin de confiance serait une dette
inutile. `serde_json::Map` est adossée à une `BTreeMap` par défaut (feature `preserve_order`
absente du workspace) : les clés sont déjà triées à la sérialisation, `serde_json::to_vec` ne
produit aucun espace superflu — suffisant pour un document sans nombre à virgule flottante.

Champs (tous requis, `additionalProperties` refusé par construction — `#[serde(deny_unknown_
fields)]`) : `schema_version`, `suite`, `authority_domain`, `subject_id`, `aal`, `auth_method`,
`audience`, `issued_at`, `expires_at`, `audit_event_id`, `signatures`.

### `signatures` : tableau à N composantes dès v1 (R8)

Arité et ordre des `component` imposés par la suite (`v1` exige exactement `["ecdsa-p256"]`),
jamais par le message lui-même — un document `v2` à une seule composante est **refusé**, pas
validé partiellement. `component` sert à l'auditabilité humaine, jamais à choisir un
vérificateur (piège « alg confusion » des JWT).

### Encodage et séparation de domaine

- **Signatures en hexadécimal minuscule**, pas base64 : cohérent avec `prev_hash` du contrat
  d'audit, canonicité triviale (base64 admet plusieurs encodages valides du même contenu — une
  porte de malléabilité sur un objet dont on hache la sérialisation complète).
- **Champs texte restreints à l'ASCII imprimable** hors `"`/`\` : rend la conformité JCS de
  l'échappement structurellement vraie plutôt que dépendante d'un détail d'implémentation de
  `serde_json` sur tout l'espace Unicode.
- **Message signé** : `m = "zero-secret/identity-assertion/v1" || 0x00 || jcs(document sans
  "signatures")`. Le préfixe est une séparation de domaine : `audit-seal/v1` réutilisera la même
  primitive P-256/SHA-256 avec une clé distincte (ADR-011) ; la séparation élimine toute
  confusion de contexte par construction plutôt que par convention de nommage de clé.
- **`key_id`** = 8 premiers octets, en hexadécimal, de `SHA-256(point SEC1 non compressé)` —
  identifie la clé de **vérification**, jamais son emplacement PKCS#11 (le label HSM reste
  interne à `zs-crypto`/`zs-hsm`).

### Champs ajoutés au-delà d'ADR-007

- **`expires_at` obligatoire**, TTL par défaut 120 s. Non listé par ADR-007 ; ajouté ici : une
  assertion signée sans expiration est un jeton porteur éternel. Admissible sans révision
  d'ADR-007 selon son propre critère de réexamen (contenu précis amendable tant que la structure
  générale — émetteur, HSM, hybridation `v2` — ne change pas).
- **`audience`** (service destinataire attendu) : réduit le risque de rejeu inter-service — un
  vérificateur peut exiger que l'assertion lui était destinée, pas seulement qu'elle est valide
  en général. Décision humaine explicite (non tranchée par `referent-crypto` seul).
- **`credential_id` exclu** : déjà dans l'événement d'audit ; l'inclure dans l'assertion
  diffuserait un identifiant d'authentificateur stable sans besoin fonctionnel (minimisation).
- **`audit_event_id` sert aussi d'identifiant unique anti-rejeu** de l'assertion — pas de second
  UUID.

### `verify()` livrée dans le même lot, sans HSM

Sans elle, `seal()` produirait un objet que personne ne peut contrôler, et la première
implémentation de vérification serait écrite par un consommateur, hors façade. Ordre des
contrôles, non négociable : borne de taille (4096 octets) avant tout parse → parse JSON strict
(`deny_unknown_fields`, un champ dupliqué est déjà refusé nativement par `serde`, avant même le
contrôle suivant) → **canonicité vérifiée par re-sérialisation, jamais supposée** (reconstruction
depuis les champs typés, comparaison octet à octet avec l'entrée) → suite acceptée → arité de
signature exacte → résolution de chaque `key_id` → vérification de **toutes** les composantes
sans court-circuit (`&=`, pas `&&`) → domaine d'autorité attendu → fenêtre temporelle. Horloge et
suites acceptées fournies par l'appelant (`AcceptancePolicy`), jamais lues en ambiant.

`VerifiedAssertion` n'a aucun constructeur public — impossible d'accéder à son contenu sans être
passé par `verify` (même patron que `authenticator_proof::Verified` et
`AuthenticationClaims`/L1.2b).

### Frontière `zs-crypto` / `zs-hsm` / `zs-webauthn`

`AssertionClaims` est un type **plat, propre à `zs-crypto`** (`AssuranceLevel`, pas
`zs_webauthn::Aal`) : ce module ne dépend d'aucun type `zs-webauthn`, l'appelant
(`identity-provider`, pas encore construit) fait la conversion. Vérifié par un nouveau test
d'architecture (`tools/lib/check-zs-crypto-deps.sh`) : `zs-crypto` ne dépend d'aucun crate
applicatif du workspace, seulement de `zs-hsm` — ferme le sens de dépendance resté ouvert après
`check-webauthn-no-hsm.sh` (qui ne couvrait que le sens inverse).

`HsmError` est traduit en `SealError::SealingUnavailable`, sans `#[source]` ni `#[from]` :
`source()` ferait rentrer `HsmError` dans la surface publique et inviterait un `match` qui
déciderait de continuer sur certaines variantes. Le détail part en télémétrie
(`tracing::warn!`, nouvelle dépendance façade — validée, règle absolue #10).

### Piège de vérification identifié et corrigé en session

`aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED::verify` hache son entrée en interne (c'est un
algorithme « message complet », pas « condensé pré-calculé »), alors que `zs_hsm::sign_digest`
signe un condensé déjà calculé par l'appelant (mécanisme PKCS#11 `CKM_ECDSA` brut, sans
re-hachage côté jeton). `verify()` doit donc appeler `ECDSA_P256_SHA256_FIXED::verify` avec le
**message complet** (`m` ci-dessus), jamais `SHA-256(m)` — sinon la vérification double-hache et
rejette systématiquement des signatures pourtant valides. Erreur découverte et corrigée par les
tests (`assertion_scellee_est_verifiee` a d'abord échoué), documentée ici pour qu'un futur
contributeur touchant `audit_seal` (L1.4b, même primitive) ne la reproduise pas.

### Tests sans HSM réel

Mock `HsmSigner` légitime ici (contrairement à `zs-hsm` lui-même, ADR-011) — `#[cfg(test)]`
in-crate uniquement, jamais une feature cargo (activable en production, ce serait le repli
logiciel interdit sous un autre nom). Signature de test via `p256` (RustCrypto, dev-dependency
validée) plutôt que `aws-lc-rs` : implémentation **indépendante** de celle de vérification, test
croisé entre deux bibliothèques distinctes plutôt qu'un aller-retour avec soi-même. 25 tests au
total dans `zs-crypto` (11 nouveaux + les 14 pré-existants d'`authenticator_proof`), couvrant les
refus obligatoires : signature modifiée, clé publique d'une autre paire, suite inconnue, arité de
signature incorrecte, tableau de signatures vide, document non canonique (espace superflu),
champ inconnu, expiration, domaine d'autorité inattendu, identifiant de clé inconnu, taille
excessive, contenu de claims invalide (ASCII, format d'horodatage, version d'UUID).

## Conséquences

**Positives** — `v2` hybride devient un ajout de composante au tableau `signatures`, sans
changement de format ni de schéma. L'invariant 5 (hybridation stricte) est vérifiable en lisant
le document (arité imposée) plutôt que par convention. Le piège de double-hachage aws-lc-rs est
documenté avant que `audit-seal/v1` (L1.4b, même primitive) ne le reproduise.

**Négatives** — le contrôle de canonicité par re-sérialisation est un point de fragilité connu
(dépend du comportement par défaut de `serde_json::Map`, non garanti si la feature
`preserve_order` était activée ailleurs dans le workspace — testé explicitement, voir
`zs-audit::canonical`). La mesure de latence `sign_digest` réelle (aller-retour PKCS#11) reste
impossible sur ce poste de développement Windows (pas de SoftHSM2) — à faire en CI/Jenkins
(Linux), comme pour H1.

**Surface d'attaque** — `verify` est un analyseur exposé à des entrées non fiables (une
assertion présentée par un client à `access-broker`/`policy-engine`) : borné en taille, refus
par défaut à chaque étape, fuzzing requis par `zs-crypto/CLAUDE.md` (cible à écrire,
`crates/zs-crypto/fuzz/fuzz_targets/identity_assertion_verify.rs` — même limite d'exécution que
`zs-webauthn` : compile, non exécutée sur ce poste, à lancer en CI/Jenkins Linux).

## Critère de réexamen

Réexaminer au démarrage de `v2` hybride (ajout de la composante ML-DSA-65 au tableau
`signatures`) et si un vérificateur Go (`access-broker`) est écrit — les vecteurs de test figés
de ce lot deviennent alors la spec de conformité à porter. `contracts/events/audit-event.schema.json`
a été corrigé en même temps (tableau `components` à N éléments, même raisonnement R8) — voir le
commit de cette contribution pour le diff exact.
