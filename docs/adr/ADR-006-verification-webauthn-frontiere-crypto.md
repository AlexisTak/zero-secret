# ADR-006 — Vérification WebAuthn : frontière entre `zs-webauthn` et `zs-crypto`

**Statut** : accepté
**Date** : 2026-08-22
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

Le backlog L1.1 introduit la première opération cryptographique réelle du projet : vérifier
qu'un authentificateur FIDO2 externe détient la clé privée correspondant à la clé publique
qu'il présente, liée au challenge et à l'origine de la cérémonie. `crates/zs-crypto` est un
stub vide à ce jour ; le choix de bibliothèque engage la règle absolue #4 (toute crypto passe
par `zs-crypto`), le contenu du CBOM et la trajectoire post-quantique.

**Différence structurante avec les suites déjà anticipées** (`audit-seal`, `channel-kex`) :
nous sommes ici **vérificateur**, pas émetteur. L'algorithme est imposé par le matériel FIDO2
déployé chez l'utilisateur — nous ne choisissons pas, nous acceptons ou refusons. L'invariant 5
du `CLAUDE.md` local (« hybridation stricte ») ne s'applique donc pas à cette suite au sens où
il s'applique à `audit-seal`/`channel-kex` : exiger une signature hybride classique+PQC sur une
assertion FIDO2 aujourd'hui reviendrait à refuser la quasi-totalité du parc matériel existant.
Cette suite est une **exception documentée** à l'invariant 5, pas un contournement.

Le vrai jalon de conformité post-quantique 2027 du parcours WebAuthn n'est pas ici : c'est
l'assertion d'identité que l'IdP émet *après* vérification, signée par notre HSM — voir
ADR-007.

## Options envisagées

1. **`webauthn-rs` intégral dans `zs-webauthn`** — bibliothèque auditée (SUSE product
   security), très utilisée, mais `webauthn-rs-core` dépend d'OpenSSL (FFI) et de
   `serde_cbor_2` (fork non maintenu). La vérification de signature se ferait hors `zs-crypto`,
   en boîte noire : violation frontale de la règle absolue #4, CBOM impossible à déclarer
   précisément (quels algorithmes sont réellement acceptés dépend d'une bibliothèque tierce
   qu'on ne maîtrise pas au niveau suite).
2. **Tout écrire nous-mêmes** — écarté d'emblée : c'est exactement écrire de la crypto,
   contraire à l'invariant 1.
3. **Séparation parsing / vérification** — `ciborium` (décodage CBOR pur Rust, sans crypto) et
   `coset` (structures COSE, vérification par closure fournie par l'appelant) dans
   `zs-webauthn` ; `aws-lc-rs` (vérification de signature, FIPS 140-3) dans `zs-crypto`
   uniquement, derrière une suite versionnée `authenticator-proof/vN`. `webauthn-rs` conservé
   en `[dev-dependencies]` de `zs-webauthn` comme **oracle différentiel de test uniquement**,
   jamais dans le chemin de confiance.

## Décision

**Option 3.**

- **Suite `authenticator-proof/v1`** : accepte COSE ES256 (ECDSA P-256 + SHA-256, alg -7) et
  COSE EdDSA (Ed25519, alg -8). **Refusés explicitement, par décision et non par omission** :
  `RS256`/`PS256` (RSA — hors recommandation RGS B1, exclurait une partie du parc Windows
  Hello/TPM, arbitrage produit qui pourra être rouvert par un ADR ultérieur si le besoin de
  parc l'impose), `ES384`/`ES512` (aucun authentificateur significatif ne les émet), `alg: none`
  ou `alg` absent (refus dur, testé).
- **Règle non négociable** : l'algorithme de vérification est celui de la **clé publique
  enregistrée**, jamais celui déclaré par l'entrée à vérifier. Le champ `alg` présenté sert
  uniquement à comparaison stricte contre la clé enregistrée — divergence = refus (classe de
  faille « algorithm confusion »).
- **Backend** : `aws-lc-rs` (Apache-2.0 OR ISC), FIPS 140-3 validé (module v3), disponible pour
  ECDSA P-256, Ed25519, RSA-PSS **et ML-DSA-44/65/87** — un seul backend pour `v1` et pour la
  cible `v2` future, donc pas de changement de bibliothèque à la migration PQC. Alternative
  écartée : `p256` (RustCrypto) documente lui-même l'absence d'audit indépendant de son
  arithmétique de courbe et de sa constance temporelle ; `ml-dsa` (RustCrypto) est en 0.1.1,
  non audité, avec un advisory de sécurité (GHSA-5x2r-hc65-25f9, janvier 2026, acceptation de
  signatures avec hints répétés — exactement le type de laxisme que ce projet refuse).
- **Feature Cargo obligatoire** : `aws-lc-rs = { version = "1", features = ["prebuilt-nasm"] }`
  — sans cette feature, `aws-lc-sys` requiert l'assembleur NASM installé sur la machine de
  build ; `prebuilt-nasm` embarque les objets pré-assemblés et évite cette dépendance externe.
  Vérifié : compile et s'exécute sur ce poste de développement (Windows), y compris au chemin
  du dépôt.
- **`unsafe_code = "forbid"` reste actif pour `zs-crypto`, sans exemption.** Vérifié
  empiriquement (pas supposé) : bien qu'`aws-lc-sys` soit du FFI C sous le capot, l'API
  publique d'`aws-lc-rs` (`signature::EcdsaKeyPair`, `Ed25519KeyPair`, `UnparsedPublicKey`) est
  entièrement sûre — le FFI reste interne au crate `aws-lc-sys`, jamais exposé à notre code.
  Un test de compilation dédié (`#![forbid(unsafe_code)]` + vérification ECDSA P-256 et Ed25519
  réelles) confirme que `zs-crypto` n'a besoin d'aucune exemption, contrairement à l'hypothèse
  initiale de ce document et de `referent-crypto` — corrigé avant tout code, pas après coup.
- **Formats d'attestation supportés en v1** : `none` et `packed` seulement. `tpm`,
  `android-key`, `apple`, `fido-u2f` sont refusés explicitement, avec un code d'erreur distinct
  d'un refus pour attestation malformée — chaque format est une surface de fuzzing permanente à
  entretenir ; `tpm` en particulier est le plus complexe et historiquement le plus bogué de
  l'écosystème WebAuthn.
- **Fuzzing du parseur d'attestation écrit dans la même contribution** que le parseur, pas
  après — c'est le point le plus exposé selon `security/threat-models/identity-provider.md`.

## Conséquences

**Positives** — règle absolue #4 respectée à la lettre ; suites versionnées et déclarables au
CBOM ; un seul backend de la version classique à la version post-quantique ; base FIPS 140-3
défendable devant un CESTI ; `webauthn-rs` reste un filet de sécurité en test sans jamais entrer
dans le chemin de confiance.

**Négatives** — volume de code net supérieur à l'intégration directe de `webauthn-rs` ; le
parseur d'attestation CBOR devient notre responsabilité et impose un effort de fuzzing continu ;
`aws-lc-sys` (dépendance transitive) requiert la feature `prebuilt-nasm` pour éviter une
dépendance de build à l'assembleur NASM ; les formats `tpm`/`android-key`/`apple` ne sont pas
couverts en v1, réduisant le parc d'authentificateurs utilisables tant qu'ils ne sont pas
ajoutés explicitement.

**Surface d'attaque** — le parseur CBOR/COSE (`zs-webauthn`) devient la nouvelle surface
d'entrée non fiable la plus exposée du système (déjà identifiée dans le modèle de menaces).
Traité par : décodage strict (rejet de tout CBOR non canonique plutôt qu'avertissement), bornage
de taille avant décodage, refus explicite des formats d'attestation non supportés, fuzzing dès
cette contribution.

## Critère de réexamen

- Si un besoin de parc réel impose `RS256` (Windows Hello/TPM sans alternative), rouvrir la
  question du refus RSA par un ADR dédié, pas par une exception silencieuse ici.
- Si le format `tpm` devient nécessaire (déploiement avec parc Windows significatif), l'ajouter
  par une contribution dédiée avec son propre effort de fuzzing, jamais en extension discrète
  d'une contribution portant sur autre chose.
- Si `aws-lc-rs` cesse d'être maintenu ou perd sa validation FIPS, réexaminer le backend
  complet de `authenticator-proof` et `identity-assertion` (ADR-007) ensemble — ils partagent
  la même dépendance.

## Addendum (H5, ADR-023) — `accept_challenge`

`Challenge` (`authenticator_proof.rs`) n'avait qu'un émetteur (`new_challenge`, CSPRNG) et
aucun constructeur depuis des octets externes — cohérent tant qu'aucun appelant ne persistait
un challenge au-delà de la mémoire du process qui l'avait émis. H5 (endpoints HTTP de
cérémonie, `identity-provider`) introduit le premier serveur sans état vis-à-vis du challenge :
il est émis, persisté en base (`identity.challenges`), puis relu potentiellement par une autre
instance/après redémarrage avant vérification. `accept_challenge(suite, bytes: Vec<u8>)` a été
ajoutée (validation humaine explicite, `referent-crypto` consulté) pour réhydrater un
`Challenge` depuis ces octets — mêmes garanties de longueur (32 octets) et de suite que le
reste du crate, `bytes` pris par valeur pour que l'effacement au drop (invariant 8) couvre le
tampon lu en base sans copie intermédiaire non effacée. Aucune primitive cryptographique
nouvelle, aucune entrée CBOM requise.
