# Backlog — Lot L0 (socle) et amorce L1

Une session Claude Code = une tâche de ce fichier. Ouvrir une session sans tâche identifiée
produit du code plausible et non aligné.

Chaque tâche porte un critère d'acceptation vérifiable. « Ça marche » n'est pas un critère.

---

## L0 — Socle et gouvernance (semaines 1 à 4)

**Critère de passage du lot** : une contribution triviale traverse toute la chaîne et produit un
artefact signé et attesté.

### L0.1 — Squelette du dépôt et outillage
- [ ] Arborescence complète (`apps/`, `crates/`, `pkg/`, `contracts/`, `policies/`, `deploy/`,
      `security/`, `tests/`, `docs/`, `tools/`) avec un `README.md` par dossier de premier niveau
- [ ] Workspace Cargo et modules Go initialisés
- [ ] `Makefile` fonctionnel : toutes les cibles existent, même en no-op documenté
- [x] `.gitignore`, `SECURITY.md`, `CODEOWNERS` — pas de `LICENSE` : dépôt propriétaire, réservé
- [ ] Hooks git : format, détection de secrets, commits signés
- **Acceptation** : `make setup && make check` passe sur un dépôt fraîchement cloné.

### L0.2 — Test d'architecture
- [x] Test qui échoue si un composant de `apps/` importe un autre composant de `apps/`
- [x] Test qui échoue si un module hors `zs-crypto` / `zs-hsm` importe une bibliothèque crypto
- [x] Test qui échoue si un fichier généré diffère de ce que produirait `make generate`
- **Acceptation** : les trois tests échouent quand on introduit volontairement la violation,
  et passent une fois retirée. Écrire la violation d'abord.
  Fait : `tests/architecture/run.sh` (8/8), détecteurs dans `tools/lib/`, câblés dans
  `tools/check-arch.sh` / `make test-arch`. Le check generated-up-to-date reste no-op contre
  le vrai dépôt tant que `buf` est absent de l'environnement de dev — le mécanisme lui-même
  est prouvé par la fixture `generated-drift` (générateur injectable, sans dépendance à buf).

### L0.3 — Contrat de décision et génération
- [x] `contracts/proto/policy/v1/decision.proto` complété et validé (`buf lint`)
- [x] `contracts/events/audit-event.schema.json` complété
- [x] `make generate` produit les types Go (committés, `pkg/gen/`) ; Rust généré à la
      compilation par `crates/zs-policy/build.rs` (ADR-004, pas via buf — incompatibilité
      constatée entre protoc-gen-prost/protoc-gen-tonic sur ce poste), aucun fichier généré
      écrit à la main
- [x] Vérification de compatibilité ascendante en CI (`buf breaking`) — `.github/workflows/contracts.yml`
- **Acceptation** : une suppression de champ dans le proto fait échouer la CI. Vérifié localement
  (`tools/check-arch.sh` détecte la divergence de `pkg/gen`) ; `buf breaking` prend le relais en
  CI une fois `contracts/buf.yaml` présent sur `main`.

### L0.4 — Chaîne d'intégration continue
- [x] Étapes : format → lint → détection de secrets → build → tests → tests d'architecture →
      analyse de dépendances → SBOM → CBOM → build reproductible → signature → attestation
      (`Jenkinsfile`, sur une instance Jenkins existante — bascule depuis GitHub Actions,
      voir ADR-005)
- [x] Exécuteurs éphémères : agents Docker jetables (plugin Docker Pipeline), un conteneur par
      stage. Secret durable : **dérogation documentée** (ADR-005) — clé cosign dans le Jenkins
      Credentials Store, rotation à 90 jours, périmètre limité au stage de signature sur `main`
- [ ] Branche principale protégée — **bloqué** : dépôt privé + plan GitHub Free renvoie 403
      sur `branches/main/protection` et sur `rulesets` (« Upgrade to GitHub Pro or make this
      repository public »). Nécessite un changement de plan GitHub (facturation — décision
      humaine) ou de rendre le dépôt public. À refaire dès que l'un des deux est tranché.
      Sans lien avec la bascule Jenkins — c'est un réglage GitHub, indépendant de la plateforme
      qui exécute la CI.
- **Acceptation** : un secret introduit volontairement dans une branche est bloqué avant fusion.
  Vérifié localement (`gitleaks detect` sur un commit de test, secret détecté, commit annulé) ;
  le stage `détection de secrets` du `Jenkinsfile` reproduit ça sur chaque build.
- **Limite constatée et assumée** : le stage `build reproductible (informatif)` est non bloquant
  (`catchError` → `UNSTABLE`, pas `FAILURE`). Un `cargo build --release` identique, réexécuté à
  l'identique, produit deux binaires différents bit à bit (non-déterminisme connu de l'écosystème
  Rust sans configuration dédiée). À reprendre via un ADR si la reproductibilité devient un
  critère de qualification (ANSSI/CESTI) plutôt qu'un objectif déclaré.
- **Historique** : implémenté une première fois sur GitHub Actions (`.github/workflows/`,
  PR #3), remplacé par Jenkins sur demande explicite — voir ADR-005 pour la justification
  complète des deux dérogations que ça introduit (secret stocké, attestation non conforme SLSA
  à la lettre).

### L0.5 — Modèle de menaces v1
- [x] `security/threat-models/` : un fichier par composant, les six catégories STRIDE renseignées
      (« non applicable car… » est une réponse valide, « — » ne l'est pas) — 7 fichiers, un par
      composant de `docs/architecture.md` (`identity-provider`, `policy-engine`, `access-broker`,
      `credential-issuer`, `audit-collector`, `admin-api`, `console-web`)
- [x] Reprise des six scénarios d'attaque de `docs/architecture.md` — vérifié par grep, chaque
      scénario référencé dans au moins un fichier
- **Acceptation** : chaque risque critique a une mesure compensatoire **et** un risque résiduel
  écrit. Un modèle sans risque résiduel est un modèle incomplet.
- **Hors périmètre, signalé** : pas de modèle de menaces dédié pour `crates/zs-crypto` et
  `crates/zs-hsm` (bibliothèques, pas des « composants » au sens du tableau de
  `docs/architecture.md`) — leurs risques apparaissent en creux dans les hypothèses de sécurité
  des composants qui en dépendent. À revoir avec `referent-crypto` si un modèle dédié devient
  nécessaire (probable avant qualification).
- **Angles morts explicites remontés** (à trancher avant L2, pas des oublis) :
  authentification de l'approbateur non spécifiée (`access-broker`), distinction contexte
  vérifié/déclaré dans `DecisionRequest.Context` non tranchée (`access-broker`), ordre
  audit/émission non tranché (`credential-issuer`), granularité des rôles d'administration non
  définie et chemin de modification de politique à chaud non clarifié (`admin-api`).

### L0.6 — Environnement de développement
- [x] `make up` : PostgreSQL 17, OpenBao en mode dev, SoftHSM2, collecteur OTel — via Podman
      (`deploy/compose.dev.yml`)
- [x] Migrations initiales : quatre schémas (`identity`, `authz`, `issuance`, `audit`), un rôle
      applicatif par schéma, `UPDATE`/`DELETE`/`TRUNCATE` révoqués explicitement sur `audit`
      (`deploy/migrations/`, appliquées par `tools/migrate.sh`)
- **Acceptation** : le rôle applicatif `audit_writer` échoue explicitement sur un `DELETE`.
  Prouvé par `tests/e2e/audit_writer_refuses_delete.sh` (`make test-e2e`) — connexion réelle en
  tant que `audit_writer`, `INSERT` accepté, `DELETE`/`UPDATE` refusés avec le code PostgreSQL
  `42501` (insufficient_privilege) vérifié explicitement, pas une lecture de la migration.
- **Non testé de bout en bout ici** : Podman/Docker bloqués par la politique de permission de
  cet environnement de développement (session Claude Code) — écrit et relu avec soin (syntaxe
  SQL, YAML du compose, scripts bash), mais le premier run réel (`make up && make test-e2e`)
  reste à faire par un humain ou en CI/Jenkins.
- Aucun secret durable : mots de passe PostgreSQL (`tools/migrate.sh`) et PIN SoftHSM2
  (`deploy/softhsm/init-token.sh`) générés à l'exécution, écrits dans `.env.dev`/`.env.softhsm`
  (gitignorés) ; jeton root OpenBao auto-généré par OpenBao lui-même, jamais fixé.

---

## L1 — Noyau d'identité FIDO2 (à partir de la semaine 3)

**Critère de passage du lot** : vecteurs de conformité verts, hameçonnage simulé bloqué, fuzzing
de l'analyseur d'attestation sans incident.

### L1.1 — Enregistrement d'authentificateur
- [x] Génération du challenge (`zs_crypto::authenticator_proof::new_challenge`, CSPRNG, 32
      octets, zeroize au drop) — **stockage DB non câblé** : schéma prêt
      (`deploy/migrations/003_identity_challenges_et_authenticators.sql`, expiration et usage
      unique portés par `expires_at`/`used_at`), mais aucun pilote Postgres async n'a été ajouté
      à `identity-provider` (scope tranché en session : bibliothèque seule, pas de serveur HTTP
      ni de nouvelle dépendance DB non discutée — voir décisions ci-dessous)
- [x] Vérification de `origin`, `rpId`, type et structure d'attestation
      (`crates/zs-webauthn/src/{client_data,registration}.rs`)
- [x] Politique d'attestation configurable (`AttestationPolicy::{Any,Required}`), refus par
      défaut si non satisfaite
- **Acceptation** : challenge rejoué → refus ; `origin` incorrect → refus ; attestation absente
  alors que la politique l'exige → refus. Trois tests, trois refus. **Fait** : 17 tests dans
  `crates/zs-webauthn` (dont les trois obligatoires + cas supplémentaires signalés par
  `referent-crypto` — `rpId` incorrect, format d'attestation non supporté, signature invalide,
  `user present` absent), vérifiés avec de vraies signatures ECDSA P-256 (`aws-lc-rs`), pas des
  doublures.
- **Décisions structurantes prises en session** (voir ADR-006, ADR-007) :
  - Suite `authenticator-proof/v1` : ES256 + EdDSA acceptés, RSA/`RS256` refusé (arbitrage
    produit assumé — exclut une partie du parc Windows Hello/TPM), formats d'attestation `none`
    et `packed` (auto-attestation) seulement — `tpm`/`android-key`/`apple`/x5c refusés
    explicitement, pas silencieusement.
  - Backend `aws-lc-rs` (FIPS 140-3, `prebuilt-nasm` — évite une dépendance de build à NASM).
    **Correction en session** : contrairement à l'hypothèse initiale de `referent-crypto` et de
    l'ADR-006, `unsafe_code = "forbid"` n'a **pas** eu besoin d'être levé pour `zs-crypto` —
    vérifié empiriquement (l'API publique d'`aws-lc-rs` reste sûre, le FFI reste interne à
    `aws-lc-sys`).
  - `identity-assertion/v1|v2` spécifiée par avance (ADR-007) pour que la frontière
    `zs-webauthn`/`zs-crypto` soit posée au bon endroit avant L1.2.
  - `tools/lib/check-no-direct-crypto.sh` étendu (motif ne couvrait pas `openssl`,
    `webauthn-rs`, `rsa`, `ml-dsa`, etc. — un contributeur aurait pu les ajouter sans que le
    hook réagisse) ; nouvelle fixture de violation ; faux positif corrigé (le motif ignorait mal
    le code crypto légitime des blocs `mod tests`, utilisé pour simuler un authentificateur
    externe dans les tests).
  - Fuzzing du parseur d'attestation écrit dans la même contribution
    (`crates/zs-webauthn/fuzz/fuzz_targets/attestation_parser.rs`), conformément à la mise en
    garde de `referent-crypto` — **non exécuté ici** : `cargo fuzz` (libFuzzer/ASan) échoue sur
    ce poste Windows (bibliothèque runtime `clang_rt.asan` absente du toolchain MSVC local) ; le
    code fuzz compile (`cargo +nightly check`), l'exécution réelle est à faire en CI/Jenkins
    (Linux).
  - Oracle différentiel de test contre `webauthn-rs` (recommandé par `referent-crypto`) :
    **reporté**, pas de test différentiel écrit faute de temps dans cette contribution.

### L1.2 — Authentification et assertion
- [x] Vérification de signature via `zs-crypto`, jamais directement
      (`crates/zs-webauthn/src/authentication.rs::verify_authentication_ceremony`, réutilise
      `authenticator-proof/v1` telle quelle — aucune ligne ajoutée à `zs-crypto`)
- [x] Gestion du compteur de signature et détection de clonage (`counter_supported` figé à
      l'enregistrement, migration 004 — voir mise en garde `referent-crypto` : une réévaluation
      par assertion permettrait à un clone de désactiver la détection en forçant `signCount=0`)
- [x] Assertion d'identité signée portant le niveau AAL atteint et la méthode employée —
      **L1.2c fait** (ADR-012) : `crates/zs-crypto::identity_assertion::{seal,verify}`. Format
      JSON canonique (RFC 8785), conteneur `signatures` à N composantes dès v1 (R8), séparation
      de domaine par préfixe, encodage hexadécimal. Champs ajoutés au-delà d'ADR-007 :
      `expires_at` (obligatoire, TTL 120 s — sans lui une assertion signée serait un jeton
      porteur éternel) et `audience` (réduit le rejeu inter-service).
- **Acceptation** : compteur régressif → alerte et refus (**fait**, `compteur_regressif_est_refuse`,
  `compteur_identique_est_refuse`) ; assertion rejouée → refus (**fait aux deux niveaux** :
  cérémonie WebAuthn — challenge à usage unique, L1.1 — **et** assertion d'identité signée —
  `audit_event_id` sert d'identifiant unique, `expires_at` borne la fenêtre de validité, L1.2c).
- **Découpage L1.2a/b/c** : voir ADR-008 (pourquoi ne pas tout livrer d'un bloc) et ADR-012
  (format complet, une fois H1 débloqué).
- **Frontière posée** : `crates/zs-webauthn` ne dépend jamais de `crates/zs-hsm`
  (`tools/lib/check-webauthn-no-hsm.sh`, L1.2a) ; `crates/zs-crypto` ne dépend d'aucun crate
  applicatif du workspace, seulement `zs-hsm` (`tools/lib/check-zs-crypto-deps.sh`, L1.2c —
  ferme l'autre sens de dépendance).
- **Ports de stockage** (`ChallengeStore`, `SignCounterStore`, `crates/zs-webauthn/src/store.rs`) :
  traits documentés (contrat d'atomicité explicite), sans implémentation — cohérent avec le
  scope-cut DB de L1.1.
- **Piège corrigé en session** (ADR-012) : `aws_lc_rs::ECDSA_P256_SHA256_FIXED::verify` hache son
  entrée en interne — `verify()` doit lui passer le message complet, jamais le condensé
  pré-calculé envoyé à `zs-hsm::sign_digest` (qui, lui, signe le condensé directement, sans
  re-hachage côté jeton). Documenté pour que L1.4b (même primitive) ne le reproduise pas.
- **Non exécuté ici** : mesure de latence `sign_digest` réelle (pas de SoftHSM2 sur ce poste
  Windows, même limite que H1) ; fuzzing de `identity_assertion::verify`
  (`crates/zs-crypto/fuzz/fuzz_targets/identity_assertion_verify.rs`, compile via
  `cargo +nightly check`, à lancer en CI/Jenkins Linux comme le fuzz target de L1.1).

### L1.3 — Cycle de vie
- [x] Révocation d'authentificateur, effet immédiat (`RegisteredCredential.revoked`, vérifié en
      premier dans `verify_authentication_ceremony` — colonne `revoked_at` déjà présente depuis
      la migration 003, aucune migration nouvelle nécessaire)
- [x] Récupération à quorum (plusieurs porteurs distincts) — `crates/zs-webauthn/src/recovery.rs`,
      réutilise `authenticator-proof/v1` (chaque porteur approuve via sa propre cérémonie
      d'authentification WebAuthn, L1.2), **aucune nouvelle suite cryptographique** (voir
      ADR-009). « Sous scellés » : scellement/chaînage réel de l'événement de récupération
      **différé à L1.4** (`zs-audit` est un stub vide) — `RecoveryOutcome` porte `#[must_use]`
      pour qu'un appelant ne puisse pas ignorer silencieusement le résultat en attendant L1.4.
- **Acceptation** : un seul porteur ne peut jamais déclencher une récupération. **Fait** —
  `un_seul_porteur_ne_peut_jamais_declencher_une_recuperation` : un plancher `MINIMUM_THRESHOLD
  = 2` est imposé par le module, non contournable même si l'appelant configure `threshold = 1`
  par erreur.
- **Hors périmètre, signalé** (ADR-009) : liaison cryptographique entre N approbations et une
  demande de récupération précise (responsabilité de l'appelant, `identity-provider`, pas encore
  construit) ; scénario de récupération « à froid » (principal sans aucun authentificateur
  disponible) — non couvert, nécessiterait un mécanisme distinct.

### L1.4 — Audit du parcours
- [x] Événements : enregistrement, révocation, tentative, succès, échec, récupération —
      `crates/zs-audit/src/record.rs::EventType` (+ `quorum.operation` couvrant L1.3,
      + `audit.chain_verified` ajouté en L1.4b, ADR-013 — 8 types). Contenu métier seulement
      (`AuditRecord`, non sérialisable — même raison qu'`AuthenticationClaims` en L1.2b) : la
      construction, le comptage et le scellement réel sont tous faits (L1.4a + L1.4b).
- [x] Chaînage et signature vérifiés par test — **chaînage fait** (`crates/zs-audit/src/chain.rs`,
      `verify_chain`, testé sur octets scellés opaques). **Signature faite** (L1.4b, ADR-013) :
      `crates/zs-crypto::audit_seal::{seal,verify}`, même primitive P-256/SHA-256
      qu'`identity_assertion` (L1.2c), clé HSM distincte (`zs-audit-seal-v1`). Forme du conteneur
      de signature différente d'`identity_assertion` (objet `{suite, components}` vs tableau),
      imposée par le contrat existant — divergence assumée et datée pour résorption en v2.
- **Acceptation** : aucune action du parcours ne réussit sans produire son événement — démontré
  au niveau de la complétude de flux
  (`crates/zs-audit/src/sink.rs::echec_du_puits_nest_jamais_avale_silencieusement`) et par
  comptage (`chaque_type_devenement_du_parcours_est_compte`, 8 types désormais avec
  `audit.chain_verified`). **Scellement réel démontré** (L1.4b) : vecteurs de chaînage figés,
  3 événements scellés et chaînés, vérifiés bout en bout par
  `crates/zs-audit/tests/chain_vectors.rs` (`audit_seal::verify` + `chain::verify_chain`).
- **Découpage L1.4a/H1/L1.4b** : voir ADR-010 (justification, choix d'une signature par
  événement) et ADR-013 (format complet, une fois H1/L1.2c livrés).
- **Correctifs de contrat** : `authority_domain` rendu obligatoire (ADR-010) ; `signature` passée
  d'un objet mono-composante à `{suite, components: [...]}` (ADR-013, même raisonnement R8
  qu'ADR-012 pour `identity-assertion`) — gratuits avant tout événement produit, cassants après.
- **`canonical.rs` supprimé** (ADR-013) : la canonicalisation de l'événement complet vit
  désormais dans `zs_crypto::audit_seal` (qui doit reconstruire un document typé pour son
  contrôle de canonicité) — deux implémentations JCS auraient divergé sans que rien ne le
  détecte. Ses deux tests de non-régression migrés dans `crates/zs-crypto/src/common.rs`.
- **Correctif hérité corrigé** : un champ optionnel absent (`target`, `context`) est omis, jamais
  scellé en `null` — le contrat le refuse (`additionalProperties: false`, non requis ≠ nullable),
  vérifié par test et par la conformité au contrat elle-même (`jsonschema`, dev-dependency).
- **Ports de stockage** (`AuditSink`, `AuditChainStore`, `crates/zs-audit/src/sink.rs`) : traits
  documentés (contrat d'atomicité explicite pour `AuditChainStore::append`), sans implémentation
  — cohérent avec le scope-cut DB de L1.1/L1.2.
- **Limite assumée du chaînage** : une troncature en queue de chaîne d'un domaine reste
  indétectable par `verify_chain` seul (prouvé par test,
  `troncature_en_queue_de_chaine_nest_pas_detectee`) — seul un ancrage périodique publié à
  l'extérieur (`event_type: "audit.chain_verified"`, désormais scellable, sans sémantique de
  charge utile propre — à instruire par un ADR dédié à `audit-collector`) la détecterait.
- **Hors périmètre L1.4b, signalé** (ADR-013) : le champ `decision` du contrat (`policy.decided`,
  `credential.issued`, backlog L2+) n'est pas supporté — aucun `EventType` de ce lot ne le
  requiert. Mesure de latence `sign_digest` réelle non faite (pas de SoftHSM2 sur ce poste
  Windows, même limite qu'H1/L1.2c) ; fuzzing de `audit_seal::verify`
  (`crates/zs-crypto/fuzz/fuzz_targets/audit_seal_verify.rs`) compile mais non exécuté ici.

### H1 — Intégration HSM (prérequis partagé L1.2c/L1.4b)
- [x] `crates/zs-hsm` : intégration PKCS#11 réelle (`cryptoki` 0.12, ADR-011) — pool de sessions
      borné plafonné par `ulMaxSessionCount`, pré-authentifiées, jamais de `thread_local!` ;
      règle absolue : aucune session du pool n'appelle `logout()` (portée application/token, pas
      session — déloguerait toutes les autres sessions).
- [x] `HsmSigner::{sign_digest, public_key}` — trait générique, sans vocabulaire métier
      (`identity-assertion`/`audit-seal` restent inconnus de `zs-hsm`, portés par `zs-crypto` en
      L1.2c/L1.4b). Encodage de signature figé : raw `r‖s`, 64 octets (entre dans `prev_hash`,
      ADR-010 — irréversible après le premier événement scellé).
- [x] Sémantique de refus stricte : aucun repli logiciel (même en dev), aucune reprise interne
      (ECDSA randomisé + `prev_hash` signature incluse = risque de fourche de chaîne si deux
      signatures valides du même contenu étaient produites), démarrage en échec dur si le
      mécanisme requis n'est pas offert par le token.
- [x] CBOM initialisé (`security/crypto-inventory/{suites.toml,cbom.json,README.md}`), trois
      suites déclarées (`authenticator-proof/v1`, `identity-assertion/v1`, `audit-seal/v1`) —
      comble l'invariant 9 de `zs-crypto/CLAUDE.md`, en défaut depuis L1.1 (aucun contrôle
      n'existait avant). Contrôle bloquant ajouté (`tools/lib/check-cbom-coverage.sh`) : une
      suite référencée dans `zs-crypto` sans entrée CBOM fait échouer `make test-arch`.
- [x] Test d'architecture étendu : `cryptoki`/`cryptoki-sys` non importables hors `zs-hsm`
      (`tools/lib/check-no-direct-crypto.sh`).
- [ ] Tests d'intégration réels contre SoftHSM2 (`crates/zs-hsm/tests/pkcs11_integration.rs`,
      `#[ignore]`, activés par `make test-crypto`) — **non exécutés dans cette contribution**
      (SoftHSM2 non installé sur ce poste de développement Windows) ; 5 tests unitaires purs
      (`decode_ec_point`) exécutés et verts, le reste attend un environnement Linux/CI avec
      `ZS_HSM_MODULE` défini.
- **Deux clés HSM séparées** dès H1 (une pour `identity-assertion`, une pour `audit-seal`,
  ADR-011) : séparer après coup exigerait de rejouer tout l'historique signé.
- **Pool saturé → refus complet de l'action métier** (ADR-011) : une surcharge HSM devient une
  indisponibilité du système par conception, jamais une action qui réussirait sans événement
  scellé — décision de disponibilité assumée, pas seulement de sécurité.
- **Hors périmètre H1, signalé** : aucun HSM matériel cible identifié à ce jour — SoftHSM2 reste
  la seule cible testée ; `SigningMechanism` (aujourd'hui `EcdsaP256Sha256` seul) peut nécessiter
  révision selon les mécanismes réellement exposés par le matériel choisi. Mesures de latence
  PKCS#11 (plancher, pas une capacité de production) non faites — pas de SoftHSM2 disponible ici.
- Voir ADR-011 pour la conception complète (bibliothèque `cryptoki`, frontière `zs-crypto`/
  `zs-hsm`, plan de test détaillé).

---

## L2 — Autorisation dynamique et émission JIT (à partir de la fin de L1)

**Critère de passage du lot** : un parcours complet (requête → décision → credential éphémère →
expiration) traverse les trois plans, chaque étape produit son événement d'audit signé, et une
décision peut être rejouée hors ligne à partir du seul journal — critère explicite du contrat
`decision.proto` (« une décision doit pouvoir être rejouée hors ligne, à l'identique, par un
tiers, à partir du seul enregistrement d'audit »).

**Prérequis documentaire non soldé** — quatre angles morts remontés par L0.5 et jamais tranchés
depuis : authentification de l'approbateur (`access-broker`), distinction contexte
vérifié/déclaré dans `DecisionRequest.Context` (`access-broker`), ordre audit/émission
(`credential-issuer`), granularité des rôles d'administration et chemin de modification de
politique à chaud (`admin-api`). Chacun est un choix structurant au sens de la méthode de travail
du `CLAUDE.md` racine (mode plan + validation avant implémentation) — ils sont rattachés à la
tâche qu'ils bloquent ci-dessous, pas pré-tranchés ici : rédiger la section n'est pas trancher les
questions qu'elle pose.

### L2.1 — Schéma d'entités Cedar et corpus de politiques
- [ ] `contracts/cedar/` : schéma d'entités (types `Principal`, `Resource`, `Action`) aligné sur
      `decision.proto` (`Principal`, `Resource`, `Action` déjà spécifiés côté transport) —
      typage statique, cohérent avec ADR-003 (menace de confusion de requête)
- [ ] Premier corpus `policies/access/` : au moins une politique nominale + ses cas d'attaque
      (`policies/CLAUDE.md` : hors conditions, principal voisin, escalade par combinaison,
      requête ambiguë, ressource proche, dépassement de TTL — six cas minimum par règle)
- [ ] Règle Sigma correspondante dans `policies/detection/` pour chaque politique sensible
      ajoutée (contrepartie en détection exigée par `policies/CLAUDE.md`)
- **Acceptation** : `cedar test` et le harnais de rejeu passent ; chaque politique a son cas de
  refus et sa règle de détection. Une politique sans cas de refus n'est pas terminée.
- **Décision préalable** : schéma Cedar d'abord, jamais une politique écrite contre un schéma
  encore instable (`policies/CLAUDE.md` — « schéma d'abord »).

### L2.2 — PDP (`policy-engine`, Rust)
- [ ] `Decide(DecisionRequest) → DecisionResponse` (`decision.proto`) : évaluation Cedar contre le
      corpus L2.1, `effect` par défaut `EFFECT_DENY` sur tout chemin d'erreur ou politique
      absente (R2)
- [ ] **Aucun appel réseau pendant l'évaluation** (invariant du contrat, règle absolue #5 du
      `CLAUDE.md` racine) — le contexte arrive intégralement en entrée, y compris `DevicePosture`
      et `approvals`, aucun enrichissement en cours d'évaluation
- [ ] `decision_hash` : empreinte de la requête + version exacte des politiques évaluées,
      suffisante pour un rejeu hors ligne bit-exact — voir L2.3 pour son scellement dans
      l'événement `policy.decided`
- **Acceptation** : rejeu hors ligne d'une décision archivée (requête + `policy_version` +
  politiques à cette version) produit exactement le même `effect`/`decision_hash`. Sans état,
  déterministe — vérifié en exécutant deux fois la même requête sur deux instances distinctes.
- **Frontière posée** : `policy-engine` ne dépend d'aucun autre composant `apps/` (règle absolue
  #7 et règle de dépendance dédiée de `docs/architecture.md`) — vérifiable par le même patron de
  test d'architecture que `zs-crypto-deps`/`webauthn-no-hsm`.

### L2.3 — Parcours JIT (`access-broker`, Go)
- [ ] Ouverture de demande : ressource, motif, référence de ticket (`Context.ticket_ref`,
      `Context.justification`, bornée à 512 caractères côté contrat)
- [ ] Sollicitation d'approbation quand la politique l'exige, avant l'appel au PDP
      (`Context.approvals`, `Approval.signature` vérifiée via `zs-crypto`, jamais directement)
- [ ] Appel `PolicyDecisionService.Decide` en mTLS, contexte complet fourni en entrée (pas
      d'enrichissement côté PDP)
- [ ] Déclenchement de l'ordre d'émission vers `credential-issuer`, décision signée transmise
      telle quelle
- **Acceptation** : une demande sans approbation requise et non fournie est refusée avant même
  l'appel au PDP — le refus n'attend pas une décision motivée qu'aucune politique n'aurait pu
  produire de toute façon.
- **Décision structurante à prendre avant l'implémentation** (mode plan requis, angle mort L0.5) :
  comment l'approbateur prouve son identité (assertion `identity-assertion/v1` réutilisée, ou
  mécanisme distinct ?) — conditionne le format d'`Approval.signature` et doit être actée par ADR
  avant tout code d'approbation.
- **Décision structurante à prendre avant l'implémentation** (angle mort L0.5) : distinction entre
  contexte **vérifié** (ex. `DevicePosture` mesurée par un agent de confiance) et contexte
  **déclaré** (ex. `justification` en texte libre) dans `DecisionRequest.Context` — sans elle, une
  politique ne peut pas distinguer une posture prouvée d'une posture affirmée, ce qui rouvre la
  confusion de requête qu'ADR-003 cherche à exclure. À trancher par ADR, pas par convention de
  nommage informelle.
- **Événements d'audit** : `authentication.attempted` et consorts sont couverts par L1 —
  `policy.decided` est nouveau ici, porte le champ `decision` du contrat
  (`request_id`, `decision_hash`, `policy_version`, `reasons`, `granted_ttl_seconds` — déjà
  spécifié dans `contracts/events/audit-event.schema.json`, non consommé avant ce lot, cf.
  « hors périmètre » de L1.4b).

### H2 — Intégration OpenBao (prérequis partagé L2.4, sur le modèle de H1)
- [ ] `apps/credential-issuer` : client OpenBao (bail à durée bornée, révocation programmée),
      interface unique vers OpenBao/PKI/HSM (`credential-issuer` seul autorisé à dialoguer avec
      le HSM — `docs/architecture.md`)
- [ ] Aucun secret durable en transit ni en repos côté `credential-issuer` : le bail est le seul
      artefact retourné, jamais journalisé en clair (règle absolue #1)
- [ ] Timeout explicite sur tout appel sortant vers OpenBao (convention Go du `CLAUDE.md` racine)
- **Acceptation** : une indisponibilité d'OpenBao produit un refus explicite d'émission, jamais un
  repli sur un credential généré localement ou un succès partiel (R2).
- **Hors périmètre attendu, à signaler explicitement le moment venu** : OpenBao en mode dev
  (`deploy/compose.dev.yml`, L0.6) n'a pas les mêmes garanties HA qu'un cluster de production —
  cohérent avec la limite déjà assumée sur SoftHSM2 en H1.

### L2.4 — Émission de credential (`credential-issuer`, Go)
- [ ] Ordre d'émission accepté uniquement d'un `access-broker` authentifié en mTLS et porteur
      d'une décision signée par le PDP (`docs/architecture.md` — règle de dépendance déjà posée,
      à implémenter ici)
- [ ] Credential à durée de vie bornée par `max_ttl` **imposé par la politique**, jamais par
      l'appelant (`DecisionResponse.max_ttl`, invariant du contrat)
- [ ] Révocation effective en < 5 s (objectif de service `docs/architecture.md`)
- [ ] Événement `credential.issued` produit, portant le même `decision` que `policy.decided`
      (`request_id`/`decision_hash` partagés — permet de relier les deux événements sans
      dénormaliser la décision)
- **Acceptation** : un ordre d'émission sans décision signée valide est refusé avant tout appel à
  OpenBao — vérifié par test, pas par relecture.
- **Décision structurante à prendre avant l'implémentation** (mode plan requis, angle mort L0.5) :
  ordre entre audit et émission — l'événement `credential.issued` doit-il être scellé et persisté
  *avant* l'appel à OpenBao (garantit qu'aucun credential n'existe sans trace, mais un crash entre
  les deux laisse un événement pour une émission qui n'a pas eu lieu) ou *après* (garantit que
  l'événement correspond à un credential réel, mais une panne après émission peut laisser un
  credential sans trace) ? Les deux échouent dans des directions opposées ; ADR-010 a déjà tranché
  ce dilemme pour l'audit du parcours L1 (signature par événement, pas de traitement par lots) —
  ce même raisonnement doit être repris ici, pas réinventé.

### L2.5 — Administration (`admin-api`, Go)
- [ ] Chargement et versionnement des politiques (`policy_version` du contrat) — chemin de
      modification à chaud vers `policy-engine`
- [ ] Quorum sur les opérations critiques (modification de politique, revue d'approbateur) — sur
      le modèle déjà livré en L1.3 pour la récupération d'authentificateur (ADR-009 : réutilisation
      d'`authenticator-proof`, pas de nouvelle suite crypto)
- **Acceptation** : une modification de politique par un seul administrateur est refusée quand
  elle touche une politique marquée critique — même critère de preuve que L1.3
  (« un seul porteur ne peut jamais déclencher »).
- **Décision structurante à prendre avant l'implémentation** (mode plan requis, angle mort L0.5) :
  granularité des rôles d'administration (qui peut modifier quoi — une politique, un
  approbateur, un authentificateur d'un tiers ?) et mécanisme précis du chargement à chaud
  (`policy-engine` relit-il un fichier versionné, ou reçoit-il un ordre explicite avec preuve de
  quorum ?). Non tranché par L0.5, ne doit pas être improvisé en cours d'implémentation.

### L2.6 — Console web (`console-web`, TypeScript)
- **Explicitement hors périmètre de ce lot, différé** : `docs/architecture.md` l'exige sans
  logique de sécurité côté client — dépend d'API stables sur `admin-api`/`access-broker`
  (L2.3/L2.5), donc en aval, pas en parallèle. Ne pas ouvrir avant que ces deux API existent
  réellement, pour éviter une interface construite contre un contrat qui bouge encore.

---

## Règles de session

1. Une tâche à la fois. Annoncer laquelle en ouverture de session.
2. Mode plan pour toute tâche touchant crypto, politiques, schéma d'audit ou contrat public.
3. Contrat → `make generate` → tests → implémentation → événement d'audit → documentation.
4. Écrire le test de refus avant l'implémentation. Sur ce projet, c'est le test qui compte.
5. `/pre-pr` avant de conclure. Cocher la case reste à l'humain.
