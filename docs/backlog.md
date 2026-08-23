# Backlog — Lot L0 (socle) et amorce L1

Une session Claude Code = une tâche de ce fichier. Ouvrir une session sans tâche identifiée
produit du code plausible et non aligné.

Chaque tâche porte un critère d'acceptation vérifiable. « Ça marche » n'est pas un critère.

---

## L0 — Socle et gouvernance (semaines 1 à 4)

**Critère de passage du lot** : une contribution triviale traverse toute la chaîne et produit un
artefact signé et attesté.

### L0.1 — Squelette du dépôt et outillage
- [x] Arborescence complète (`apps/`, `crates/`, `pkg/`, `contracts/`, `policies/`, `deploy/`,
      `security/`, `tests/`, `docs/`, `tools/`) avec un `README.md` par dossier de premier niveau —
      vérifié, les dix dossiers ont chacun leur `README.md`
- [x] Workspace Cargo et modules Go initialisés (`crates/{zs-audit,zs-crypto,zs-hsm,zs-policy,
      zs-webauthn}`, `apps/{access-broker,admin-api,audit-collector,credential-issuer,
      identity-provider,policy-engine}`)
- [x] `Makefile` fonctionnel : 15 cibles présentes
- [x] `.gitignore`, `SECURITY.md`, `CODEOWNERS` — pas de `LICENSE` : dépôt propriétaire, réservé
- [x] Hooks git : `.githooks/pre-commit`, `scripts/hooks/`
- **Acceptation** : `make setup && make check` passe sur un dépôt fraîchement cloné.
- **Correction de bookkeeping** (cette session) : les quatre cases ci-dessus étaient restées
  décochées bien que livrées dans des sessions antérieures — aucun changement de code, seule la
  case reflétait un état obsolète. Vérifié par lecture directe du dépôt, pas par confiance dans
  une session précédente.

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
- [x] `contracts/cedar/schema.cedarschema.json` : namespace `ZeroSecret`, entités `Principal` et
      `Database` (un type Cedar dédié par type de ressource métier, jamais un `map` générique —
      ADR-014), action `db.connect` — mappé champ à champ sur `decision.proto`
      (`contracts/cedar/README.md` porte la table de correspondance), `Approval.signature` exclue
      du contexte Cedar (déjà vérifiée avant l'appel au PDP)
- [x] Premier corpus `policies/access/` : `db_connect.cedar` (politique nominale, AAL3 + ticket +
      approbation + posture fraîche + même domaine d'autorité) et `db_connect_guardrails.cedar`
      (trois `forbid` volontairement redondants, garde-fou anti-élargissement — ADR-014). 12 cas
      dans `policies/tests/db_connect/cases.json` : 1 nominal + les six catégories obligatoires de
      `policies/CLAUDE.md` (le sixième, « dépassement de TTL », instancié en fraîcheur de posture
      — ADR-014, `context.posture.evaluated_at` vs `context.requested_at`), avec variantes (AAL
      non renseigné, ressource de domaine voisin, posture datée dans le futur)
- [x] `policies/detection/db_connect.yml` : cinq règles Sigma (refus isolé, sondage par essais
      successifs corrélé, franchissement de domaine d'autorité, émission sans AAL3, dépassement du
      plafond de TTL) — corrige au passage `policies/README.md` (`sigma/` → `detection/`)
- **Acceptation** : `bash tools/cedar-test.sh` (`cedar validate --validation-mode strict
  --deny-warnings` puis `cedar run-tests`) — **12/12 cas passés, 0 avertissement**, exécuté
  réellement via `cargo install cedar-policy-cli --locked` sur ce poste (pas différé, contrairement
  à SoftHSM2/`cargo fuzz`). Test de mutation complémentaire : les cinq conditions du `permit` ont
  chacune été supprimées individuellement dans une copie du corpus, les cinq suppressions
  détectées par le corpus de test — démontre que chaque condition est réellement nécessaire, pas
  seulement présente.
- **`Makefile`** : la cible `cedar test --policies <dossier>` était doublement invalide (sous-
  commande inexistante côté CLI moderne, `--policies` n'accepte qu'un fichier) — remplacée par
  `bash tools/cedar-test.sh`. `|| true` conservé tel quel : le rendre bloquant suppose de
  provisionner le CLI Cedar dans le `Jenkinsfile`, hors périmètre de cette tâche (modifier une
  étape de CI exige une validation humaine explicite séparée).
- **Décisions structurantes** : voir ADR-014 (type d'entité dédié par ressource, réinterprétation
  du sixième cas d'attaque, garde-fous `forbid` redondants).
- **Surface non couverte, signalée** (ADR-014) : rejeu d'un ticket/d'une approbation déjà
  consommés, approbateur identique au demandeur, collusion de deux approbateurs, `source_network`
  déclaré mais inexploité, `posture.managed`/`disk_encrypted` déclarés mais non exigés — portée
  volontairement limitée à `db.connect`, à traiter par les politiques suivantes de L2.1+.
- **Hors périmètre, signalé** : `crates/zs-policy` non modifié (l'évaluation Cedar réelle par le
  PDP est L2.2, pas cette tâche) ; `Jenkinsfile` ne provisionne pas le CLI Cedar (vérifié — la CI
  ne peut donc pas encore exécuter `tools/cedar-test.sh` de façon bloquante).

### L2.2 — PDP (`policy-engine`, Rust)
- [x] `Decide(DecisionRequest) → DecisionResponse` (`decision.proto`) : évaluation Cedar réelle
      (`zs_policy::pdp::Pdp`, crate `cedar-policy` 4.12.0) contre le corpus L2.1 —
      `effect` par défaut `EFFECT_DENY` sur tout chemin d'erreur ou politique absente (R2).
      `apps/policy-engine` est un adaptateur mince (`tonic`) qui charge le `Pdp` une fois et
      délègue chaque appel — premier serveur réseau réel du dépôt (ADR-015)
- [x] **Aucun appel réseau pendant l'évaluation** — `Pdp::decide` est synchrone, lecture du
      corpus faite une seule fois au démarrage (`Pdp::load`), le contexte arrive intégralement en
      entrée (`DevicePosture`, `approvals`), aucun enrichissement en cours d'évaluation
- [x] `decision_hash`/`policy_version` : `zs_crypto::decision_binding` (suite
      `decision-binding/v1`, ADR-015, consultation `referent-crypto`) — pas un hash calculé dans
      `zs-policy`, pour éviter le piège du double-hachage déjà rencontré en L1.2c. `policy_version`
      = empreinte seule (`decision-binding/v1:<hex>`, validé explicitement), jamais un couple
      tag/empreinte. Scellement dans l'événement `policy.decided` reste L2.3.
- **Acceptation** : rejeu hors ligne d'une décision archivée produit exactement le même
  `effect`/`decision_hash`. **Vérifié réellement** (pas différé) : test d'intégration
  (`apps/policy-engine/tests/decide_integration.rs`) démarrant deux instances distinctes du
  service gRPC sur deux ports séparés, interrogées avec un vrai client `tonic` — même requête,
  `decision_hash`/`policy_version`/`effect` strictement identiques sur les deux.
- **Frontière posée** : `policy-engine` ne dépend d'aucun autre composant `apps/` — vérifié par le
  détecteur `apps-isolation` déjà générique (aucun nouveau test d'architecture nécessaire).
- **Traduction `Resource`/`Action`** (`contracts/cedar/README.md`, L2.1) : `Resource.type`
  inconnu ou attribut manquant → refus de traduction explicite, jamais une entité partielle.
  `Action.verb` validé contre le schéma (`Request::new(..., Some(&schema))`) : une action non
  déclarée est un refus de traduction documenté, pas un « deny » Cedar implicite par absence de
  politique — cohérent avec « schéma d'abord » (L2.1).
- **`DecisionRequest.policy_version` en entrée** : si non vide et différent de la version chargée
  par cette instance → refus explicite (`policy_version_indisponible`), jamais un repli silencieux
  sur la version courante. Le PDP sert une seule version à la fois (pas de magasin multi-version
  en mémoire) ; un rejeu relance ce même binaire déterministe contre les fichiers du commit
  historique correspondant.
- **Annotation `@id` du corpus remappée** (`PolicySet::annotation`) : `PolicySet::from_str`
  attribue des identifiants auto-générés (`policy0`, …), pas l'annotation `@id("...")` de L2.1 —
  sans ce remappage, `DecisionResponse.reasons` aurait divergé silencieusement des identifiants
  déjà référencés par les règles Sigma de L2.1 (ex. `guardrail-authority-domain-isolation`).
- **Régression découverte et corrigée** : `cedar-policy-core` active `serde_json/preserve_order`
  — Cargo unifiant les features d'une dépendance partagée sur tout le workspace compilé ensemble,
  `zs_crypto::common::canonical_bytes` (JCS, ADR-012/013) ne pouvait plus compter sur le backing
  `BTreeMap` implicite de `serde_json::Map` dès que `policy-engine` entrait dans le graphe de
  compilation (`cargo test --workspace`) — signatures `identity-assertion/v1`/`audit-seal/v1`
  déjà en production auraient cessé d'être canoniques silencieusement. Corrigé : tri explicite et
  récursif des clés (`sort_keys_recursively`), indépendant de tout backing/feature Cargo — vérifié
  octet-identique aux vecteurs figés existants (pas de régénération). Détail complet : ADR-015.
- **`tools/lib/check-no-direct-crypto.sh` étendu** (`sha2`/`sha3`/`blake3`/`digest`) : trou du
  hook comblé dans la même contribution (prérequis, pas une tâche séparée) — `sha2` n'était pas
  bloqué hors `zs-crypto`/`zs-hsm` avant ce lot.
- **Hors périmètre L2.2, signalé** : mTLS/authentification de l'appelant (aucune intégration
  SPIFFE/SPIRE dans le dépôt — prérequis d'infrastructure séparé, à traiter à l'ouverture de L2.3) ;
  `max_ttl`/`constraints` de `DecisionResponse` non calculés (dépendent de métadonnées de
  politique non encore spécifiées) ; le PDP tourne sans authentification en développement local
  uniquement.

### H3 — Service de vérification d'assertion d'identité (prérequis L2.3)
- [x] `contracts/proto/identity/v1/assertion_verification.proto` : `AssertionVerificationService.
      VerifyAssertion` — un refus cryptographique n'est jamais une erreur gRPC (P2), `valid: bool`
      + `reason` catégorisée, mêmes catégories que `identity_assertion::VerifyError`
- [x] `crates/zs-identity` (types générés uniquement, miroir de `zs-policy`) ; `apps/
      identity-provider` prend le patron `lib.rs`/`main.rs` de `policy-engine` (L2.2) — deuxième
      serveur réseau réel du dépôt. Aucune ligne de cryptographie nouvelle : traduction gRPC
      autour de `zs_crypto::identity_assertion::verify`, déjà existant (L1.2c)
- [x] Clé de vérification par variables d'environnement (`ZS_IDP_VERIFYING_KEY_HEX`/
      `ZS_IDP_VERIFYING_KEY_ID`), échec dur au démarrage si absente/malformée — **provisoire,
      signalé** : distribution/rotation réelle de la clé publique non conçue ici (ADR-016)
- **Acceptation** : test d'intégration réel (`apps/identity-provider/tests/
      verify_assertion_integration.rs`) — assertion scellée par un signeur de test déterministe,
      vérifiée via un vrai client `tonic` contre une vraie instance du service. 4 cas : nominal,
      signature altérée, assertion expirée, domaine d'autorité inattendu — tous vérifiés avec la
      raison de refus exacte, pas seulement `valid = false`.
- **`AcceptancePolicy.now` construit depuis l'horloge système**, pas reçu en entrée — différence
  assumée avec le PDP (L2.2) : une vérification en ligne EST l'appel réseau, sa fraîcheur dépend
  nécessairement de l'instant de l'appel. Formatage RFC 3339 par calcul manuel
  (`civil_from_days`, Howard Hinnant) plutôt qu'une dépendance de calendrier — format fixe et
  étroit, nouvelle dépendance non justifiée pour ça seul (règle absolue #10).
- **gRPC en clair, signalé** : aucune intégration SPIFFE/SPIRE dans le dépôt — mTLS reste un
  prérequis distinct, à traiter avant l'ouverture réelle de L2.3 côté `access-broker` ou dans un
  H-lot dédié. Décision validée explicitement par l'utilisateur pour ce lot.
- **Hors périmètre H3, signalé** : émission d'assertions (`AssertionSealer::seal`, L1.2c) non
  câblée dans un serveur — nécessite une session HSM, hors périmètre (vérification seule ne
  l'exige pas). La question « comment `access-broker` sait, avant l'appel au PDP, qu'une politique
  exige une approbation » (critère d'acceptation de L2.3) n'est pas tranchée ici.
- Voir ADR-016 pour la conception complète (contrat, clé par configuration, patron
  `lib.rs`/`main.rs`, gRPC en clair).

### L2.3 — Parcours JIT (`access-broker`, Go)
- [x] Ouverture de demande : `apps/access-broker/internal/broker` (bibliothèque testable ; entrée
      HTTP réelle livrée ensuite, voir ADR-022).
      `Context.justification` bornée à 512 caractères **appliquée** ici (documentée dans le
      contrat depuis L0.3, jamais vérifiée avant)
- [x] Sollicitation d'approbation : chaque `RawApproval` vérifiée via `identity.v1.
      AssertionVerificationService` (H3), jamais directement — une approbation invalide est
      ignorée sans annuler les autres ; **règle universelle provisoire** (ADR-017) : toute
      demande sans approbation vérifiée est refusée avant l'appel au PDP, faute d'un mécanisme de
      métadonnées par politique (la seule politique réelle aujourd'hui, `db.connect`, exige déjà
      une approbation inconditionnellement — ce n'est donc pas une simplification arbitraire)
- [x] Appel `PolicyDecisionService.Decide` réel (gRPC en clair — mTLS hors périmètre, même
      limite que L2.2/H3), contexte complet construit côté broker (`Context.requested_at` fixé
      par l'horloge du broker, jamais fourni par l'appelant — même raisonnement qu'
      `AcceptancePolicy.now`, H3/ADR-016)
- [ ] Déclenchement de l'ordre d'émission vers `credential-issuer` — **non fait** :
      `credential-issuer` est un stub vide (L2.4/H2), rien à déclencher réellement. `Broker.Decide`
      retourne la décision complète (`Allowed`, `Reasons`, `DecisionHash`, `PolicyVersion`) pour
      qu'un futur appelant l'utilise.
- **Acceptation** : une demande sans approbation vérifiée est refusée avant même l'appel au PDP —
  vérifié par test (`TestAucuneApprobationVerifieeEstRefuseeAvantAppelAuPDP`,
  `TestDemandeSansApprobationFournieEstRefuseeAvantAppelAuPDP`), pas par lecture.
- **Décisions structurantes tranchées** (ADR-017, mode plan) :
  - Approbateur : assertion `identity-assertion/v1` réutilisée, vérifiée via le service H3 —
    confirmé et implémenté, pas seulement décidé.
  - Contexte vérifié/déclaré : **non résolu, traité comme déclaré uniquement**, signalé
    explicitement en commentaire de code et en ADR — aucun agent de posture de confiance n'existe
    dans ce dépôt, un mécanisme de vérification n'a pas été inventé sans instruction. Étendu par
    cohérence à `Approval.approved_at` (H3 ne renvoie pas d'horodatage vérifié).
- **Événements d'audit** : `policy.decided` **non scellé ici** — exigerait un service Rust de
  scellement symétrique à H3, inexistant. `authentication.attempted` et consorts restent couverts
  par L1.
- **Pas de test d'intégration réel avec de vrais serveurs** (contrairement à L2.2/H3), raison
  structurelle : `tools/lib/check-no-direct-crypto.sh` interdit tout import crypto Go direct,
  **sans l'exemption de test que Rust possède** (`mod tests { ... }`) — un test Go ne peut pas
  fabriquer sa propre assertion signée, même à des fins de test. Tests locaux avec doublures des
  interfaces gRPC générées (7 cas, tous les chemins de refus + le chemin nominal + la propagation
  d'erreur de transport).
- Voir ADR-017 pour la conception complète et les conséquences négatives assumées.

### H2 — Intégration OpenBao (prérequis partagé L2.4, sur le modèle de H1)
- [x] `apps/credential-issuer/internal/openbao` : client OpenBao générique — `IssueLease`/
      `Revoke`, agnostique du moteur de secrets (quel moteur pour quel verbe reste une décision
      de L2.4). `github.com/openbao/openbao/api/v2` (MPL-2.0), pas le client Vault (BUSL-1.1) —
      cohérent avec ADR-002 (ADR-018)
- [x] Aucun secret durable en transit ni en repos : `Lease.String()`/`GoString()` masquent les
      données du bail, vérifié par test (`%v`/`%+v` ne fuitent jamais le secret injecté) — règle
      absolue #1
- [x] Timeout explicite sur tout appel sortant (`context.WithTimeout`, 5 s par défaut) — vérifié
      par test avec un délai réellement mesuré, pas seulement déclaré
- **Acceptation** : indisponibilité (5xx, connexion refusée, timeout, réponse sans bail
  exploitable) → `ErrUnavailable` explicite, jamais un bail partiel — vérifié par test avec un
  serveur `httptest` simulant chacun de ces cas.
- **Authentification par jeton en variable d'environnement, provisoire et signalée** (ADR-018) :
  même patron que H3 — mécanisme de production (AppRole, Kubernetes auth) non conçu ici.
- **Retries désactivés explicitement** (`MaxRetries = 0`) plutôt que le défaut de la bibliothèque
  cliente : un retry automatique masquerait une indisponibilité réelle derrière un délai
  variable — politique de retry authentique à instruire séparément si nécessaire.
- **Hors périmètre attendu, signalé** : test d'intégration réel contre un vrai OpenBao
  (`deploy/compose.dev.yml`, L0.6) **non exécuté** — Podman/Docker bloqués sur ce poste, même
  limite que SoftHSM2 (H1). `apps/credential-issuer/main.go` reste un stub — H2 livre la
  bibliothèque, pas le binaire (cohérent avec H1, qui n'a câblé aucun `main.go` non plus).
- Voir ADR-018 pour la conception complète.

### H4 — Signature de décision (prérequis L2.4)
- [x] Nouvelle suite `crates/zs-crypto::decision_seal` (`decision-seal/v1`) : message signé
      fermé — `request_id`, `decision_hash`, `policy_version`, `effect`, `reasons`, `max_ttl`,
      `constraints`, `issued_at` — jamais `decision_hash` isolément (un `effect` substitué sous
      un `decision_hash` valide serait sinon indétectable, vérifié par test dédié)
- [x] Clé HSM dédiée `zs-decision-seal-v1`, troisième clé séparée (ADR-011)
- [x] `contracts/proto/policy/v1/decision.proto` : `DecisionResponse` gagne `issued_at`,
      `decision_signature`, `decision_signature_key_id` ; nouveau RPC `VerifyDecision` — un refus
      cryptographique n'est jamais une erreur gRPC (P2, même discipline que H3)
- [x] `apps/policy-engine` ouvre une session HSM au démarrage (nouvelle dépendance `zs-hsm`),
      scelle systématiquement (ALLOW et DENY) après `Pdp::decide` — `Pdp::decide` reste pur, sans
      HSM (voir ci-dessous). Vérification hébergée dans `policy-engine` lui-même
      (`VerifyDecision`), clé de vérification dérivée du scelleur — pas de configuration séparée
- **Acceptation** : 9 tests unitaires `decision_seal` avec signeur déterministe — scellement/
  vérification nominale, `effect`/`reasons`/`max_ttl` substitués sous un `decision_hash` valide
  → refusés, clé/suite inconnue → refusée, signature absente → refusée explicitement.
- **Règle absolue #5 réinterprétée, `CLAUDE.md` non modifié** (décision validée) : elle porte sur
  les entrées de la décision (déterminisme, rejeu hors ligne) — le scellement de la réponse est
  une étape postérieure et isolée, documentée dans ADR-019 plutôt que gravée dans la gouvernance.
- **Vérification hébergée dans `policy-engine`, pas un nouveau composant** (décision validée) :
  même patron que H3. Compromis de défense en profondeur assumé et signalé (signataire =
  vérificateur).
- **Régression de couverture de test assumée et signalée** : le test d'intégration réel de L2.2
  (`decide_integration.rs`, deux instances, même `decision_hash`) exige désormais SoftHSM2 réel
  (`policy_engine::serve` requiert un `DecisionSealer`) — `#[ignore]`, `ZS_HSM_MODULE` requis,
  même limite que H1. Signalé explicitement comme une régression causée par ce lot, pas une
  limite préexistante glissée sous le tapis.
- **Hors périmètre H4, signalé** : `request_id` absent de `DecisionResponse` (choix de contrat
  antérieur à L2.2, non révisé) — le message signé porte une valeur vide pour ce champ,
  documenté explicitement dans le code, pas oublié silencieusement.
- Voir ADR-019 pour la conception complète.

### L2.4 — Émission de credential (`credential-issuer`, Go)
- [x] `apps/credential-issuer/internal/issuer` (bibliothèque testable, pas de serveur gRPC/HTTP
      dans ce lot — aucun contrat `access-broker → credential-issuer` n'existe, même coupe que
      L2.3). Ordre d'émission vérifié via `PolicyDecisionService.VerifyDecision` (H4) avant tout
      appel à OpenBao — refus explicite si invalide, absente, ou `effect != ALLOW`
- [x] `max_ttl` **imposé par la décision vérifiée**, jamais par l'appelant : le TTL transmis à
      OpenBao vient exclusivement de `DecisionResponse.max_ttl` (déjà signé) — `EmissionOrder`
      n'a aucun champ pour une durée alternative, vérifié par test
- [x] `Revoke` : wrapper direct du client OpenBao (H2), timeout déjà imposé (5 s) — pas de mesure
      réelle du délai possible sans OpenBao réel (même limite que H2)
- [x] `IssuedCredentialEvent` **construit**, portant `decision_hash`/`policy_version`/`reasons`
      partagés avec `policy.decided` comme demandé — **pas scellé** (voir hors périmètre)
- **Acceptation** : un ordre d'émission sans décision valide est refusé avant tout appel à
  OpenBao — vérifié par test (`TestDecisionInvalideEstRefuseeAvantAppelOpenBao`,
  `TestEffectDenyEstRefuseSansAppelOpenBao`, `TestVerbeNonSupporteEstRefuse`), le double
  `LeaseIssuer` n'étant jamais appelé dans ces cas.
- **Ordre audit/émission tranché par réapplication de R7** (ADR-008/012), pas réinventé (mode
  plan, angle mort L0.5) : `event_id` (UUIDv7) généré **avant** l'appel à OpenBao ;
  `credential.issued` construit seulement **après** un succès réel — un événement ne doit jamais
  affirmer l'existence d'un credential non réellement émis. Fenêtre de répudiation résiduelle
  assumée (crash entre succès OpenBao et écriture de l'événement), déjà anticipée par
  `security/threat-models/credential-issuer.md`.
- **Le risque Tampering du modèle de menaces est confirmé fermé par H4** : le message signé
  `decision-seal/v1` couvre `max_ttl`/`effect`/`reasons`/`constraints` directement, pas seulement
  `decision_hash` — l'angle mort documenté en L0.5 n'en est plus un.
- **Mapping verbe → moteur OpenBao minimal et explicite** : seul `db.connect` instrué (seule
  politique réelle, L2.1) → `database/creds/{resource.id}`. Tout autre verbe refusé
  explicitement (`moteur_non_supporte`), cohérent avec le risque EoP du modèle de menaces.
- **Port `ConsumedDecisionStore`, sans implémentation — prévention de rejeu NON assurée** : le
  modèle de menaces liste explicitement ce scénario ; sans stockage persistant (scope-cut DB
  cohérent avec L1.1/L1.2/L1.4), un ordre rejoué serait aujourd'hui honoré une seconde fois — gap
  réel, signalé, pas silencieux.
- **Nouvelle dépendance `github.com/google/uuid`** (BSD-3-Clause) : génération d'UUIDv7 pour
  `event_id` — aucune génération UUIDv7 n'existait encore nulle part dans ce dépôt (Rust comme
  Go, seulement des validateurs/littéraux de test). Pas une opération cryptographique au sens de
  la règle absolue #4 (identifiant unique, pas une primitive de sécurité).
- **Hors périmètre, signalé** : `credential.issued` non scellé (exigerait un service Rust d'audit
  symétrique à H3/H4, inexistant, comme `policy.decided` en L2.3) ; aucun serveur réseau ; mTLS.
- Voir ADR-020 pour la conception complète.

### L2.5 — Administration (`admin-api`, Go)
- [x] Quorum sur les opérations critiques : `apps/admin-api/internal/quorum` — sur le modèle
      déjà livré en L1.3 pour la récupération d'authentificateur (ADR-009 : réutilisation
      d'`identity-assertion/v1` via H3, pas de nouvelle suite crypto). Plancher
      `MinimumThreshold = 2` imposé par le module, non contournable (même garde-fou
      qu'`zs_webauthn::recovery::verify_quorum`)
- [ ] Chargement et versionnement des politiques (`policy_version` du contrat), chemin de
      modification à chaud vers `policy-engine` — **non fait, portée réduite assumée** (voir
      ci-dessous)
- **Acceptation** : un seul porteur ne peut jamais atteindre le quorum, même avec plusieurs
  assertions valides du même `subject_id` (rejeu ou double soumission) — vérifié par test
  (`TestUnSeulPorteurNePeutJamaisDeclencherMemeAvecPlusieursAssertions`), qui compte les
  porteurs **distincts**, pas le nombre brut d'assertions.
- **Décision de portée** (mode plan, angle mort L0.5) : `security/threat-models/admin-api.md`
  documente déjà que la granularité des rôles d'administration et le chemin de modification à
  chaud des politiques sont « non tranchés, à clarifier avant L2 » — les trancher sans
  instruction supplémentaire aurait inventé une politique d'autorisation non voulue (même
  discipline que H2/H3/L2.3 : pas de mécanisme non instruit improvisé). L2.5 livre uniquement ce
  qui a un critère d'acceptation concret et déjà spécifié — le quorum — et hérite les deux
  questions ouvertes du modèle de menaces telles quelles, pas résolues ici.
- **`VerifyQuorum` agnostique de l'opération et du rôle** : ne sait pas quelle opération critique
  il protège ni qui a le droit de l'initier — l'appelant fournit le domaine d'autorité attendu et
  les assertions, le module ne fait que compter des porteurs distincts vérifiés. Conception
  délibérément étroite pour rester réutilisable quel que soit le futur système de rôles.
- **`apps/admin-api/internal/quorum`, bibliothèque d'abord** — entrée HTTP réelle livrée
  ensuite, voir ADR-022. Pas de test d'intégration réel signé (même limite structurelle que
  L2.3/L2.4 : `check-no-direct-crypto.sh` sans exemption de test côté Go).
- Voir ADR-021 pour la conception complète.

### Entrée HTTP réelle (`access-broker`, `admin-api`, `contracts/openapi/`)
- [x] `contracts/openapi/{access-broker,admin-api}.yaml` (OpenAPI 3.1, source de vérité) +
      `tools/generate-openapi.sh` (`oapi-codegen`, câblé dans `make generate`) — premier
      outillage de génération HTTP Go de ce dépôt.
- [x] `POST /v1/access-requests` (`access-broker`) et
      `POST /v1/critical-operations/{operation_id}/quorum` (`admin-api`) : `main.go` cesse
      d'être un stub dans les deux apps, premier vrai serveur HTTP côté Go (symétrique à
      `policy-engine`/`identity-provider` côté Rust).
- [x] Authentification du demandeur par assertion `identity-assertion/v1` en en-tête
      (`X-Identity-Assertion`), vérifiée via H3 avant toute construction de requête interne —
      jamais un `Principal` accepté depuis le corps JSON.
- **Décision de portée** : un seul appel synchrone par endpoint, pas de collecte incrémentale
  d'approbations/quorum (magasin d'état persistant hors périmètre, même famille que
  `ConsumedDecisionStore`, L2.4). Pas de TLS/mTLS (signalé, même limite que partout ailleurs).
- **Événement d'audit** : aucun nouveau — ces endpoints ne font que traduire HTTP vers les
  bibliothèques déjà auditées (`broker.Decide`, `quorum.VerifyQuorum`), qui ne produisent
  toujours pas d'événement scellé côté Go (même limite que L2.3/L2.4/L2.5).
- Voir ADR-022 pour la conception complète.

### H5 — Cérémonie WebAuthn HTTP (`identity-provider`, prérequis à L2.6)
- [x] `contracts/openapi/identity-provider.yaml` (source de vérité documentée, sans générateur
      Rust — voir ADR-023) : `POST /v1/webauthn/{registration,authentication}/{challenge,verify}`.
- [x] `apps/identity-provider/src/store.rs` : premier driver Postgres du dépôt (`sqlx`), deux
      pools/rôles distincts (`identity_app`, `audit_writer`) — jamais le même pool pour les deux
      schémas.
- [x] `apps/identity-provider/src/httpapi.rs` : implémentation réelle de `ChallengeStore`/
      `SignCounterStore` (sémantique async, pas les traits synchrones de `zs-webauthn` — voir
      ADR-023), premier appelant applicatif de `AssertionSealer::seal` **et**
      `AuditSealer::seal` (deux clés HSM, deux scellements par authentification réussie, règle
      absolue #9 respectée dans le même lot — décision explicite, pas de dette).
- [x] `crates/zs-crypto::authenticator_proof::accept_challenge` — ajout validé (`referent-crypto`
      + validation humaine explicite) pour réhydrater un `Challenge` depuis des octets persistés,
      trou d'API découvert en cours d'implémentation (aucun serveur sans état n'existait avant
      H5). Voir addendum ADR-006.
- [x] `deploy/migrations/005_audit_events_sealed_bytes.sql` — colonne `sealed_bytes` sur
      `audit.events`, nécessaire pour dériver `prev_hash` sans réimplémenter JCS hors zs-crypto.
- [x] `apps/identity-provider/tests/http_ceremony.rs` — bout en bout réel (SoftHSM2 + Postgres),
      `#[ignore]` par défaut, même discipline que `crates/zs-hsm/tests/pkcs11_integration.rs` :
      enregistrement puis authentification nominal, rejeu de challenge refusé, signature
      invalide refusée.
- **Décision de portée** (mode plan + `AskUserQuestion`) : bootstrap du tout premier facteur non
  résolu — `subject_id` accepté tel quel à l'enregistrement, aucun mécanisme d'invitation/admin
  instruit. Angle mort documenté (ADR-023, modèle de menaces), pas caché.
- Voir ADR-023 pour la conception complète, y compris le patron `spawn_blocking` autour de
  chaque appel HSM (défaut identifié mais non corrigé dans `policy-engine`, hors périmètre).

### L2.6 — Console web (`console-web`, TypeScript)
- [x] Premier code réel : `node:http` natif, zéro dépendance runtime (`typescript`/`@types/node`
      en devDependency uniquement) — même esprit qu'ADR-022 (Go)/ADR-023 (Rust, `axum` minimal).
- [x] Login WebAuthn (enregistrement + authentification, relais vers `identity-provider` H5) et
      demande d'accès (relais vers `access-broker`), flux à un seul utilisateur, testé de bout
      en bout (`apps/console-web/src/server.test.ts`, 21 tests, faux serveurs HTTP en process).
- [x] Session opaque côté serveur (`crypto.randomBytes(32)`, jamais un JWT), cookie
      `__Host-session`, rotation à chaque authentification, purge active périodique — voir
      ADR-024 pour la conception complète (frontière crypto TypeScript, liste blanche fermée).
- [x] Échappement HTML systématique (`src/html.ts`, tagged template, testé contre une charge XSS)
      et contrôle `Origin`/`Sec-Fetch-Site` sur tout `POST` (CSRF, `SameSite=Strict` jugé
      insuffisant seul).
- **Décision de portée** (mode plan + `AskUserQuestion`) : écran quorum (`admin-api`) différé à
  L2.6b (fait, voir ci-dessous) — flux à plusieurs porteurs s'authentifiant séparément,
  structurellement différent d'un flux à un seul utilisateur, hors périmètre de ce lot.
- **Angle mort hérité, pas résolu ici** : bootstrap du premier facteur (H5/ADR-023) —
  `console-web` transmet le `subject_id` saisi tel quel, aucune authentification préalable.
- Voir ADR-024 pour la conception complète.

### L2.6b — Écran quorum (`console-web` → `admin-api`)
- [x] `GET /quorum`/`POST /quorum` — formulaire **single-shot** (`operation_id`, `threshold`,
      `expected_authority_domain`, assertions base64 standard réunies hors bande, une par
      ligne) ; session requise pour y accéder, mais la session de l'opérateur n'est pas comptée
      comme l'une des assertions du quorum.
- [x] `apps/console-web/src/clients/admin-api.ts` — nouveau client HTTP fin, même patron que
      `clients/access-broker.ts` (base64 standard, jamais base64url).
- **Décision de portée** (mode plan + `AskUserQuestion`) : **aucune coordination temps réel
  entre porteurs** — qui crée l'`operation_id`, comment les autres l'apprennent, reste un angle
  mort non résolu (déjà signalé par ADR-022 : « collecte incrémentale » différée faute de
  magasin persistant tranché). Résoudre cet angle mort exigerait un nouvel état serveur
  (magasin d'opérations en attente) — décision structurante non instruite, pas inventée ici.
- **Correctif trouvé en écrivant les tests de refus** (pas un ajout de portée, un bogue
  préexistant de L2.6) : `sendPage()` réinitialisait toujours `res.statusCode` à `200` après
  qu'un appelant l'ait positionné à `400`/`401`/`502` — toute page d'erreur HTML de L2.6
  (`/access-request` compris) était donc renvoyée avec un statut `200` trompeur. Corrigé en
  ajoutant un paramètre `status` explicite à `sendPage()`. Aucun test de L2.6 n'exerçait
  auparavant un chemin de refus rendu en HTML (seuls les chemins JSON, via `send()`, étaient
  couverts) — d'où l'angle mort resté invisible jusqu'ici.
- 29 tests au total dans `apps/console-web` (`node --test`), dont les nouveaux tests de
  `/quorum` (session requise, refus relayé, assertion mal encodée refusée avant tout appel
  réseau).

---

## Règles de session

1. Une tâche à la fois. Annoncer laquelle en ouverture de session.
2. Mode plan pour toute tâche touchant crypto, politiques, schéma d'audit ou contrat public.
3. Contrat → `make generate` → tests → implémentation → événement d'audit → documentation.
4. Écrire le test de refus avant l'implémentation. Sur ce projet, c'est le test qui compte.
5. `/pre-pr` avant de conclure. Cocher la case reste à l'humain.
