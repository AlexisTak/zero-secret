# Audit du projet zero-secret

**Date** : 2026-08-24
**Périmètre** : intégralité du dépôt à la révision `1ef11dd` (branche `main`)
**Méthode** : lecture du code source, des contrats, des politiques, des ADR, des modèles de
menaces et de la chaîne d'intégration continue. Vérification contradictoire des règles absolues
énoncées dans `CLAUDE.md` contre l'état réel du code — aucune règle n'est réputée respectée sur la
seule foi de sa documentation.
**Auditeur** : revue automatisée assistée. Les constats sont accompagnés de leur preuve
(`fichier:ligne`) afin d'être rejouables par un tiers.

---

## 1. Synthèse à l'usage du décideur

Le projet présente une **discipline d'ingénierie de sécurité nettement au-dessus de la moyenne** :
les règles architecturales ne sont pas seulement écrites, elles sont mécaniquement vérifiées par
des détecteurs statiques bloquants en intégration continue. Le refus par défaut est réellement
implémenté dans le moteur de politiques. Aucun secret durable n'a été détecté. La séparation des
responsabilités entre composants est respectée sans exception.

Trois réserves toutefois, dont une bloquante :

1. **Un déni de service à distance est atteignable** sur le service `policy-engine` (§3.1).
2. **La cible `make test-crypto` ne peut pas s'exécuter** : elle référence une fonctionnalité Cargo
   qui n'existe pas. Les vecteurs Wycheproof exigés par le `CLAUDE.md` de `zs-crypto` sont donc
   absents, et personne ne s'en est aperçu car cette cible n'est pas appelée en CI (§3.2).
3. **La trajectoire post-quantique n'est pas engagée dans le code**, alors que l'échéance ANSSI
   2027 est structurante pour la qualification du produit (§5.3).

| Domaine | Verdict | Détail |
|---|---|---|
| Isolation architecturale | Conforme | §4.1 |
| Refus par défaut | Conforme | §4.2 |
| Gestion des secrets | Conforme | §4.3 |
| Façade cryptographique | Conforme | §4.4 |
| Chaîne d'audit | Conforme, limite documentée | §4.5 |
| Conformité RGPD | Conforme | §4.6 |
| Robustesse aux entrées réseau | **Violation** | §3.1 |
| Tests de conformité crypto | **Violation** | §3.2 |
| Couverture de tests | **Non mesurée** | §3.3 |
| Préparation post-quantique | Non engagée | §5.3 |
| Complétude du schéma d'audit | Partielle, assumée | §5.1 |
| Politiques de plateforme (Rego) | Absentes | §5.2 |

**Volumétrie** : 21 475 lignes hors code généré et dépendances — 10 446 Rust (53 fichiers),
7 906 Go (46 fichiers), 1 724 TypeScript (12 fichiers), 908 shell (17 fichiers), 390 Protobuf,
101 Cedar. 33 décisions d'architecture actées, 8 modèles de menaces STRIDE.

---

## 2. Ce que le projet fait bien, et qu'il faut préserver

Ces points méritent d'être signalés en propre : ils constituent le socle sur lequel les correctifs
ci-dessous viendront s'appuyer, et une régression sur l'un d'eux serait plus coûteuse que les
défauts identifiés.

**Les règles architecturales sont exécutables, pas déclaratives.** `tools/check-arch.sh` enchaîne
cinq détecteurs statiques réels — isolation des applications, interdiction de la crypto directe,
frontière WebAuthn/HSM (ADR-008), couverture CBOM (ADR-011), dépendances de `zs-crypto` (ADR-012) —
puis vérifie la fraîcheur des fichiers générés. Ces détecteurs sont eux-mêmes testés contre des
fixtures volontairement violantes (`tests/architecture/`). La règle qui n'est pas testée n'existe
pas ; ici elles le sont.

**Le refus par défaut est structurel, pas conventionnel.** `Pdp::decide`
(`crates/zs-policy/src/pdp.rs:134-190`) retourne `deny(...)` sur *tout* chemin d'erreur : version
de politique inconnue (ligne 142), échec de traduction (ligne 151), type de ressource non reconnu
(lignes 400-401). Les garde-fous Cedar (`policies/access/db_connect_guardrails.cedar:16-42`)
s'appuient sur `forbid`/`unless`, qui l'emporte toujours sur un `permit` en sémantique Cedar.
Aucun `unwrap_or(true)` ni valeur par défaut permissive n'a été trouvé.

**Les tests d'attaque dominent les tests nominaux.** `policies/tests/db_connect/cases.json` compte
1 cas d'autorisation contre 11 cas de refus explicitement nommés (`refus-a-…` à `refus-f-…`,
incluant un cas d'escalade). Ce ratio de 1:11 est exactement l'inverse de ce qu'on observe
habituellement, et c'est la bonne direction.

**Les limites connues sont documentées comme telles, pas dissimulées.** Le test
`troncature_en_queue_de_chaine_nest_pas_detectee` (`crates/zs-audit/src/chain.rs:216-231`) fige
explicitement une faiblesse assumée du chaînage plutôt que de la laisser implicite. C'est une
pratique d'audit exemplaire : le lecteur tiers sait ce qui n'est pas couvert et pourquoi (ici,
compensation par `audit.chain_verified` et l'ancrage périodique de l'ADR-031).

**L'API cryptographique expose des intentions, jamais des algorithmes.** `seal`, `verify`,
`accept_verifying_key` — conformément à l'invariant 2 de `crates/zs-crypto/CLAUDE.md`. Aucune
signature de fonction `ecdsa_sign` ou équivalent n'affleure la surface publique.

---

## 3. Constats bloquants

### 3.1 — Déni de service à distance sur `policy-engine` (critique)

**Emplacement** : `apps/policy-engine/src/lib.rs:159-160`, atteignable depuis
`apps/policy-engine/src/lib.rs:100` (`verify_decision`, handler gRPC).

**Règle enfreinte** : `CLAUDE.md` — *« Pas de `panic!` atteignable depuis une entrée réseau »* et
*« Pas de `unwrap()` ni `expect()` hors tests et démarrage »*.

**Chaîne d'exploitation** :

```
verify_decision (gRPC, entrée réseau)          lib.rs:100
  └─ decision.issued_at.seconds                 lib.rs:115   ← valeur contrôlée par l'appelant
      └─ rfc3339_from_seconds(seconds)          lib.rs:193
          └─ format!("{year:04}-…")             lib.rs:200   ← largeur MINIMALE 4, non bornée
              └─ Timestamp::new(chaîne)         common.rs:57 ← exige bytes.len() == 20 exactement
                  └─ Err(FieldError)            common.rs:69
                      └─ .expect(…)             lib.rs:160   ← PANIC
```

Le spécificateur `{year:04}` de Rust impose une largeur *minimale* de quatre caractères, pas une
largeur maximale. Pour `seconds` correspondant à une année supérieure à 9999 — ou négative, le
signe consommant un caractère supplémentaire — la chaîne produite dépasse ou n'atteint pas les
20 octets exigés par `Timestamp::new`. La validation échoue correctement, mais le `.expect()` de
la ligne 160 transforme ce refus légitime en panique du processus.

Le commentaire de la ligne 160 — *« rfc3339_now/rfc3339_from_seconds produisent toujours un format
valide »* — est vrai pour `rfc3339_now()`, dont l'entrée provient de l'horloge système, mais faux
pour `rfc3339_from_seconds()` lorsque son argument vient du réseau. L'invariant a été établi pour
un appelant, puis la fonction a été réutilisée par un second appelant qui ne le respecte pas.

**Impact** : un client gRPC capable d'atteindre le point d'entrée `verify_decision` provoque
l'arrêt du processus `policy-engine` avec une requête unique et triviale. En architecture de
décision d'accès, l'indisponibilité du PDP est un incident de sécurité, non un simple incident de
disponibilité : les composants appelants doivent alors refuser, ce qui est correct, mais bloque
l'ensemble des accès légitimes.

**Facteur atténuant** : le point d'entrée est protégé par mTLS SPIFFE, ce qui restreint la surface
aux composants internes déjà authentifiés. Cela réduit la probabilité, pas la sévérité — un
composant compromis ou un client mal formé suffit.

**Correctif recommandé** : propager l'erreur au lieu de paniquer. `decision_fields` doit renvoyer
un `Result`, et `verify_decision` traduire l'échec en `VerifyDecisionResponse { valid: false,
reason: "issued_at_invalide" }` — cohérent avec le traitement déjà appliqué aux cas
`decision_absente` (ligne 109) et `issued_at_absent` (ligne 119). La forme du correctif existe
donc déjà dans la fonction ; il s'agit d'étendre le motif au troisième cas d'échec.

**Test de non-régression à écrire** : appel `verify_decision` avec `issued_at.seconds = i64::MAX`,
puis avec une valeur négative de grande amplitude — le service doit répondre `valid: false` et
rester vivant.

### 3.2 — La cible `make test-crypto` ne peut pas s'exécuter

**Emplacement** : `Makefile:61-65`.

```makefile
test-crypto:
	cargo test -p zs-crypto --features conformance -- --include-ignored
	cargo test -p zs-webauthn --features conformance -- --include-ignored
```

Ni `crates/zs-crypto/Cargo.toml` ni `crates/zs-webauthn/Cargo.toml` ne déclarent de section
`[features]`. La fonctionnalité `conformance` n'existe pas ; la commande échoue immédiatement.

**Conséquence directe** : les *« vecteurs de test Wycheproof et vecteurs officiels de chaque
spécification, exécutés en CI »* exigés par `crates/zs-crypto/CLAUDE.md` sont **absents du dépôt**.
`tests/vectors/` ne contient que `audit-seal-v1/chain.json`, vecteur propre au projet et non issu
d'un corpus externe de conformité. Aucun vecteur Wycheproof, aucun vecteur de conformité WebAuthn
officiel.

**Cause racine du silence** : la cible `test-crypto` n'est appelée par aucun workflow
(`.github/workflows/ci.yml` ne la mentionne pas). Une cible cassée qui n'est jamais invoquée ne
produit aucun signal. C'est le mode de défaillance le plus coûteux d'une chaîne de vérification :
l'absence de test est indiscernable du test qui passe.

**Correctif recommandé, en deux temps** :
1. Rendre la cible exécutable — soit en déclarant réellement la fonctionnalité `conformance` dans
   les deux crates, soit en retirant le drapeau si les tests doivent toujours s'exécuter.
2. Intégrer les corpus de vecteurs manquants et appeler la cible en CI. Sans le second point, le
   premier ne fait que rendre visible un test vide.

### 3.3 — Le seuil de couverture de tests n'est mesuré nulle part

`CLAUDE.md` exige une couverture ≥ 85 % sur `crates/` et `pkg/`, ≥ 95 % sur `zs-crypto`,
`zs-policy` et `zs-audit`. Le `CLAUDE.md` de `zs-crypto` renchérit : *« Une ligne non couverte dans
ce crate doit être justifiée. »*

Aucun outil de mesure n'est configuré dans le dépôt : ni `cargo-tarpaulin`, ni `cargo-llvm-cov`, ni
`go test -coverprofile`, ni configuration `codecov`. Aucun job d'intégration continue ne calcule ni
n'impose ces seuils.

L'exigence est donc **purement déclarative**. La couverture réelle est inconnue — elle peut être
excellente, rien ne permet de l'affirmer ni de détecter une régression. Pour un produit destiné à
l'audit par un CESTI, l'incapacité à produire un chiffre de couverture est un point de friction
prévisible.

**Correctif recommandé** : ajouter `cargo-llvm-cov` (couverture Rust, compatible workspace) et
`go test -coverprofile` au workflow, avec échec du job sous les seuils énoncés. Commencer par
mesurer sans bloquer pendant une itération, afin de connaître l'écart réel avant de le rendre
opposable.

---

## 4. Vérification des règles absolues

Chaque règle du `CLAUDE.md` racine a été confrontée au code.

### 4.1 — Isolation des applications (règle 7) : **conforme**

Aucun composant de `apps/` n'en importe un autre. Tous les `Cargo.toml` d'applications ne
dépendent que de `crates/` (exemple : `apps/identity-provider/Cargo.toml` → `zs-webauthn`,
`zs-audit`, `zs-crypto`, `zs-hsm`, `zs-identity`). Tous les `go.mod` ne référencent que `pkg/gen`.
La règle est vérifiée mécaniquement par `tools/lib/check-apps-isolation.sh`, appelé via
`tools/check-arch.sh` en CI (`.github/workflows/ci.yml:96`).

### 4.2 — Refus par défaut (règle 2) : **conforme**

Détaillé au §2. Aucun chemin de repli permissif détecté.

### 4.3 — Aucun secret durable (règle 1) : **conforme**

Aucun secret en dur détecté dans le code, les tests, les fixtures ou les fichiers de déploiement.
Le matériel sensible transite par `secrecy::SecretString` et des variables d'environnement
(`apps/identity-provider/src/main.rs:81`, `apps/policy-engine/src/main.rs:49`,
`crates/zs-hsm/src/pool.rs:35`) ou par OpenBao. `deploy/compose.dev.yml:4-5,12,26-27` documente
explicitement la génération à l'exécution des PIN et jetons de développement. Détection continue
par gitleaks, à la fois en CI (job `secrets`) et en pré-commit (`.githooks/pre-commit`).

### 4.4 — Toute crypto passe par `zs-crypto` (règles 3 et 4) : **conforme**

Aucun import direct de `ring`, `rustls`, `aws-lc-rs`, `p256`, `ed25519-*` ou `crypto/*` hors de
`zs-crypto` et `zs-hsm`. Les seules occurrences d'`aws-lc-rs` sont en `dev-dependencies` et sous
`#[cfg(test)]` (`crates/zs-webauthn/src/registration.rs:274-275`), ce que le détecteur exempte
légitimement — il retire les modules de test avant analyse.

**Précision utile pour un lecteur tiers** : le `CLAUDE.md` évoque un « hook `no-direct-crypto` ».
Il existe en réalité deux mécanismes distincts, et c'est le second qui fait foi.
`scripts/hooks/no-direct-crypto.sh` est un garde-fou de session pour l'assistant, déclaré dans
`.claude/settings.json` ; il n'est pas installé comme hook git. Le contrôle opposable est
`tools/lib/check-no-direct-crypto.sh`, exécuté par `make check` et par la CI. Le hook git réel
(`.githooks/pre-commit`) ne réalise que la détection de secrets et le contrôle de formatage. Cette
distinction mérite d'être clarifiée dans le `CLAUDE.md`, car un auditeur cherchant « le hook »
trouverait le mauvais fichier.

### 4.5 — Chaîne d'audit vérifiable (règle 9) : **conforme, avec limite documentée**

`crates/zs-audit/src/chain.rs` couvre par des tests la racine invalide, le trou de séquence, la
séquence dupliquée et le `prev_hash` incohérent. Vecteurs figés dans
`tests/vectors/audit-seal-v1/chain.json`, rejoués par `crates/zs-audit/tests/chain_vectors.rs:18`.
La non-détection de la troncature en queue de chaîne est explicitement testée et assumée
(`chain.rs:216-231`), compensée par l'événement `audit.chain_verified` et par l'ancrage périodique
en cours d'instruction (ADR-031).

### 4.6 — RGPD, aucune donnée biométrique côté serveur : **conforme**

`apps/identity-provider/src/store.rs:28-30,143-166` ne persiste que `credential_id`, `public_key`,
`sign_count`, `algorithm` et `aaguid` — usage WebAuthn standard, sans stockage de gabarit
biométrique. Le schéma d'audit interdit explicitement les données biométriques et les données
personnelles non nécessaires (`contracts/events/audit-event.schema.json:85`).

### 4.7 — `policy-engine` déterministe, sans appel réseau (règle 5) : **conforme**

`Pdp::load` (`crates/zs-policy/src/pdp.rs:65-125`) ne réalise que des lectures de fichiers, au
démarrage. `Pdp::decide` (ligne 134) ne comporte aucune entrée-sortie : posture, approbations et
ticket arrivent par le paramètre `DecisionRequest`. Le seul appel externe du service est le
scellement HSM, postérieur à l'évaluation et isolé dans `spawn_blocking`
(`apps/policy-engine/src/lib.rs:83`), avec justification en commentaire (lignes 11-14).

### 4.8 — `contracts/` source de vérité (règle 8) : **conforme**

Les fichiers de `pkg/gen/**/*.pb.go` portent le marqueur `// Code generated … DO NOT EDIT`.
`Makefile:32-39` régénère via `buf generate` et `tools/generate-openapi.sh`.
`tools/check-arch.sh:44-68` vérifie en CI que les fichiers générés sont à jour, ce qui empêche la
divergence silencieuse redoutée par le `CLAUDE.md`.

### 4.9 — Conventions de langage : **conforme (Rust hors §3.1), conforme (Go)**

`#![forbid(unsafe_code)]` est appliqué globalement via `[workspace.lints.rust]`
(`Cargo.toml:15-16`) et hérité par tous les crates. `crates/zs-hsm/Cargo.toml` déroge
explicitement, avec justification en commentaire renvoyant à l'ADR-001 — exception documentée et
donc conforme.

Côté Go : aucune erreur ignorée en code applicatif (les seuls `_ = err` sont dans du code généré
par `oapi-codegen`), aucun `http.Client` sans délai d'expiration, aucun `exec.Command` sans
contexte. Un point mineur : `apps/audit-collector/internal/collector/collector.go:29` déclare
`chainRoot` en `var` plutôt qu'en constante — aucune mutation actuelle, mais rien ne s'y oppose
structurellement. Go n'offre pas de `const []byte` ; une fonction accesseur retournant une copie
lèverait l'ambiguïté. Sévérité faible.

### 4.10 — Aucune logique de sécurité côté client : **conforme**

`apps/console-web/public/webauthn.ts:3` énonce explicitement que le client *« ne décide jamais si
une assertion est valide »*. Le code se limite au relais des réponses brutes de l'authentificateur.

---

## 5. Écarts non bloquants et dette identifiée

### 5.1 — Six types d'événements d'audit sans producteur

Le schéma `contracts/events/audit-event.schema.json:26-42` définit 16 valeurs d'`event_type`.
L'énumération `EventType` de `crates/zs-audit/src/record.rs:18-38` n'en couvre que 10.

Sans producteur dans le code : `access.approved`, `access.denied`, `credential.expired`,
`credential.revoked`, `policy.modified`. `access.requested` n'apparaît que dans un test
d'`audit-sealer` vérifiant qu'il est **rejeté** (`apps/audit-sealer/src/lib.rs:273`).

L'écart est documenté comme intentionnel — les lots ultérieurs les produiront
(`record.rs:15-16`) — et ne constitue donc pas une violation de la règle 9, qui interdit
d'ajouter une fonctionnalité *sans* son événement, non de spécifier un événement en avance de
phase. Il reste que six schémas orphelins dans un contrat public sont une ambiguïté pour un
intégrateur tiers, qui ne peut distinguer « pas encore produit » de « produit mais non observé ».

**Recommandation** : marquer ces valeurs comme réservées dans le schéma, par un commentaire ou un
champ de statut, afin que l'intention soit lisible depuis le contrat seul.

### 5.2 — Les politiques de plateforme Rego n'existent pas

`CLAUDE.md` annonce *« Cedar (accès) + Rego/OPA (plateforme) »* et `Makefile:59` exécute
`opa test policies/platform policies/tests`. Or `policies/` ne contient que deux fichiers Cedar,
une règle Sigma et un jeu de cas de test — **aucun fichier `.rego`**, et le répertoire
`policies/platform` n'existe pas.

La commande est neutralisée par un `|| true` et n'échoue donc jamais. Le `|| true` est
explicitement justifié en commentaire pour `cedar-test.sh` — provisionner le CLI Cedar en CI
demanderait une validation humaine — mais cette justification a été étendue de fait à `opa test`,
qui porte sur un répertoire inexistant.

Il s'agit d'une divergence entre la documentation et l'état réel, non d'un défaut de sécurité : le
volet plateforme n'est simplement pas encore commencé. À corriger dans un sens ou dans l'autre —
soit en implémentant les politiques, soit en retirant la mention jusqu'à leur arrivée.

### 5.3 — Trajectoire post-quantique : instruite, non engagée

**Ce qui existe** : les cinq suites cryptographiques réelles sont versionnées et déclarées dans
`security/crypto-inventory/suites.toml` (`identity-assertion/v1`, `audit-seal/v1`,
`decision-seal/v1`, `decision-binding/v1`, `authenticator-proof/v1`). Chacune porte un champ
`successor` désignant sa cible hybride et un champ `anssi_2027_compliant = false`. Le CBOM est
régénéré en CI (`ci.yml:130-134`) et correspond exactement au code. La lucidité de l'inventaire est
à porter au crédit du projet : rien n'est présenté comme conforme alors qu'il ne l'est pas.

**Ce qui manque** : aucune ligne de code post-quantique. `channel-kex` (X25519) n'existe que
mentionné en commentaire (`crates/zs-crypto/src/lib.rs:7`). `crates/zs-hsm/src/mechanism.rs:9-13`
n'expose qu'une variante, `EcdsaP256Sha256`, avec `MlDsa65` explicitement noté absent
(lignes 7-8). Les seules occurrences de `"ml-dsa-65"` dans le code sont des chaînes factices
servant à tester le **refus** d'un composant hybride inconnu (`audit_seal.rs:1393`,
`identity_assertion.rs:626`) — ce qui est un bon test, mais n'est pas une implémentation.

**Ce qui bloque** : les trois ADR portant le sujet sont au statut *proposé*, non accepté —
ADR-030 (audit-seal v2 hybride), ADR-031 (ancrage périodique), ADR-032 (socle ML-DSA-65). Ils sont
mutuellement dépendants : ADR-030 est explicitement bloqué par ADR-031 et ADR-032.

**Appréciation** : l'échéance ANSSI de 2027 interdit la qualification des produits dépourvus de
composante post-quantique. Au rythme d'instruction actuel, et compte tenu du fait que
l'implémentation ne peut commencer qu'après acceptation d'ADR-032, la marge se réduit. Le risque
n'est pas la qualité de la trajectoire — elle est sérieuse et bien documentée — mais le délai
entre la décision et le code. Le déblocage d'ADR-031 et ADR-032 est le chemin critique du projet.

### 5.4 — Zones de la chaîne de vérification non couvertes par la CI

Cinq cibles du `Makefile` n'ont aucun équivalent en intégration continue :

| Cible | Statut | Conséquence |
|---|---|---|
| `test-crypto` | Cassée (§3.2) | Vecteurs de conformité absents, silencieusement |
| `fuzz` | Jamais appelée | Trois cibles de fuzzing existent mais ne tournent pas |
| `test-e2e` | Jamais appelée | Nécessite Podman, indisponible sur les exécuteurs GitHub |
| `replay` | **Cassée** | Référence le crate `zs-replay`, absent du workspace |
| `opa test` | Sans objet (§5.2) | Répertoire cible inexistant, neutralisée par `|| true` |

Le cas du fuzzing mérite attention : les cibles existent et sont pertinentes
(`zs-crypto/fuzz/fuzz_targets/{audit_seal_verify,identity_assertion_verify}.rs`,
`zs-webauthn/fuzz/fuzz_targets/attestation_parser.rs`) — ce sont exactement les analyseurs
d'entrée que le `CLAUDE.md` de `zs-crypto` exige de fuzzer. Elles ne sont simplement jamais
exécutées automatiquement. Un job nocturne de fuzzing à durée bornée corrigerait l'écart à faible
coût. On notera d'ailleurs que le défaut du §3.1 relève précisément de la classe de bogues qu'un
fuzzing du chemin `verify_decision` aurait révélée.

Le cas de `make replay` est plus net : la cible invoque `cargo run -p zs-replay`, or aucun crate de
ce nom ne figure dans les membres du workspace (`Cargo.toml:3-14`) ni dans `crates/`. La commande
`make replay`, présentée dans le `CLAUDE.md` comme un moyen de rejouer les décisions depuis le
journal d'audit, ne peut pas s'exécuter. Cette capacité de rejeu étant un argument de vérifiabilité
central du produit, son absence devrait être signalée ou la cible retirée.

### 5.5 — SBOM et CBOM non versionnés

`security/crypto-inventory/cbom.json` et `security/sbom/**/*.json` sont exclus par `.gitignore`
(lignes 26-27) et absents de l'index git. Ils sont régénérés en CI et publiés comme artefacts
GitHub Actions à rétention de 90 jours.

Le règlement CRA impose un SBOM à chaque version. Une rétention de 90 jours ne permet pas de
produire le SBOM d'une version publiée il y a plus de trois mois. La reconstruction reste possible
par rejeu de la révision correspondante, mais suppose que l'environnement de construction soit
reproductible — le job `reproducible-build` existe, en mode informatif seulement.

**Recommandation** : attacher SBOM et CBOM aux artefacts de publication (release GitHub ou registre
équivalent), avec la même durée de conservation que la version qu'ils décrivent. Le stockage dans
le dépôt n'est pas nécessaire et générerait du bruit de diff ; l'attachement à la version l'est.

### 5.6 — Divergence sur le décompte des ADR

Le message d'accueil de session annonce « 34 ADR ouverts ». Le décompte réel est de **33 ADR
numérotés**, dont **29 acceptés, 1 remplacé** (ADR-005, par ADR-033) et **3 proposés**
(ADR-030, 031, 032, tous datés du 2026-08-24 et portant la mention explicite de ne pas passer à
« accepté » avant arbitrage).

Trois décisions ouvertes, non trente-quatre. L'indicateur du script d'accueil compte
vraisemblablement les fichiers plutôt que les statuts. Sans gravité, mais un indicateur faux est
pire qu'aucun indicateur : il donne une impression de dette d'instruction considérable là où la
situation est saine.

### 5.7 — Modèles de menaces : périmètre applicatif uniquement

Les huit applications de `apps/` disposent chacune d'un modèle STRIDE
(`security/threat-models/`), de bonne facture — celui de `policy-engine` comporte un tableau
complet par catégorie avec risque résiduel assumé et explicité (par exemple la fuite d'information
possible via le champ libre `justification`, limité à 512 caractères).

Aucun modèle de menaces ne couvre en propre les crates `zs-crypto`, `zs-hsm`, `zs-policy`,
`zs-webauthn` et `zs-audit`. Ils sont traités implicitement à travers les applications qui les
consomment. Cette approche est défendable — une bibliothèque n'a pas de surface d'attaque propre
indépendamment de son appelant — mais elle laisse un angle mort sur les invariants transverses,
typiquement l'invariant 5 d'hybridation stricte de `zs-crypto`, qui n'appartient à aucune
application en particulier. Le défaut du §3.1 illustre cette zone grise : il naît précisément de la
réutilisation d'une fonction dont l'invariant d'entrée n'était garanti que pour son premier
appelant.

---

## 6. Plan d'action proposé

Par ordre de priorité décroissante.

**Immédiat**
1. Corriger le `panic!` réseau de `apps/policy-engine/src/lib.rs:159` en propageant l'erreur, et
   ajouter le test de non-régression décrit au §3.1. Correctif de faible ampleur, sévérité élevée.

**Court terme**
2. Rendre `make test-crypto` exécutable, puis intégrer les vecteurs Wycheproof et les vecteurs de
   conformité WebAuthn, et appeler la cible en CI (§3.2).
3. Ajouter un job nocturne de fuzzing à durée bornée sur les trois cibles existantes (§5.4).
4. Corriger ou retirer `make replay`, qui référence un crate inexistant (§5.4).
5. Mettre en place la mesure de couverture, sans seuil bloquant lors de la première itération, afin
   de connaître l'écart réel (§3.3).

**Moyen terme**
6. Arbitrer ADR-031 et ADR-032 — chemin critique de la trajectoire post-quantique (§5.3).
7. Attacher SBOM et CBOM aux artefacts de publication, avec la conservation requise par le CRA
   (§5.5).
8. Clarifier dans le `CLAUDE.md` la distinction entre garde-fous de session et contrôles opposables
   en CI, afin qu'un auditeur tiers identifie le bon mécanisme (§4.4).
9. Trancher le sort des politiques Rego : les implémenter ou retirer leur mention (§5.2).
10. Marquer comme réservés les six types d'événements non encore produits (§5.1).
11. Corriger l'indicateur d'ADR ouverts du script d'accueil (§5.6).

---

## 7. Conclusion

Le projet est, sur le fond, bien construit. La qualité rare tient à ce que les règles y sont
**exécutables** : détecteurs statiques bloquants, tests d'attaque majoritaires, limites connues
consignées explicitement plutôt que tues. Un auditeur tiers y trouvera de quoi étayer ses constats
sans avoir à interroger les auteurs, ce qui est l'objectif énoncé par le `CLAUDE.md`.

Les défauts identifiés partagent une cause commune : **ils vivent dans les angles morts de la
chaîne de vérification automatisée**. Le `panic!` réseau se trouve sur un chemin qui n'est pas
fuzzé ; les vecteurs de conformité manquent parce que la cible qui devrait les exécuter n'est
jamais invoquée ; la couverture est inconnue parce qu'elle n'est pas mesurée. Là où les contrôles
tournent, le code est conforme sans exception. Là où ils ne tournent pas, la dette s'accumule
silencieusement.

La recommandation structurante n'est donc pas d'écrire davantage de règles, mais de **fermer
l'écart entre les cibles du `Makefile` et les jobs d'intégration continue**. Une cible qui n'est
jamais appelée finit par se casser sans que personne ne le sache — trois l'ont déjà fait
(`test-crypto`, `replay`, `opa test`).

L'échéance ANSSI 2027 constitue le risque de calendrier principal. La trajectoire est correctement
instruite et honnêtement documentée ; c'est le passage à l'implémentation qui n'a pas commencé, et
il dépend d'un arbitrage humain sur ADR-031 et ADR-032.
