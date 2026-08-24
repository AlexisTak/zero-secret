# ADR-030 — Passage de `audit-seal` à la suite hybride v2 (ECDSA P-256 + ML-DSA-65)

**Statut** : proposé — ne pas passer à « accepté » avant arbitrage des questions ouvertes en fin
de document.
**Date** : 2026-08-24
**Auteurs** : instruction `referent-crypto`, à relire par le porteur du projet.

## Contexte

### L'échéance

L'ANSSI cesse en 2027 d'accepter en qualification/certification les produits dépourvus de
composante post-quantique ; les certifications existantes restent valides jusqu'à expiration
mais leur renouvellement est conditionné à la conformité PQC. La doctrine ANSSI impose
l'**hybridation** (composante pré-quantique + composante post-quantique), pas la substitution —
ce qui correspond exactement à l'invariant 5 de `crates/zs-crypto/CLAUDE.md`. Sources :
[cyber.gouv.fr — Cryptographie post-quantique](https://cyber.gouv.fr/enjeux-technologiques/cryptographie-post-quantique/),
[INCYBER, 2026](https://incyber.org/article/lanssi-integre-le-post-quantique-a-ses-exigences-de-certification/).

Pour un journal d'audit, l'échéance est plus dure qu'ailleurs : la valeur probante d'un
événement scellé doit survivre à sa date d'émission. Un événement signé en 2026 sous ECDSA P-256
seul est un événement dont la non-répudiation s'éteint le jour où un CRQC existe. C'est le seul
endroit du dépôt où « harvest now, forge later » a un sens.

### L'état actuel

`audit-seal/v1` (ECDSA P-256/SHA-256, clé HSM `zs-audit-seal-v1`, ADR-010/011/013) est
**l'opération HSM la plus fréquente du système** : une signature par action métier. Trois
producteurs Go y sont câblés via le pont `audit-sealer` (ADR-026) :

| Producteur | Événement | ADR |
|---|---|---|
| `access-broker` | `policy.decided` | ADR-027 |
| `admin-api` | `quorum.operation` | ADR-028 |
| `credential-issuer` | `credential.issued` | ADR-029 |

Auxquels s'ajoute `identity-provider` (appelant Rust direct, ADR-023).

Trois constats issus de la lecture du code, qui déterminent tout le reste :

1. **Le format v1 a été conçu pour v2.** `contracts/events/audit-event.schema.json` porte déjà
   `"audit-seal/v2"` dans l'enum `signature.suite`, cite déjà `ml-dsa-65` en exemple de
   `component`, et impose déjà un conteneur à N composantes dont l'arité est fixée par la suite.
   `schema_version` est `const: 1` et n'est **pas** couplé à la version de suite. **Le passage v2
   ne casse aucun contrat.**
2. **Il n'existe aujourd'hui aucun vérificateur `audit-seal` en production.** `audit_seal::verify`
   n'est appelé que depuis `crates/zs-audit/tests/chain_vectors.rs` et la cible de fuzzing. La
   surface de la période de recouvrement se réduit donc à deux points
   (`accept_verifying_key`, `AcceptancePolicy::accepted_suites`). **Migrer maintenant coûte une
   fraction de ce que ça coûtera après l'ouverture d'`audit-collector` en lecture.**
3. **Les dépendances sont déjà en place.** `Cargo.lock` verrouille `aws-lc-rs 1.18.0` — la version
   qui a précisément stabilisé les API ML-DSA (`ML_DSA_65`, `PqdsaKeyPair`,
   `PqdsaVerificationAlgorithm`, sorties de `unstable`) — et `cryptoki 0.12.0`, qui expose déjà
   `MechanismType::ML_DSA`, `Mechanism::MlDsa(..)` et la famille `HashMlDsa*` de PKCS#11 v3.2.

## Instruction

### 1. Disponibilité ML-DSA-65 côté PKCS#11

**Norme.** PKCS#11 v3.2 (OASIS) définit `CKM_ML_DSA` (ML-DSA pur, FIPS 204),
`CKM_ML_DSA_KEY_PAIR_GEN`, et la famille `CKM_HASH_ML_DSA[_SHA256|...]` (HashML-DSA, FIPS 204
§5.4). Le vocabulaire est donc normalisé — pas de mécanisme vendeur.

**`cryptoki` 0.12.0 (déjà dans `Cargo.lock`)** : `MechanismType::ML_DSA`,
`Mechanism::MlDsa(dsa::SignAdditionalContext)`, `Mechanism::HashMlDsaSha256(..)` sont présents.
**Aucune montée de version, aucune nouvelle dépendance côté liaison PKCS#11.**

**SoftHSM2 (dev) : NON — c'est le point bloquant.** La demande de support ML-DSA est l'issue
[softhsm/SoftHSMv2#800](https://github.com/softhsm/SoftHSMv2/issues/800), ouverte le 22/07/2025,
**toujours ouverte**, sans jalon, sans branche, sans réponse publique de mainteneur. SoftHSM2 est
adossé à Botan/OpenSSL pour ses primitives et son rythme de release est lent (2.6.1 date de
2020). **Il faut planifier v2 en supposant que SoftHSM2 ne supportera pas ML-DSA à l'horizon
utile.**

Alternatives de développement/test, par ordre de préférence :

| Option | Avantage | Coût / risque |
|---|---|---|
| A. Kryoptic (jeton PKCS#11 logiciel Rust, Red Hat, PKCS#11 3.2, support ML-DSA/ML-KEM) | vrai PKCS#11, remplace SoftHSM2 sans toucher `zs-hsm` | nouvelle dépendance d'outillage, maturité à auditer, changement de `make setup` |
| B. OpenSSL 3.5+ derrière `pkcs11-provider` | OpenSSL 3.5 a ML-DSA nativement | chaîne indirecte, comportement PKCS#11 moins fidèle |
| C. Fournisseur PKCS#11 de test interne | maîtrisé | exclu : ce serait écrire un jeton crypto, contraire à l'invariant 1 |
| D. SoftHSM2 pour ECDSA, ML-DSA en logiciel `aws-lc-rs` en dev uniquement | zéro outillage nouveau | crée un chemin « ML-DSA hors HSM » — acceptable seulement si mode de test explicitement nommé, refusé au démarrage en prod, couvert par un test de refus |

**Tranché (Q1, 2026-08-24) : A — Kryoptic**, avec D comme filet temporaire strictement encadré si
Kryoptic s'avère indisponible ou trop immature à l'implémentation.

**HSM matériel qualifié ANSSI (prod).** À ce jour, aucun HSM disposant d'un **visa de sécurité
ANSSI portant sur ML-DSA** n'est identifiable de manière fiable : les grands fournisseurs
(Thales Luna, Utimaco, Entrust nShield, Atos/Eviden Trustway) annoncent du firmware PQC, mais le
périmètre certifié/qualifié est en cours de renouvellement chez tous. **C'est le risque
calendaire dominant de cet ADR** : notre code peut être prêt en 2026 sans qu'un HSM qualifié
ML-DSA soit disponible en 2027. Action en cours (Q2, tranché 2026-08-24) : le porteur du projet
sollicite directement les fournisseurs par écrit sur le périmètre `CKM_ML_DSA` et le statut
visa/qualification ANSSI associé — réponses à venir.

### 2. Bibliothèque pour la composante ML-DSA-65 côté Rust

Point d'architecture d'abord : **la signature ML-DSA se fait dans le HSM, pas en Rust.**
`zs-crypto` n'a besoin que de la **vérification** (et d'un signeur de test hors chemin de
production, comme `p256` l'est déjà pour v1). Le besoin est donc étroit.

**Candidat retenu : `aws-lc-rs` — déjà présent, version 1.18.0 déjà verrouillée.**

- **Statut** : ML-DSA stabilisé en 1.18.0 (sorti de `unstable`, disponible sous `fips`).
  Constantes `ML_DSA_44/65/87` (vérification) et `ML_DSA_44/65/87_SIGNING`.
- **API compatible avec le code existant** :
  `UnparsedPublicKey::new(&ML_DSA_65, pk_bytes).verify(message, sig)` — exactement la forme déjà
  utilisée pour `ECDSA_P256_SHA256_FIXED` (`audit_seal.rs`). L'impact sur `verify()` se réduit à
  choisir l'algorithme par composante au lieu de le coder en dur.
- **Licence** : Apache-2.0 / ISC — OSI, pas de copyleft fort.
- **Maintenance / audit** : AWS, releases régulières, AWS-LC dérive de BoringSSL/OpenSSL, module
  FIPS 4.x validé, fuzzing et vérification formelle continus sur une partie du code. C'est déjà la
  bibliothèque de référence du projet pour ECDSA et WebAuthn (`crates/zs-webauthn`).
- **CVE** : aucune CVE ouverte connue sur `aws-lc-rs` ; historique court, traité en amont. À
  reconfirmer via `cargo audit` au moment de l'implémentation.

**Note importante sur l'API** : `PqdsaVerificationAlgorithm::parsed_verify_digest_sig` retourne
désormais toujours `Unspecified` — ML-DSA pur **ne se vérifie pas à partir d'un condensat**. Voir
§3, c'est structurant.

Candidats écartés :

| Bibliothèque | Pourquoi écartée |
|---|---|
| `fips204` (pure Rust) | ajout d'une dépendance là où `aws-lc-rs` couvre déjà le besoin ; règle absolue #10 |
| `ml-dsa` (RustCrypto) | écarté en production ; **retenu comme signeur de test indépendant** (miroir du rôle de `p256` aujourd'hui), voir Q3 tranchée |
| `libcrux-ml-dsa` | vérification formelle attrayante, mais dépendance supplémentaire, écosystème plus étroit ; à réévaluer si `aws-lc-rs` régressait |

**Conclusion : aucune nouvelle dépendance Rust n'est nécessaire pour la composante ML-DSA en
production.** C'est le point le plus favorable du dossier.

### 3. Le point de conception le moins évident : ML-DSA ne signe pas un condensat

`AuditSealer::seal` fait aujourd'hui :

```rust
let digest = common::sha256(&message);
self.pool.sign_digest(&self.key, SigningMechanism::EcdsaP256Sha256, &digest)
```

`CKM_ML_DSA` signe **le message**, pas un condensat. Deux voies :

- **(a) ML-DSA pur (`CKM_ML_DSA`)** : le message canonique complet (jusqu'à `MAX_BYTES`) doit
  traverser la frontière PKCS#11 à chaque signature. Conforme FIPS 204 §5.2, aucune ambiguïté.
- **(b) HashML-DSA (`CKM_HASH_ML_DSA_SHA256`)** : pré-hachage normalisé FIPS 204 §5.4, préserve le
  modèle « on n'envoie que 32 octets au HSM ». La sémantique exacte des paramètres PKCS#11 (message
  vs condensat fourni) doit être **vérifiée sur la spec v3.2 et sur le HSM cible**, pas supposée.
  HashML-DSA et ML-DSA pur produisent des signatures **non interchangeables** : le choix est figé
  dans la suite.

Conséquence sur `zs-hsm` dans les deux cas : `HsmSigner::sign_digest` ne suffit plus, il faut une
opération qui transporte le message (ou un condensat accompagné de son OID). C'est une
modification de `crates/zs-hsm` et une variante de plus dans l'énumération `SigningMechanism`,
dont le commentaire de `mechanism.rs` anticipe déjà l'ajout (`MlDsa65`), en exigeant ADR +
validation humaine — c'est ce document.

**Tranché (Q4, 2026-08-24) : (a), ML-DSA pur.** Moins de surface d'interprétation, meilleur
alignement avec la doctrine « pas de construction maison » ; le coût est un transfert de ~8 Kio
par signature vers le HSM, mesurable et probablement négligeable devant le coût de la signature
ML-DSA elle-même — à confirmer par mesure (§5), sans remettre en cause le mécanisme lui-même
sauf si la mesure s'avère rédhibitoire.

### 4. Impact taille — mesuré

Mesure faite par sérialisation JCS réelle de documents `policy.decided` représentatifs (même
construction que `unsigned_document`, `key_id` de 16 caractères hex conformément à
`key_id_from_public_key`, valeurs de signature aux longueurs exactes : 64 o → 128 car. hex pour
ECDSA P-256, **3309 o → 6618 car. hex** pour ML-DSA-65). Le contrat impose l'hexadécimal
(`pattern: ^[0-9a-f]+$`), donc **le facteur 2 sur l'encodage n'est pas négociable sans changer le
contrat**.

| Scénario | Doc non signé | Total v1 | Total v2 | Marge vs 8192 |
|---|---|---|---|---|
| `policy.decided` nominal, 1 raison courte | 904 | 1 151 | 7 834 | −358 (tient de justesse) |
| nominal + `target` + `context` (justif. 120 o) | 1 248 | 1 495 | 8 178 | −14 (tient à 14 octets près) |
| 16 raisons de 64 o | 1 909 | 2 156 | 8 839 | +647 → dépasse |
| 16 raisons de 256 o (max contrat) | 4 981 | 5 228 | 11 911 | +3 719 |
| pire cas, tous champs à leur borne | 7 211 | 7 458 | 14 141 | +5 949 |
| pire cas + `decision_signature` hybride recopiée (`decision-seal/v2`) | 13 829 | 14 076 | 20 759 | +12 567 |
| nominal + `decision_signature` hybride recopiée | 7 522 | 7 769 | 14 452 | +6 260 |

Surcoût pur du bloc `signature` : **247 octets en v1 → 6 930 octets en v2 (+6 683)**.

**Conclusions fermes :**

1. `MAX_BYTES = 8192` **doit être relevé**. Un `policy.decided` réaliste avec `target` +
   `context` passe à 14 octets près : c'est un piège, pas une marge.
2. **`MAX_BYTES` ne peut pas rester une constante unique.** Elle est appliquée avant le parse,
   donc avant que la suite soit connue. Il faut :
   - une **borne d'entrée** = maximum sur toutes les suites acceptées (protection anti-DoS du
     parseur, seule garde possible avant parse) ;
   - une **borne par suite** réappliquée **après** résolution de `signature.suite`, pour que v1
     conserve sa sémantique exacte (un document v1 de 10 Kio doit rester refusé) ;
   - `signature_overhead_bytes()` (émission) doit devenir dépendante de la suite : le calcul
     actuel code en dur `REQUIRED_COMPONENTS_V1[0]` et 128 caractères.
3. **Valeur proposée : `MAX_BYTES_V2 = 32768`** (32 Kio). Couvre le pire cas mesuré incluant une
   `decision_signature` hybride recopiée (20 759 o) avec ~1,6× de marge, sans être une borne
   molle. `MAX_BYTES_V1` reste **8192**, inchangé.
4. **Le cas à surveiller est le couplage `decision-seal/v2` → `audit-seal/v2`** : quand
   `decision-seal` passera lui aussi en hybride, sa signature recopiée dans
   `decision.decision_signature` (ADR-027) ajoutera à elle seule +6 618 caractères hex à
   l'événement. C'est le principal argument en faveur d'un traitement coordonné (§6).

**Reste de la chaîne :**

- **Transport gRPC** (`contracts/proto/audit/v1/sealing.proto`, `bytes sealed_bytes`) : aucune
  limite explicite configurée côté tonic ni côté grpc-go ; les défauts (4 Mio en réception)
  laissent trois ordres de grandeur de marge. Aucun impact. Recommandation annexe : profiter de v2
  pour fixer explicitement ces limites plutôt que d'hériter d'un défaut (durcissement, pas
  correctif).
- **Stockage Postgres** (`audit.events.sealed_bytes bytea`, migration 005) : aucun changement de
  schéma, `bytea` non borné. Mais le seuil TOAST de Postgres est ~2 Kio : en v1 (~1,2 Kio nominal)
  la colonne reste inline ; en v2 (~7,8 Kio) **chaque ligne bascule en stockage TOAST hors ligne**.
  Conséquence : ~1 déréférencement TOAST supplémentaire par événement lors de la vérification de
  chaîne, qui lit `sealed_bytes` séquentiellement. Volumétrie : **×6,8 sur le journal d'audit**,
  l'objet le plus volumineux et le plus rétentionné du système. Chiffré (Q5, 2026-08-24) :
  ~700 Go sur 5 ans en v2 (scénario nominal, hypothèse ~50 000 événements/jour), contre ~105 Go
  qu'aurait représenté la même charge en v1 seul — détail complet en fin de document.

### 5. Latence — protocole de mesure (non mesurable aujourd'hui)

**Aucune mesure possible aujourd'hui** : aucun jeton PKCS#11 disponible dans ce dépôt ne fait
ML-DSA (cf. §1). Toute valeur donnée ici serait une estimation, ce que
`crates/zs-crypto/CLAUDE.md` interdit explicitement pour une nouvelle suite. Protocole à exécuter
**avant** de passer cet ADR à « accepté » :

1. Bench `zs-hsm` isolé : `sign_digest` ECDSA P-256 vs `sign` ML-DSA-65, p50/p95/p99, sur le
   jeton de dev retenu **et** sur le HSM matériel cible.
2. Bench de bout en bout `AuditSealer::seal` v1 vs v2, avec le pool de sessions réel, à la taille
   de document nominale **et** au pire cas.
3. Bench de `verify` v1 vs v2 (vérification ML-DSA en logiciel `aws-lc-rs`, chemin le plus chaud
   d'un rejeu de chaîne complet).
4. Test de saturation du pool : v2 fait **deux opérations HSM par événement** au lieu d'une, sur
   l'opération la plus fréquente du système. Le dimensionnement `pool_size` établi pour v1 est à
   réévaluer, pas à reconduire.

Point de conception associé, indépendant de la mesure : les deux signatures sont produites
séquentiellement. Si la seconde échoue, l'événement **ne doit pas être émis partiellement** et
**ne doit pas être réessayé** — ADR-011 interdit déjà le réessai (ECDSA randomisé, risque de
fourche de chaîne). Comportement attendu : `SealError::SealingUnavailable`, la chaîne n'avance
pas, refus par défaut. À couvrir par un test d'échec injecté sur chaque composante.

### 6. Stratégie de recouvrement pour l'historique v1

**Un ré-scellement rétroactif de l'historique n'est ni possible ni souhaitable.**

- **Pas possible sans destruction de preuve** : `prev_hash` de l'événement N+1 est le SHA-256 des
  octets scellés de N, signature comprise (`zs_audit::hash_sealed_event`). Re-signer N en v2
  change ses octets, donc son hash, donc invalide le chaînage de tout ce qui suit. Un
  ré-scellement n'est pas une migration : c'est une réécriture complète de la chaîne.
- **Pas souhaitable** : un journal d'audit dont l'exploitant peut réécrire les entrées passées
  avec des signatures valides perd sa propriété fondamentale. La capacité technique de ré-sceller
  est elle-même une vulnérabilité — c'est précisément ce contre quoi ADR-010 protège en isolant la
  clé `audit-seal`.
- Un ré-scellement ne ferait de toute façon pas ce qu'on en attend : il attesterait que
  l'exploitant détenait ces octets *au moment du ré-scellement*, pas que l'événement a eu lieu à sa
  date d'origine. La propriété perdue (non-répudiation post-quantique de l'historique) **ne se
  rattrape pas**.

**Stratégie proposée — trois volets :**

**(a) Recouvrement asymétrique, conforme à l'invariant 4.**
- Vérification : `accepted_suites = ["audit-seal/v1", "audit-seal/v2"]`, sans date d'expiration
  pour v1. L'historique reste vérifiable indéfiniment ; retirer v1 de la vérification rendrait le
  journal illisible, ce qui est pire que non-PQC.
- Émission : v2 exclusivement, à partir d'une date de bascule `T`. Aucun chemin de code ne doit
  permettre d'émettre en v1 après `T` — pas un drapeau de configuration, une constante.
- Un vérificateur doit refuser explicitement un événement v1 de séquence ≥ à celle de la bascule
  (voir (b)) : accepter v1 partout après `T` rouvrirait une attaque par rétrogradation de suite sur
  les événements *nouveaux*.

**(b) Marquer la frontière dans la chaîne elle-même.** À la bascule, émettre un événement
charnière (type `audit.chain_verified`, déjà réservé au contrat) **scellé en v2** dont le
`prev_hash` couvre le dernier événement v1. Cet événement lie cryptographiquement — sous une
signature hybride — la tête de la chaîne pré-quantique. Effet réel : un adversaire disposant d'un
CRQC peut forger une signature ECDSA sur un événement v1 isolé, mais **ne peut pas réinsérer cet
événement dans la chaîne** sans casser le `prev_hash` scellé en ML-DSA de l'événement charnière.
La borne v2 protège rétroactivement l'intégrité positionnelle de tout l'historique v1, à défaut
d'en protéger la non-répudiation individuelle. C'est le meilleur rattrapage disponible et il ne
coûte presque rien. Cette construction rejoint l'ancrage périodique laissé en suspens par le
commentaire d'`EventType::AuditChainVerified` — d'où une question de portée (Q6).

**(c) Documenter le risque résiduel accepté.** À inscrire dans
`security/threat-models/audit-sealer.md` et dans l'entrée CBOM : « Les événements scellés sous
`audit-seal/v1` avant `T` reposent sur ECDSA P-256 seul. Leur non-répudiation individuelle ne
résiste pas à un adversaire quantique cryptographiquement pertinent. Leur intégrité positionnelle
dans la chaîne est protégée par l'événement charnière v2. Risque résiduel accepté, non remédiable
sans réécriture de la chaîne, laquelle est un risque supérieur. »

**Clés.** Deux clés HSM neuves — `zs-audit-seal-v2-ecdsa-p256` et `zs-audit-seal-v2-ml-dsa-65`.
Jamais de réutilisation de `zs-audit-seal-v1` : ADR-013 pose déjà que la version vit dans le
label. `HsmSettings.key_label: String` doit donc devenir un jeu de labels par composante —
modification d'API publique de `zs-crypto`. `accept_verifying_key` doit également devenir
dépendante de la composante : la garde actuelle (65 octets SEC1, `0x04`) est spécifique ECDSA ;
une clé publique ML-DSA-65 fait 1952 octets et ne doit pas passer par ce contrôle.

**Ce qui est déjà correct et ne doit pas être touché** : la boucle de vérification accumule déjà
avec un `&=` sans court-circuit, l'arité et l'ordre des composantes sont vérifiés avant toute
crypto, et `component` n'est jamais utilisé pour *choisir* un vérificateur (comparaison par
égalité à ce que la suite impose) — le piège d'« algorithm confusion » est déjà fermé.
L'invariant 5 (hybridation stricte) est structurellement supporté par le code v1 ; v2 n'a qu'à le
peupler. C'est le dividende du travail d'ADR-012/013.

### 7. Portée : `audit-seal` seul, ou les trois suites d'émission ?

Trois suites d'émission visent la même hybridation : `audit-seal/v2`, `identity-assertion/v2`,
`decision-seal/v2`.

**Avis : un effort coordonné, mais des ADR et des bascules séparés.**

- **Ce qui doit être coordonné** — le socle est rigoureusement commun et le dupliquer trois fois
  est la garantie de trois divergences : variante `SigningMechanism::MlDsa65` de `zs-hsm`,
  opération de signature sur message, `accept_verifying_key` dépendant de la composante, borne de
  taille en deux étages, vérification par composante, corpus de vecteurs ML-DSA (Wycheproof +
  vecteurs ACVP FIPS 204), outillage de dev PKCS#11 PQC. Un ADR socle « composante ML-DSA-65 dans
  `zs-crypto` et `zs-hsm` » est justifié, dont ADR-030 serait la première application.
- **Ce qui ne doit pas être couplé** — les profils de risque diffèrent nettement. `audit-seal` a
  le besoin PQC le plus fort (valeur probante longue durée) et, aujourd'hui, le coût de migration
  le plus faible (aucun vérificateur en production). `identity-assertion` est consommé par un
  service de vérification réel (ADR-016) : sa bascule impose une coordination inter-composants.
  `decision-seal` est un objet à durée de vie de quelques secondes, dont l'urgence PQC est
  objectivement moindre — sa signature vit néanmoins **recopiée durablement** dans les événements
  `audit-seal` (ADR-027/029), ce qui est un couplage de taille (§4) mais pas de sécurité.
- `audit-seal` est le bon premier candidat, et sa bascule doit précéder l'ouverture
  d'`audit-collector` en lecture. Chaque événement scellé en v1 d'ici là est un événement à
  recouvrement définitif.
- **Ordre proposé** : ADR socle → `audit-seal/v2` (ADR-030) → `identity-assertion/v2` →
  `decision-seal/v2`. Point d'attention : lors de la bascule `decision-seal/v2`, revérifier la
  borne de taille d'`audit-seal/v2` (mesure « pire cas + decision_signature hybride » =
  20 759 o ci-dessus) — c'est la raison pour laquelle 32768 est proposé dès maintenant plutôt
  qu'une valeur ajustée au besoin du jour.

## Décision proposée

1. Créer `audit-seal/v2` = ECDSA P-256/SHA-256 + ML-DSA-65, deux composantes, arité et ordre
   `["ecdsa-p256", "ml-dsa-65"]` imposés par la suite, hybridation stricte (les deux valides ou
   refus).
2. Conserver le conteneur `{suite, components}` et l'encodage hexadécimal minuscule — le contrat
   les impose déjà et anticipe déjà v2. `schema_version` reste `1`.
3. Composante ML-DSA signée dans le HSM via `CKM_ML_DSA` (ML-DSA pur), vérifiée en Rust via
   `aws-lc-rs 1.18.0` (`ML_DSA_65`) — aucune nouvelle dépendance de production.
4. Deux clés HSM neuves dédiées ; `HsmSettings` porte un label par composante.
5. `MAX_BYTES` devient une borne d'entrée globale (32768) plus une borne par suite réappliquée
   après résolution de la suite : v1 reste plafonnée à 8192, inchangée.
6. Recouvrement asymétrique : vérification v1+v2 sans expiration ; émission v2 seule à partir de
   `T` ; aucun ré-scellement rétroactif.
7. Événement charnière `audit.chain_verified` scellé en v2 à la bascule, ancrant la tête de
   chaîne v1 sous signature hybride.
8. Entrée CBOM `audit-seal/v2` avec `anssi_2027_compliant = true`, `predecessor =
   "audit-seal/v1"`, mécanismes HSM déclarés, période de recouvrement documentée ;
   `audit-seal/v1` conserve son entrée avec `successor` renseigné et `role` étendu à la
   vérification seule après `T`.

## Options laissées ouvertes

- **O1** — jeton PKCS#11 PQC de développement : **tranché, Kryoptic** (Q1, 2026-08-24).
- **O2** — `CKM_ML_DSA` vs `CKM_HASH_ML_DSA_SHA256` : **tranché, `CKM_ML_DSA` pur** (Q4,
  2026-08-24).
- **O3** — valeur de `MAX_BYTES_V2` : 32768 (recommandé, anticipe `decision-seal/v2`) vs 16384
  (ajusté au besoin actuel, exige une seconde révision plus tard).
- **O4** — date de bascule `T` : à la mise en service de v2 en dev, ou à une date calendaire ?
  Recommandation : à la première émission v2 réussie en production, matérialisée par la séquence
  de l'événement charnière — une séquence est vérifiable hors ligne, une date d'horloge ne l'est
  pas.

## Conséquences

**Positives**
- Conformité à l'exigence ANSSI 2027 sur l'opération la plus fréquente et la plus probante du
  système.
- Aucune modification de `contracts/` : le format v1 avait été conçu pour ça (ADR-012/013), le
  pari est gagné.
- Aucune nouvelle dépendance de production, Rust ou PKCS#11 : `aws-lc-rs 1.18.0` et
  `cryptoki 0.12.0` sont déjà verrouillés et déjà capables.
- Migration à son coût minimum historique : aucun vérificateur `audit-seal` en production
  aujourd'hui.
- L'événement charnière protège rétroactivement l'intégrité positionnelle de tout l'historique
  v1.
- Le socle (mécanisme HSM, vérification par composante, bornes par suite) est réutilisé tel quel
  par `identity-assertion/v2` et `decision-seal/v2`.

**Négatives — assumées**
- ×6,8 sur le volume du journal d'audit (1 151 → 7 834 octets par événement nominal), et bascule
  systématique en stockage TOAST côté Postgres : coût de stockage, de sauvegarde et d'I/O de
  rejeu réel et permanent. Chiffré (Q5) : ~700 Go sur 5 ans à ~50 000 événements/jour, contre
  ~105 Go en v1 seul — ordre de grandeur, pas une compression TOAST mesurée.
- Deux opérations HSM par action métier au lieu d'une, sur l'opération la plus fréquente :
  dimensionnement du pool à revoir, latence à mesurer, débit maximal du système potentiellement
  contraint par le HSM.
- La non-répudiation de l'historique v1 reste non-PQC pour toujours. Risque résiduel accepté, non
  remédiable.
- Dépendance à un jalon externe non maîtrisé : disponibilité d'un HSM ML-DSA sous visa ANSSI. Le
  code peut être prêt sans que la prod puisse basculer.
- L'outillage de dev SoftHSM2 doit être remplacé ou complété — impact sur `make setup`, la CI,
  les runbooks, la documentation d'onboarding.
- L'encodage hexadécimal impose +3 309 octets par événement de pure inefficacité d'encodage,
  cohérence contractuelle payée cash.
- Élargissement de l'API publique de `zs-crypto` et de `zs-hsm` (labels multiples,
  `accept_verifying_key` par composante) : rupture pour `identity-provider` et `audit-sealer`.

## Alternatives rejetées

1. **Substituer ML-DSA-65 à ECDSA (non hybride).** Rejeté : contraire à la doctrine ANSSI, à
   l'invariant 5, et à la prudence élémentaire — ML-DSA a moins de dix ans de cryptanalyse
   publique. On ne remplace pas une primitive éprouvée par une jeune, on l'additionne.
2. **Ré-sceller l'historique v1 en v2.** Rejeté : détruit le chaînage, n'apporte pas la propriété
   recherchée, et la capacité même de ré-sceller est une vulnérabilité (§6).
3. **Retirer `audit-seal/v1` de la vérification à la bascule.** Rejeté : rendrait le journal
   historique invérifiable. Un journal illisible est pire qu'un journal non-PQC.
4. **Encoder les signatures en base64 pour économiser 3 309 octets/événement.** Rejeté :
   `contracts/events/audit-event.schema.json` impose `^[0-9a-f]+$` avec une justification
   explicite (canonicité triviale à vérifier, cohérence avec `prev_hash`). L'économie ne
   justifie pas d'affaiblir la vérifiabilité par un tiers avec ses propres outils. Réexaminable
   seulement si la volumétrie devient bloquante en production, et alors par un ADR dédié qui
   modifie le contrat en premier.
5. **Ne signer en ML-DSA que les événements « importants ».** Rejeté : introduit un chemin
   d'émission à deux vitesses, donc une surface de rétrogradation, et rend la chaîne hétérogène.
   Une chaîne se vérifie entièrement ou pas du tout.
6. **Attendre la disponibilité de SoftHSM2 avec ML-DSA.** Rejeté : issue ouverte sans jalon
   depuis juillet 2025, contre une échéance 2027 ferme. Rendre notre calendrier dépendant d'un
   projet tiers non engagé est un risque calendaire inacceptable.
7. **Différer `audit-seal/v2` jusqu'à un ADR unique couvrant les trois suites.** Rejeté : le coût
   de migration d'`audit-seal` croît avec chaque événement scellé et avec l'ouverture
   d'`audit-collector`. Coordonner le socle, oui ; coupler les bascules, non (§7).
8. **Résorber la divergence de forme avec `identity-assertion` (tableau au premier niveau) à
   l'occasion de v2, comme ADR-013 le prévoyait.** Rejeté en l'état — **revirement explicite par
   rapport à ADR-013**. Le conteneur `{suite, components}` d'`audit-seal` est strictement
   supérieur : il nomme la suite dans le document. La convergence souhaitable consiste à aligner
   `identity-assertion/v2` sur cette forme, pas l'inverse — et cela relève de l'ADR
   `identity-assertion/v2`, pas de celui-ci. Mélanger un changement cosmétique de format à un
   changement de suite au moment où on double la surface cryptographique est un mauvais échange.

## Critère de réexamen

- **Immédiat, bloquant** : disponibilité effective d'un HSM ML-DSA sous visa/qualification
  ANSSI. Si aucun fournisseur ne s'engage avant mi-2026, réexaminer la stratégie de qualification
  globale, pas seulement cette suite.
- Toute publication ANSSI ou NIST modifiant la doctrine d'hybridation ou les paramètres ML-DSA
  recommandés.
- Toute cryptanalyse significative de ML-DSA (Dilithium) ou d'ECDSA P-256.
- Au passage de `decision-seal` en hybride : revérifier par mesure la borne `MAX_BYTES_V2`
  (`decision_signature` recopiée passe de 128 à 6 746 caractères hex).
- Si la volumétrie du journal (×6,8) devient contraignante en exploitation : réexaminer
  l'encodage (alternative 4) via un ADR modifiant `contracts/` en premier.
- Si `aws-lc-rs` régressait sur ML-DSA (dépréciation, CVE, retrait de l'API) : réévaluer
  `libcrux-ml-dsa` / `fips204`.
- Au plus tard fin 2026, quelle que soit l'avancée, pour tenir 2027.

---

## Questions ouvertes — arbitrage humain requis avant « Statut : accepté »

**Q1 — Jeton PKCS#11 PQC de développement. TRANCHÉE (2026-08-24) : Kryoptic.** Remplacement/
complément de SoftHSM2 en dev, sous réserve d'un ADR de dépendance dédié (règle absolue #10 :
licence OSI, activité de maintenance, historique CVE — Kryoptic est porté par Red Hat, PKCS#11
3.2, support ML-DSA/ML-KEM déjà présent) et de l'adaptation de `make setup`/CI qui en découle.
Le mode dégradé logiciel (option D) n'est pas retenu comme cible — seulement comme filet
temporaire si Kryoptic s'avère indisponible à l'implémentation, dans les mêmes conditions
strictes déjà décrites (nommé explicitement, refusé au démarrage en production, couvert par un
test de refus).

**Q2 — Disponibilité HSM matériel. TRANCHÉE (2026-08-24) : le porteur du projet sollicite
directement les fournisseurs** (Thales Luna, Utimaco, Entrust nShield, Atos/Eviden Trustway en
priorité — liste §1) sur le périmètre `CKM_ML_DSA` et le statut visa/qualification ANSSI associé.
Réponses à consigner dans ce document (ou en annexe référencée) dès reçues. Le plan de repli si
aucun fournisseur ne s'engage avant 2027 reste à formuler une fois les réponses connues — pas
avant, pour ne pas planifier un repli sur une hypothèse non vérifiée.

**Q3 — Signeur ML-DSA de test indépendant. TRANCHÉE (2026-08-24) : `ml-dsa` (RustCrypto).**
Reproduit le principe déjà en place avec `p256` (implémentation ECDSA indépendante d'`aws-lc-rs`
en test, ADR-011/012/013) : nouvelle dépendance de développement uniquement, jamais en
production, justifiée par la même propriété d'indépendance d'implémentation entre signature de
test et vérification réelle. À couvrir par l'ADR de dépendance requis par la règle absolue #10 au
moment de l'implémentation.

**Q4 — `CKM_ML_DSA` vs `CKM_HASH_ML_DSA_SHA256`. TRANCHÉE (2026-08-24) : `CKM_ML_DSA` pur.**
Choix figé dans la suite, non réversible après la première émission. Retenu pour sa conformité
sans ambiguïté à FIPS 204 §5.2 (moins de surface d'interprétation qu'un pré-hachage dont la
sémantique exacte des paramètres PKCS#11 v3.2 n'a pas encore été vérifiée sur le HSM cible). Le
coût (~8 Kio transférés au HSM par signature au lieu de 32 octets) reste à confirmer par mesure
de latence réelle (§5) avant l'implémentation — cette décision porte sur le mécanisme, pas sur
sa performance, qui n'invaliderait le choix que si elle s'avérait rédhibitoire.

**Q5 — Acceptation du coût volumétrique. TRANCHÉE (2026-08-24) : hypothèse ~50 000
événements/jour, rétention 5 ans** (échelle organisation cliente de taille moyenne, cohérente
avec un objectif de qualification ANSSI/CESTI plutôt qu'un pilote). Chiffré à partir des tailles
mesurées §4 (`nominal` = 1 151 o v1 / 7 834 o v2, `pire cas` = 7 458 o v1 / 14 141 o v2),
`50 000 × 1826 jours` :

| Scénario | Volume/jour v1 | Volume/jour v2 | Total 5 ans v1 | Total 5 ans v2 |
|---|---|---|---|---|
| nominal | 57,5 Mo | 391,7 Mo | 105,1 Go | 715,2 Go |
| pire cas | 372,9 Mo | 707,0 Mo | 680,9 Go | 1 291,1 Go |

**Ordre de grandeur retenu pour le dimensionnement : ~700 Go sur 5 ans en v2 (scénario
nominal)**, à comparer aux ~105 Go qu'aurait représenté la même charge restée en v1 seul —
c'est le coût concret de la conformité PQC sur cet objet. Ces chiffres ignorent la compression
TOAST (Postgres compresse par défaut au-delà du seuil de bascule, non mesurée ici — le contenu
hexadécimal répétitif d'une signature ML-DSA devrait bien compresser, mais aucune mesure réelle
n'existe) : le total physique sur disque sera probablement inférieur à ces chiffres bruts, sans
qu'on sache de combien avant une mesure sur un jeu de données réel. **L'hypothèse de charge
elle-même reste une estimation de dimensionnement, pas un engagement contractuel avec un client
réel** — à recaler dès qu'une charge de production réelle est observée.

**Q6 — Portée de l'événement charnière. TRANCHÉE (2026-08-24) : instruire d'abord un ADR dédié
à l'ancrage périodique.** L'ancrage de chaîne est aujourd'hui explicitement laissé en suspens
(`EventType::AuditChainVerified` : « la charge utile probante d'un ancrage n'existe dans aucun
champ du contrat actuel — à instruire par un ADR dédié »). Traiter la charnière ici, en cas
particulier minimal, aurait improvisé précisément ce qu'ADR-013 a refusé d'improviser. La
bascule `audit-seal/v2` devient un cas d'usage de cet ancrage une fois instruit, pas
l'inverse — **la section (b) de §6 (« marquer la frontière dans la chaîne elle-même ») et le
point 7 de la Décision proposée restent en l'état pour mémoire, mais leur mise en œuvre est
suspendue jusqu'à l'ADR d'ancrage.** **Instruit : voir [ADR-031](ADR-031-ancrage-periodique-journal-audit.md).**
Confirme la clôture proposée par ADR-031 §5 : l'événement charnière devient un ancrage
`anchor.reason = "suite_transition"`, et la date de bascule `T` (Q9 ci-dessous) se définit comme
la séquence de cet ancrage plutôt qu'une date calendaire. ADR-031 doit être accepté avant que
ce document le soit (ordre imposé par ADR-031 §5, sa Q7).

**Q7 — Découpage en deux ADR. TRANCHÉE (2026-08-24) : ADR socle séparé.** Un ADR dédié au
mécanisme ML-DSA-65 partagé (`SigningMechanism::MlDsa65` dans `zs-hsm`, `accept_verifying_key`
par composante, corpus de vecteurs Wycheproof/ACVP FIPS 204, outillage de dev PKCS#11 PQC) sera
instruit séparément — ce document en devient la première application, pas le lieu où le socle
est défini. Motivation retenue : sans ce découpage, `identity-assertion/v2` et
`decision-seal/v2` devraient soit re-instruire le même socle depuis zéro, soit le référencer à
l'intérieur d'un ADR nommé `audit-seal/v2`, ce qui aurait mal porté son nom. Instruction à
lancer séparément — voir référence ci-dessous une fois produite ; `audit-seal/v2` ne peut pas
être accepté avant que ce socle existe.

**Q8 — Revirement assumé vis-à-vis d'ADR-013. TRANCHÉE (2026-08-24) : revirement validé.**
ADR-013 §Conséquences datait explicitement la résorption de la divergence de forme « au passage
v2 ». Ce document ne la résorbe **pas** : le conteneur `{suite, components}` d'`audit-seal` est
jugé structurellement supérieur (il nomme la suite dans le document même, contrairement au
tableau `signatures: [...]` d'`identity-assertion` — voir alternative 8) et la convergence
souhaitable ira dans l'autre sens, portée par un futur ADR `identity-assertion/v2` dédié, pas
mêlée ici au changement de suite ML-DSA. **Ceci contredit consciemment ADR-013 §Conséquences** —
mentionné en toutes lettres, pas silencieusement contourné. ADR-013 lui-même n'est pas modifié
(un ADR accepté n'est jamais réécrit, `docs/adr/README.md` §Règles) : ce revirement est acté ici,
dans le document qui le décide, et devra être répercuté dans le futur ADR
`identity-assertion/v2` qui héritera de la charge de la convergence.

**Q9 — Définition de la date de bascule `T`** (option O4) : séquence de l'événement charnière
(recommandé, vérifiable hors ligne) ou date calendaire ?

Sources : [cyber.gouv.fr — PQC](https://cyber.gouv.fr/enjeux-technologiques/cryptographie-post-quantique/),
[INCYBER — ANSSI intègre le post-quantique aux exigences de certification](https://incyber.org/article/lanssi-integre-le-post-quantique-a-ses-exigences-de-certification/),
[aws/aws-lc-rs releases (ML-DSA stabilisé en 1.18.0)](https://github.com/aws/aws-lc-rs/releases),
[docs.rs aws-lc-rs 1.18.0 signature](https://docs.rs/aws-lc-rs/1.18.0/aws_lc_rs/signature/index.html),
[softhsm/SoftHSMv2 issue #800 — Plans for support of MLDSA](https://github.com/softhsm/SoftHSMv2/issues/800),
[EJBCA/Keyfactor — HSMs et PQC](https://www.ejbca.org/resources/keymaster-where-were-at-with-hsms-and-pqc/).
