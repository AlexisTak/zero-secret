# ADR-032 — Socle ML-DSA-65 partagé pour les suites hybrides (zs-crypto, zs-hsm)

**Statut** : proposé — QS1 à QS9 toutes tranchées (2026-08-25). Ne peut pas passer à « accepté »
avant QS10 : exige une mesure de latence réelle (`crates/zs-crypto/CLAUDE.md`), pas une décision
de principe.
**Date** : 2026-08-24
**Auteurs** : instruction `referent-crypto`, à relire par le porteur du projet.
**Dépendances d'ordre** : doit être accepté **avant** ADR-030 (`audit-seal/v2`). Indépendant
d'ADR-031 (ancrage périodique), qui doit lui aussi précéder ADR-030 pour une autre raison.

## Contexte

### Pourquoi un ADR socle

Trois suites d'émission du projet visent la même hybridation `ECDSA P-256 + ML-DSA-65` :
`audit-seal/v2`, `identity-assertion/v2`, `decision-seal/v2`. ADR-030 §7 a constaté que le socle
technique de ces trois bascules est rigoureusement identique et que le dupliquer trois fois
garantit trois divergences. L'utilisateur a tranché ce découpage explicitement (ADR-030, Q7,
2026-08-24) : le mécanisme ML-DSA-65 partagé fait l'objet d'un ADR distinct, dont ADR-030 devient
la première application.

Le raisonnement tient en une phrase : un ADR nommé `audit-seal/v2` est un mauvais endroit pour
décider comment `identity-assertion/v2` et `decision-seal/v2` signeront. Ou bien elles
re-instruiraient le même dossier depuis zéro, ou bien elles référenceraient un document dont le
titre ne les concerne pas. Les deux sont mauvais pour un lecteur d'audit externe, qui est le
destinataire réel de ces documents.

### Ce que le code anticipe déjà

Trois points relevés à la lecture, qui déterminent la forme de la décision :

1. `crates/zs-hsm/src/mechanism.rs` anticipe explicitement l'ajout : l'énumération
   `SigningMechanism` est `#[non_exhaustive]`, fermée volontairement à `EcdsaP256Sha256`, avec le
   commentaire « `MlDsa65` sera ajoutée avec la cible hybride `v2` — pas avant, et pas par un
   contributeur qui l'ajouterait seul ». Ce document est l'ADR que ce commentaire réclame.
2. La boucle de vérification d'`audit_seal::verify` accumule déjà sans court-circuit
   (`all_valid &= …`), vérifie arité et ordre des composantes avant toute opération
   cryptographique, et n'utilise jamais le champ `component` du document pour choisir un
   vérificateur. L'invariant 5 est structurellement supporté ; le socle n'a pas à le créer,
   seulement à ne pas le casser en le peuplant.
3. Les deux points qui, eux, ne sont pas prêts : `accept_verifying_key` code en dur la garde
   ECDSA (`len != 65 || bytes[0] != 0x04`), et `HsmSettings.key_label: String` est un label
   unique. Ce sont les deux ruptures d'API publique portées par ce socle.

### Dépendances déjà en place

`Cargo.lock` verrouille `aws-lc-rs 1.18.0` (ML-DSA stabilisé : `ML_DSA_65`, `PqdsaKeyPair`,
`PqdsaVerificationAlgorithm`) et `cryptoki 0.12.0` (`MechanismType::ML_DSA`,
`Mechanism::MlDsa(..)`, famille `HashMlDsa*`). Aucune nouvelle dépendance de production n'est
nécessaire pour ce socle — c'est le point le plus favorable du dossier et il vaut pour les trois
suites.

## Décision proposée

### 1. Ce que ce socle garantit à toute suite hybride qui en dépend

Une suite `<intention>/v2` conforme à ce socle obtient, sans avoir à les re-décider :

**(a) Un mécanisme de signature HSM ML-DSA-65 — `zs-hsm`.**
- Ajout de la variante `SigningMechanism::MlDsa65` (ML-DSA pur, `CKM_ML_DSA`, FIPS 204 §5.2).
  C'est la seule variante ML-DSA ajoutée par ce socle ; voir §2.
- Ajout d'un point d'entrée qui transporte le message, `CKM_ML_DSA` ne signant pas un condensat.
  `HsmSigner::sign_digest` reste inchangé et reste réservé à ECDSA. Les deux appariements croisés
  sont refusés explicitement, jamais silencieusement tolérés : `sign_digest(MlDsa65, …)` → erreur,
  `sign_message(EcdsaP256Sha256, …)` → erreur (sinon ECDSA aurait deux chemins de hachage
  possibles, donc une divergence latente). Forme exacte de l'API à arbitrer, QS2.
- Vérification des capacités au démarrage, pas à la première signature : présence de
  `CKM_ML_DSA` via `C_GetMechanismInfo`, existence de la clé sous son label, type `CKK_ML_DSA` et
  jeu de paramètres ML-DSA-65. Absence d'une seule de ces conditions → refus d'ouverture du
  scelleur. Un système qui démarre puis échoue à la première action métier est pire qu'un système
  qui refuse de démarrer.
- Aucun repli logiciel, jamais : mécanisme absent, session perdue, jeton déconnecté → `HsmError`
  remontée telle quelle, convertie en refus opaque côté `zs-crypto` (`SealError::SealingUnavailable`).
  Le trait `HsmSigner` reste interdit d'implémentation hors `zs-hsm` et hors `#[cfg(test)]`.
- Aucun réessai interne, comme pour ECDSA (ADR-011). La justification est la même et elle est
  renforcée : ML-DSA en mode « hedged » (défaut FIPS 204) est randomisé ; un réessai produirait
  une seconde signature valide sur le même contenu, donc une fourche potentielle de chaîne
  d'audit. Le mode déterministe de ML-DSA existe mais son activation dépend du jeton : ne pas
  fonder d'invariant dessus.

**(b) Une forme unique de vérification par composante — `zs-crypto`.**
Toute suite hybride adopte la même construction, module par module :
- L'algorithme de vérification d'une composante est déterminé par la position dans la liste
  `REQUIRED_COMPONENTS_V2` de la suite, jamais par le champ `component` du document reçu, jamais
  par le type de la clé fournie. C'est la fermeture de la confusion d'algorithme, déjà acquise en
  v1, à préserver mot pour mot.
- `AcceptedVerifyingKey` porte sa composante : `{ component, key_id, raw }`. Une clé acceptée
  pour `ecdsa-p256` ne peut pas servir à vérifier la composante `ml-dsa-65`, même si son
  `key_id` correspond.
- La sélection de clé exige la conjonction `key.component == required[i] && key.key_id ==
  component.key_id`. Échec → `UnknownKeyId`.
- Garde supplémentaire à ajouter en v2 : refuser deux composantes portant le même `key_id`. Sans
  elle, un document dont les deux composantes désignent la même clé ECDSA est un cas dégénéré à
  examiner, et le meilleur moment pour l'interdire est avant qu'il existe.
- L'accumulation sans court-circuit (`all_valid &=`) et la vérification d'arité/ordre avant toute
  crypto sont conservées telles quelles. Un refus ne peut pas provenir d'un `?` placé au milieu
  de la boucle de validité.

**(c) Une garde de reconnaissance de clé publique par type.**
`accept_verifying_key` prend la composante en paramètre d'entrée et applique la garde
correspondante :

| Composante | Encodage attendu | Contrôle |
|---|---|---|
| `ecdsa-p256` | SEC1 non compressé | longueur exactement 65 et premier octet `0x04` |
| `ml-dsa-65` | clé publique ML-DSA brute (FIPS 204) | longueur exactement 1952 octets |

Point de conception non négociable : le type ne se déduit jamais de la longueur. La longueur est
un contrôle appliqué à un type déjà connu. Déduire le type de la longueur reviendrait à laisser
le contenu non fiable choisir l'algorithme — exactement l'erreur que la v1 a évitée sur
`component`. Conséquence directe : une clé ML-DSA-65 de 1952 octets passée en composante
`ecdsa-p256` doit être refusée par `MalformedKey`, et réciproquement. C'est un cas de test
obligatoire, pas une remarque.

**(d) Une gestion de clés multiples par `HsmSettings`.**
- `key_label: String` devient un jeu de labels indexé par composante, résolu contre
  `required_components(suite)` à l'ouverture. Label manquant pour une composante requise → refus
  d'ouverture. Label surnuméraire → refus également (une configuration qui contient un label
  inutilisé est une configuration dont on ne sait pas ce qu'elle décrit).
- Convention de nommage : `zs-<intention>-v2-ecdsa-p256`, `zs-<intention>-v2-ml-dsa-65`. Une
  clé = une suite = une composante. Aucune réutilisation d'une clé v1 sous une suite v2 :
  ADR-013 pose déjà que la version vit dans le label, ce socle étend la règle à la composante.
- Le `key_id` dérivé de la clé publique (`key_id_from_public_key`) devient un par composante.
  Toute API publique exposant `key_id()` sans argument devient `key_id(component)` — rupture pour
  les appelants (`identity-provider`, `audit-sealer`, `policy-engine`).
- Ces trois clés v2 par suite, soit six clés HSM neuves à terme pour les trois suites,
  s'ajoutent aux trois clés v1 existantes qui restent en place pour la vérification de
  l'historique.

### 2. Mécanisme PKCS#11 : `CKM_ML_DSA` pur, imposé par le socle

L'utilisateur a tranché `CKM_ML_DSA` pur pour `audit-seal/v2` (ADR-030, Q4). La question propre à
ce socle est différente : impose-t-il ce choix à toute suite qui en dépend, ou se contente-t-il
de l'outiller ?

**Proposition : imposer.** Le socle n'ajoute que `SigningMechanism::MlDsa65` (pur). Introduire
`HashMlDsa65Sha256` exigerait un nouvel ADR modifiant celui-ci, avec validation humaine — même
barrière que celle qui protège aujourd'hui l'ajout de `MlDsa65` lui-même.

Arguments, dans l'ordre de poids :

1. Les deux familles produisent des signatures non interchangeables. Un vérificateur doit savoir
   laquelle appliquer. Si le choix est libre par suite, il devient un paramètre de plus à
   transporter, à valider et à ne pas confondre — c'est-à-dire une surface de confusion
   d'algorithme créée volontairement, dans le crate dont l'invariant 2 dit que l'API expose des
   intentions et pas des algorithmes.
2. La matrice de qualification double. Un HSM sous visa ANSSI devra être qualifié sur
   `CKM_ML_DSA` et sur `CKM_HASH_ML_DSA_SHA256` si les deux sont utilisés. Compte tenu de ce
   qu'ADR-030 §1 documente sur l'incertitude d'offre HSM PQC en 2027, ajouter une exigence de
   mécanisme supplémentaire est un risque calendaire gratuit.
3. La sémantique exacte des paramètres PKCS#11 v3.2 pour HashML-DSA (message fourni vs condensat
   fourni) n'a été vérifiée sur aucun HSM cible. Un socle ne doit pas outiller une voie qu'il n'a
   pas vérifiée.
4. Un seul corpus de vecteurs, un seul chemin de code, un seul harnais de bench. C'est la raison
   d'être d'un socle.

Contre-argument honnête, à trancher par l'humain : `identity-assertion` et `decision-seal`
manipulent des documents nettement plus petits qu'`audit-seal` (`MAX_BYTES` = 4096 pour
`identity-assertion` aujourd'hui). Le coût du transport du message complet vers le HSM y est donc
mineur, ce qui rend l'imposition peu coûteuse pour elles. Inversement, si la mesure de latence
(§5 d'ADR-030) révélait que `CKM_ML_DSA` est rédhibitoire sur `audit-seal` en raison du volume
transféré, la question se rouvrirait pour toutes les suites d'un coup — ce qui est précisément le
comportement souhaitable d'un socle : une décision, un lieu, une révision. Voir QS1.

### 3. Bibliothèques — reconfirmées au niveau socle

**Vérification, production : `aws-lc-rs 1.18.0`, déjà verrouillé.**
- ML-DSA stabilisé en 1.18.0 (sorti de `unstable`) ; constantes `ML_DSA_44/65/87` (vérification)
  et `*_SIGNING`.
- Forme d'appel identique à l'existant :
  `UnparsedPublicKey::new(&ML_DSA_65, pk).verify(message, sig)` — exactement la construction déjà
  employée avec `ECDSA_P256_SHA256_FIXED`. L'impact sur `verify()` se limite à choisir
  l'algorithme par composante.
- Licence Apache-2.0 / ISC (OSI, pas de copyleft fort). Maintenance AWS, AWS-LC dérivé de
  BoringSSL, module FIPS validé, fuzzing et vérification formelle continus. Déjà bibliothèque de
  référence du projet (ECDSA, `zs-webauthn`).
- Aucune nouvelle dépendance de production. À reconfirmer par `cargo audit` au moment de
  l'implémentation.
- Rappel structurant repris d'ADR-030 : `PqdsaVerificationAlgorithm::parsed_verify_digest_sig`
  retourne toujours `Unspecified` — ML-DSA pur ne se vérifie pas depuis un condensat. C'est le
  pendant côté vérification de la contrainte §1(a) côté signature.

**Signature de test indépendante, développement uniquement : `ml-dsa` (RustCrypto).**
Tranché par l'utilisateur (ADR-030, Q3), reconfirmé ici au niveau socle. Reproduit exactement le
rôle que `p256` tient déjà face à `aws-lc-rs` pour ECDSA : la signature de test et la vérification
réelle doivent provenir d'implémentations indépendantes, sinon un test ne prouve que la cohérence
d'une bibliothèque avec elle-même. `dev-dependencies` strictement, jamais en production, jamais
dans un chemin atteignable depuis une entrée réseau. Soumis à la règle absolue #10 (licence,
maintenance, CVE) au moment de l'implémentation.

**Écartées, au niveau socle** : `fips204` (redondant avec `aws-lc-rs`), `libcrux-ml-dsa`
(vérification formelle attrayante, écosystème plus étroit — réserve de repli si `aws-lc-rs`
régressait sur ML-DSA), fournisseur interne (exclu par l'invariant 1).

### 4. Outillage de développement PKCS#11 PQC — Kryoptic, décidé une fois

SoftHSM2 ne fournit pas ML-DSA : l'issue
[softhsm/SoftHSMv2#800](https://github.com/softhsm/SoftHSMv2/issues/800) est ouverte depuis
juillet 2025 sans jalon ni branche. Cette contrainte n'appartient pas à `audit-seal` : elle
bloque les trois suites, la CI et tout test d'intégration HSM PQC du dépôt. Elle est donc au bon
niveau ici.

**Kryoptic** (jeton PKCS#11 logiciel écrit en Rust, projet latchset, écosystème Red Hat) est
tranché (ADR-030, Q1). Éléments vérifiés ce jour : Kryoptic 1.4.0 (janvier 2026) inclut des
correctifs sur les clés ML-DSA / ML-KEM / SLH-DSA ; l'écosystème PKCS#11 PQC associé est actif
(RHEL 10.1 documente ML-DSA de bout en bout, `pkcs11-tools` active ML-KEM/ML-DSA/SLH-DSA par
défaut). Le socle en tire une conséquence d'outillage : `make setup`, la CI, les runbooks et la
documentation d'onboarding changent une fois, pas trois.

Deux points restent à instruire à l'implémentation, sans quoi ce paragraphe reste une intention :
- ADR de dépendance dédié exigé par la règle absolue #10 (licence, activité de maintenance,
  historique CVE, gouvernance) — QS5 : intégré à ce socle ou séparé ?
- Remplacement ou complément de SoftHSM2 ? Un jeton unique en dev simplifie le poste
  développeur ; conserver SoftHSM2 pour les suites v1 préserve la fidélité du contexte de
  non-régression de l'historique. Recommandation : complément d'abord, remplacement une fois la
  parité vérifiée.

Le filet temporaire (option D d'ADR-030 : ML-DSA en logiciel `aws-lc-rs` en dev uniquement) reste
encadré exactement comme décrit dans ADR-030 Q1 — mode nommé explicitement, refusé au démarrage
en production, couvert par un test de refus — et n'est pas une cible. Ce socle est le lieu où ce
garde-fou doit vivre, pas chaque suite.

### 5. Plan de test du socle

Ce que le socle apporte, et que chaque suite consomme sans le reconstruire :

- Vecteurs officiels : vecteurs ACVP ML-DSA de NIST (`ML-DSA sigVer FIPS204` notamment) et
  vecteurs Wycheproof ML-DSA (ajoutés au projet C2SP/wycheproof, versions Dilithium round 3 et
  FIPS 204). Exécutés en CI, comme les vecteurs ECDSA existants. À figer dans `tests/vectors/`
  avec leur provenance et leur date de récupération.
- Tests de refus obligatoires, communs aux trois suites :
  - composante ML-DSA remplacée par une seconde signature ECDSA valide → refus (l'attaque la plus
    directe contre une hybridation mal implémentée) ;
  - jeu de clés ne contenant que la composante ECDSA → refus, jamais « composante ignorée » ;
  - clé de 1952 octets présentée comme `ecdsa-p256` et clé SEC1 de 65 octets présentée comme
    `ml-dsa-65` → `MalformedKey` dans les deux sens ;
  - deux composantes portant le même `key_id` → refus ;
  - échec HSM injecté sur chacune des deux composantes séparément → aucune émission partielle,
    aucun réessai, refus ;
  - mécanisme `CKM_ML_DSA` absent du jeton → refus à l'ouverture, pas à la signature ;
  - perte de session pendant la seconde signature → refus, aucun repli logiciel.
- Fuzzing de `accept_verifying_key` et de `verify` en configuration v2 (parseur d'entrée,
  invariant du crate).
- Signeur indépendant `ml-dsa` (RustCrypto) pour produire les documents de test, `aws-lc-rs` pour
  les vérifier.
- Couverture ≥ 95 % maintenue sur `zs-crypto` ; toute ligne non couverte justifiée.

### 6. Entrée CBOM

Ce socle n'est pas une suite : il n'a pas de `<intention>/vN`, donc pas d'entrée `[[suite]]` dans
`security/crypto-inventory/suites.toml` au sens actuel du fichier (`tools/generate-cbom.sh`
dérive `cbom.json` depuis des suites, et `make test-arch` contrôle la correspondance entre les
suites référencées dans `crates/zs-crypto/src/**/*.rs` et ce fichier).

Proposition minimale et sans effet de bord : le socle normalise les champs que chaque suite
hybride devra renseigner, plutôt que d'inventer une entité que la chaîne d'outillage ne consomme
pas :

```
hybrid = true                       # nouveau, explicite l'invariant 5
components = ["ecdsa-p256", "ml-dsa-65"]   # ordre imposé par la suite
hsm_mechanisms = ["CKM_ECDSA", "CKM_ML_DSA"]
key_labels = ["zs-<intention>-v2-ecdsa-p256", "zs-<intention>-v2-ml-dsa-65"]
foundation_adr = "ADR-032"
anssi_2027_compliant = true
predecessor = "<intention>/v1"
```

et, en miroir, chaque entrée v1 conserve la sienne avec `successor` renseigné et son `role`
restreint à la vérification après la bascule de sa suite.

Réserve honnête : CycloneDX 1.6 sait représenter un `cryptographic-asset` de type `algorithm`
distinct d'un `protocol`, donc une entrée de niveau mécanisme serait défendable et probablement
plus lisible pour un auditeur externe. Cela suppose de faire évoluer `suites.toml` et
`generate-cbom.sh`. Voir QS6.

### 7. Impact performance — ce que le socle fournit, ce qu'il ne mesure pas

Le socle fournit le harnais de mesure commun, pas les chiffres : chaque suite mesure les siens,
sur ses tailles de documents et sa fréquence.

Harnais commun à construire une fois :
1. bench `zs-hsm` isolé : `sign_digest` ECDSA P-256 vs signature ML-DSA-65, p50/p95/p99, sur le
   jeton de dev retenu et sur le HSM matériel cible ;
2. bench de vérification `aws-lc-rs` ECDSA vs ML-DSA-65 en logiciel ;
3. bench de saturation du pool de sessions : toute suite hybride fait deux opérations HSM par
   acte au lieu d'une ; le `pool_size` établi en v1 est à réévaluer, pas à reconduire ;
4. courbe latence vs taille du message signé — nécessaire pour instruire proprement le coût de
   `CKM_ML_DSA` pur (§2) sur des documents de tailles très différentes selon la suite.

Aucune mesure n'est possible aujourd'hui : aucun jeton PKCS#11 du dépôt ne fait ML-DSA. Toute
valeur avancée avant la mise en place de Kryoptic serait une estimation, ce que
`crates/zs-crypto/CLAUDE.md` interdit explicitement pour une nouvelle suite. La mise en place du
harnais et l'obtention d'un premier jeu de mesures sont un prérequis d'acceptation de ce socle,
pas d'ADR-030 seul.

### 8. Ce que ce socle ne fait pas

Délimitation explicite, pour qu'aucune suite ne croie trouver ici une réponse qu'elle doit
produire elle-même :

- Il ne fixe aucune valeur de `MAX_BYTES`. Elle dépend du format de message de chaque suite
  (`audit-seal` 8192 aujourd'hui, `identity-assertion` 4096, `decision-seal` sur un objet
  protobuf typé). Le socle constate seulement un fait qui les concerne toutes : une signature
  ML-DSA-65 fait 3309 octets, soit 6618 caractères en hexadécimal minuscule, et le surcoût est
  donc du même ordre pour chacune. Le principe de la borne à deux étages (borne d'entrée globale
  avant parse, borne par suite réappliquée après résolution de `signature.suite`) est un motif
  recommandé par le socle ; les valeurs appartiennent à chaque suite.
- Il ne fixe aucune stratégie de recouvrement de l'historique. Les profils de risque diffèrent
  nettement (ADR-030 §7) : `audit-seal` a une valeur probante de longue durée et aucun
  vérificateur en production ; `identity-assertion` est consommé par un service de vérification
  réel (ADR-016) et sa bascule impose une coordination inter-composants ; `decision-seal` produit
  des objets vivant quelques secondes, mais dont la signature est recopiée durablement dans les
  événements d'audit (ADR-027/029). Chaque suite décide de ses `accepted_suites` et de sa
  fenêtre.
- Il ne fixe ni la cadence de bascule ni la date `T` de quelque suite que ce soit. Il ne fixe pas
  non plus l'ordre des bascules, seulement l'ordre d'acceptation des ADR (§10).
- Il ne modifie aucun contrat de `contracts/`, ne décide d'aucun format de conteneur de
  signature, et ne tranche pas la divergence de forme entre `audit-seal` (objet
  `{suite, components}`) et `identity-assertion` (tableau au premier niveau) — ADR-030
  alternative 8 et Q8 traitent ce point, qui relève des suites.
- Il ne couvre pas ML-KEM-768 (`channel-kex/v2`). Un KEM n'est pas une signature : ni le même
  mécanisme PKCS#11, ni la même forme de vérification, ni la même notion de composante. Un socle
  jumeau sera nécessaire ; le nommer ici évite qu'on croie ce document plus large qu'il n'est.
  Voir QS7.

### 9. Relation avec ADR-030 — sections à remplacer par un renvoi

ADR-030 devient la première application de ce socle. Une fois ce document accepté, ADR-030 doit
être réécrit pour renvoyer ici plutôt que de répéter, sur les points suivants :

| Section d'ADR-030 | Action |
|---|---|
| §1 « Disponibilité ML-DSA-65 côté PKCS#11 » | Remplacée intégralement par un renvoi à ADR-032 §1(a) et §4 (Kryoptic, SoftHSM2, HSM matériel qualifié). Aucun élément de §1 n'est spécifique à `audit-seal`. |
| §2 « Bibliothèque pour la composante ML-DSA-65 » | Remplacée intégralement par un renvoi à ADR-032 §3. Conserver au plus une phrase de conclusion : « aucune nouvelle dépendance de production, voir ADR-032 §3 ». |
| §3 « ML-DSA ne signe pas un condensat » | Choix du mécanisme (`CKM_ML_DSA` pur) et conséquence sur `SigningMechanism`/`sign_digest` → renvoi à ADR-032 §1(a) et §2. Conserver ce qui est propre à `audit-seal` : le fait que le message canonique complet, jusqu'à `MAX_BYTES`, traverse la frontière PKCS#11 à chaque signature, car c'est ce qui alimente §4 (taille) et §5 (latence) d'ADR-030. |
| §6, dernier bloc « Clés » | Remplacé par un renvoi à ADR-032 §1(c) et §1(d) : labels par composante, `accept_verifying_key` par type, convention de nommage. Conserver uniquement les noms de clés retenus pour `audit-seal/v2`. Les volets (a), (b), (c) de §6 (recouvrement, événement charnière, risque résiduel) sont spécifiques à `audit-seal` et restent dans ADR-030. |
| §6, bloc « Ce qui est déjà correct et ne doit pas être touché » | Remplacé par un renvoi à ADR-032 §1(b), qui en fait une garantie de socle opposable aux trois suites au lieu d'une observation locale. |
| §7, premier tiret « Ce qui doit être coordonné » | Remplacé par un renvoi : c'est la liste des éléments que ce socle absorbe. Le reste de §7 (profils de risque différenciés, ordre des bascules) reste. |
| Décision proposée, points 3 et 4 | Reformulés en renvoi : « composante ML-DSA conforme à ADR-032 (mécanisme, bibliothèque, clés par composante) », en ne conservant que les labels de clés propres à `audit-seal/v2`. |
| Q1 (Kryoptic), Q3 (`ml-dsa` de test), Q4 (`CKM_ML_DSA`) | Migrées vers ce socle, où elles sont reprises et généralisées. ADR-030 les conserve en référence historique avec la mention « tranchée le 2026-08-24, portée par ADR-032 ». |
| Q2 (disponibilité HSM matériel sous visa ANSSI) | À migrer également — la démarche du porteur auprès des fournisseurs porte sur `CKM_ML_DSA`, donc sur les trois suites. C'est le risque calendaire dominant du programme PQC entier, pas d'`audit-seal`. Voir QS4. |

Ce qui reste intégralement dans ADR-030 : §4 (impact taille mesuré), §5 (protocole de latence
propre à la fréquence d'`audit-seal`), §6 (a)(b)(c) (recouvrement, ancrage, risque résiduel), §7
(portée et ordre des bascules), Q5 (volumétrie), Q6 (ancrage, renvoyant à ADR-031), Q8 (revirement
vs ADR-013), Q9 (définition de `T`).

### 10. Ordre d'acceptation

```
ADR-032 (socle ML-DSA-65)  ─┐
                            ├──►  ADR-030 (audit-seal/v2)  ──►  identity-assertion/v2  ──►  decision-seal/v2
ADR-031 (ancrage périodique)┘
```

ADR-030 ne peut pas être accepté avant ADR-032 : il consommerait un socle inexistant, ce que sa
propre Q7 constate en toutes lettres. La même relation de dépendance existe déjà avec ADR-031
(ADR-030 Q6). ADR-031 et ADR-032 sont indépendants entre eux et peuvent être arbitrés dans
n'importe quel ordre.

Conséquence pratique à ne pas perdre de vue : ADR-030 attend désormais deux prérequis. Si l'un
des deux traîne, chaque événement scellé en `audit-seal/v1` d'ici là est un événement à
recouvrement définitif (ADR-030 §7). Ce n'est pas un argument pour raccourcir l'instruction,
c'est un argument pour ne pas la laisser dormir.

## Conséquences

**Positives**
- Une décision, un lieu, une révision : le mécanisme ML-DSA-65 est instruit une fois pour les
  trois suites, au lieu d'être re-litigé trois fois avec trois résultats légèrement différents.
- Aucune nouvelle dépendance de production : `aws-lc-rs 1.18.0` et `cryptoki 0.12.0` sont déjà
  verrouillés et déjà capables.
- L'outillage de développement PKCS#11 PQC change une fois (`make setup`, CI, runbooks,
  onboarding), pas trois.
- La garde de reconnaissance de clé par type ferme, avant qu'il existe, un piège de confusion
  ECDSA/ML-DSA que trois modules auraient pu ouvrir indépendamment.
- Le corpus de vecteurs (ACVP FIPS 204, Wycheproof) et le harnais de bench sont mutualisés.
- Un auditeur externe trouve la justification du mécanisme PQC dans un document dont le titre
  correspond à ce qu'il cherche.

**Négatives — assumées**
- Un prérequis de plus avant `audit-seal/v2`. Deux ADR doivent être acceptés avant ADR-030 au
  lieu d'un, sur une échéance 2027 ferme, et chaque jour de retard produit des événements v1 non
  recouvrables.
- Rupture d'API publique de `zs-crypto` et `zs-hsm` portée par ce socle et subie par les
  appelants : `HsmSettings.key_label` → labels par composante, `accept_verifying_key` signature
  modifiée, `key_id()` → `key_id(component)`, nouveau point d'entrée de signature sur message.
  Impacte `identity-provider`, `audit-sealer`, `policy-engine`. Cette rupture arrive avant que la
  première suite en tire un bénéfice fonctionnel : le coût est payé d'abord, la valeur vient
  ensuite.
- Un socle impose à qui n'en veut pas. `decision-seal` (objets de quelques secondes, urgence PQC
  objectivement moindre) hérite du choix `CKM_ML_DSA` pur décidé au regard des contraintes
  d'`audit-seal`. C'est le prix de l'uniformité, et il doit être assumé consciemment (QS1).
- Une abstraction prématurée est un risque réel. Ce socle est écrit alors qu'aucune des trois
  suites n'est implémentée. Il codifie une forme déduite de la lecture du code v1, pas de
  l'expérience d'une v2 en fonctionnement. Le premier consommateur (ADR-030) doit être autorisé à
  faire remonter une correction du socle plutôt qu'à contourner localement — et une telle
  remontée est un amendement d'ADR, pas une adaptation silencieuse.
- Dépendance à un jalon externe non maîtrisé, désormais au niveau programme : sans HSM ML-DSA
  sous visa ANSSI, aucune des trois suites ne bascule en production, quel que soit l'état du
  code.

## Alternatives rejetées

1. **Ne pas faire d'ADR socle et laisser chaque suite instruire son mécanisme.** Rejeté par
   décision explicite de l'utilisateur (ADR-030, Q7). Motif technique : trois instructions
   parallèles du même dossier produisent trois divergences, et la troisième arriverait quand les
   deux premières seront figées par des signatures déjà émises.
2. **Mettre le socle dans ADR-030 et y renvoyer depuis les deux autres suites.** Rejeté : un
   document intitulé `audit-seal/v2` définissant comment `identity-assertion` signe est un
   document mal nommé, donc un document qu'un auditeur externe ne trouvera pas.
3. **Un ADR socle couvrant à la fois signature (ML-DSA-65) et échange de clés (ML-KEM-768).**
   Rejeté : mécanismes PKCS#11 différents, forme de vérification différente, notion de composante
   différente, calendrier différent (`channel-kex/v2` n'a aucun consommateur instruit à ce jour).
   Un socle qui couvre deux choses sans rapport n'est pas un socle, c'est un fourre-tout.
4. **Outiller `CKM_ML_DSA` et `CKM_HASH_ML_DSA_SHA256` et laisser chaque suite choisir.** Rejeté
   au titre de §2 : signatures non interchangeables, matrice de qualification HSM doublée,
   sémantique PKCS#11 v3.2 du pré-hachage non vérifiée sur un HSM cible. Le socle ouvre une voie
   qu'il a vérifiée, pas deux.
5. **Déduire le type de clé publique de sa longueur dans `accept_verifying_key`.** Rejeté :
   laisse une donnée non fiable sélectionner l'algorithme. La v1 a évité exactement cette erreur
   sur le champ `component` ; la reproduire sur la longueur de clé serait un recul.
6. **Généraliser `sign_digest` en acceptant un « digest » de longueur arbitraire pour ML-DSA.**
   Rejeté : `zs-hsm` documente qu'il ne hache jamais lui-même et que l'appelant fournit un
   condensat. Faire passer un message complet dans un paramètre nommé `digest` est un mensonge de
   nommage dans le crate le plus sensible du dépôt.
7. **Attendre que les trois suites soient prêtes pour figer le socle sur du concret.** Rejeté :
   c'est l'ordre inverse de celui décidé, et il garantit que la forme du socle sera dictée par la
   première implémentation faite dans l'urgence. L'abstraction prématurée est un risque (voir
   Conséquences) ; l'abstraction rétroactive sur trois implémentations divergentes en est un plus
   grand.

## Critère de réexamen

- Bloquant, immédiat : disponibilité effective d'un HSM ML-DSA sous visa/qualification ANSSI
  (réponses fournisseurs attendues, ADR-030 Q2 à migrer ici). Sans elle, le socle est du code
  prêt sans cible de production.
- Première mesure de latence réelle sur Kryoptic et sur le HSM cible : si le transport du message
  complet vers le HSM (`CKM_ML_DSA` pur) s'avère rédhibitoire, §2 se rouvre pour les trois suites
  simultanément.
- Toute publication ANSSI ou NIST modifiant la doctrine d'hybridation, les paramètres ML-DSA
  recommandés, ou FIPS 204.
- Toute cryptanalyse significative de ML-DSA (Dilithium) ou d'ECDSA P-256.
- Régression de `aws-lc-rs` sur ML-DSA (dépréciation, CVE, retrait d'API) → réévaluer
  `libcrux-ml-dsa` / `fips204`.
- Abandon, stagnation ou changement de gouvernance de Kryoptic → réexaminer l'outillage de dev,
  sans remettre en cause le mécanisme.
- Retour d'expérience du premier consommateur (ADR-030) : si la forme imposée ici s'avère
  inadaptée à l'implémentation réelle, amender ce document plutôt que le contourner localement.
- Au plus tard fin 2026, quelle que soit l'avancée, pour tenir 2027.

---

## Questions ouvertes — arbitrage humain requis avant « Statut : accepté »

**QS1 — Le socle impose-t-il `CKM_ML_DSA` pur à toute suite, ou l'outille-t-il seulement ?
TRANCHÉE (2026-08-25) : imposé (§2).** L'énumération `SigningMechanism` ne reçoit que `MlDsa65` ;
ajouter `HashMlDsa65Sha256` exigerait un nouvel ADR. Argument contraire pesé et retenu malgré tout
: `decision-seal` et `identity-assertion` héritent d'un choix instruit au regard des contraintes
d'`audit-seal`, qui manipule les documents les plus volumineux.

**QS2 — Forme exacte du point d'entrée de signature sur message dans `zs-hsm`. TRANCHÉE
(2026-08-25) : option (i).** Méthode distincte `sign_message(key, mechanism, message)` à côté de
`sign_digest`, appariements croisés refusés explicitement — limite la rupture, préserve la
surface existante, n'oblige aucun appelant ECDSA à changer. Option (ii) (entrée typée
`SigningInput::{Digest(&[u8]), Message(&[u8])}`) pesée et écartée : plus sûre structurellement
mais rupture d'API plus large que nécessaire ici. Refus croisé à tester explicitement dans les
deux sens.

**QS3 — Type de clé publique retourné par `zs-hsm`. TRANCHÉE (2026-08-25) : remplacer
`PublicKeyDer(Vec<u8>)` par un type portant explicitement son encodage.** `Sec1Uncompressed` /
`MlDsaRaw` plutôt qu'un nom déjà imprécis qui ne documente pas l'encodage — évite que
`accept_verifying_key` soit le seul endroit à savoir de quoi il s'agit. Rupture d'API assumée.

**QS4 — Migration de Q1, Q2, Q3, Q4 d'ADR-030 vers ce socle, et réécriture d'ADR-030 selon le
tableau §9. TRANCHÉE (2026-08-25) : confirmé.** En particulier Q2 (démarche fournisseurs HSM sur
`CKM_ML_DSA` et visa ANSSI) concerne les trois suites et non `audit-seal` seule — ces questions
déjà tranchées sont reprises ici sans être re-litigées. ADR-030 sera amendé avant son passage à
« accepté ».

**QS5 — Kryoptic : ADR de dépendance dédié inclus ici ou séparé ? Remplacement ou complément de
SoftHSM2 en dev et en CI ? TRANCHÉE (2026-08-25) : ADR de dépendance séparé, complément
d'abord.** Kryoptic est un outil, pas une décision de suite — mérite son propre ADR (règle
absolue #10 : licence / maintenance / CVE / gouvernance à instruire dans ce document dédié).
Complément de SoftHSM2 d'abord, remplacement envisageable seulement après vérification de parité
sur les suites v1.

**QS6 — Représentation CBOM d'un socle qui n'est pas une suite. TRANCHÉE (2026-08-25) : option
A.** Champs supplémentaires normalisés dans chaque entrée `[[suite]]` (`hybrid`, `components`,
`hsm_mechanisms`, `key_labels`, `foundation_adr`) — aucun changement d'outillage. Option B
(entité de niveau mécanisme dans `suites.toml` et `tools/generate-cbom.sh`, plus fidèle au modèle
CycloneDX 1.6) différée : à reconsidérer si un auditeur externe la demande explicitement.

**QS7 — Un socle jumeau pour ML-KEM-768 (`channel-kex/v2`) est-il à planifier dès maintenant, ou
à laisser dormir jusqu'à ce qu'un consommateur existe ? TRANCHÉE (2026-08-25) : laissé dormir.**
`channel-kex/v2` n'a aucun consommateur instruit ; l'inclure ici diluerait le socle sans
bénéfice. Décision consciente de ne pas le faire, consignée ici plutôt qu'implicite.

**QS8 — `decision-seal/v2` est absent des « Cibles post-quantiques » de
`crates/zs-crypto/CLAUDE.md`, alors que `suites.toml` porte déjà `successor =
"decision-seal/v2"` sur `decision-seal/v1` et que ce socle la vise explicitement. TRANCHÉE
(2026-08-25) : ajoutée.** Un socle qui vise trois suites alors que la doctrine du crate n'en
déclare que deux est une incohérence qu'un auditeur relèverait — à corriger dans
`crates/zs-crypto/CLAUDE.md` avant l'acceptation de cet ADR.

**QS9 — `authenticator-proof/v2` (ML-DSA-44/65, COSE -48/-49) relève-t-il de ce socle ? TRANCHÉE
(2026-08-25) : partage confirmé.** Non pour la partie HSM et hybridation (nous sommes
vérificateur, pas émetteur ; exception documentée à l'invariant 5, ADR-006), oui pour la partie
vérification (même `aws-lc-rs`, mêmes vecteurs ACVP/Wycheproof, même principe de garde de
longueur de clé publique par type).

**QS10 — Le socle doit-il exiger un premier jeu de mesures de latence (§7) avant son propre
passage à « accepté »**, ou ce prérequis appartient-il uniquement à ADR-030 ? Recommandation :
oui pour le socle — c'est ce qui rend le choix de §2 révisable sur des faits plutôt que sur une
intuition, et `crates/zs-crypto/CLAUDE.md` exige une mesure, pas une estimation.

---

Sources consultées ce jour, en complément de celles déjà citées par ADR-030 :
- [latchset/kryoptic — jeton PKCS#11 logiciel en Rust](https://github.com/latchset/kryoptic)
- [Red Hat — What's new in post-quantum cryptography in RHEL 10.1](https://www.redhat.com/en/blog/whats-new-post-quantum-cryptography-rhel-101)
- [Mastercard/pkcs11-tools — support PQC (ML-KEM, ML-DSA, SLH-DSA) et compatibilité Kryoptic](https://github.com/Mastercard/pkcs11-tools/blob/master/docs/INSTALL.md)
- [C2SP/wycheproof — ajout des vecteurs de test ML-DSA](https://github.com/C2SP/wycheproof/pull/112)
- [usnistgov/ACVP-Server — vecteurs ML-DSA keyGen/sigGen/sigVer FIPS 204](https://github.com/usnistgov/ACVP-Server/releases)
- [softhsm/SoftHSMv2 issue #800 — support ML-DSA, toujours ouverte](https://github.com/softhsm/SoftHSMv2/issues/800)
