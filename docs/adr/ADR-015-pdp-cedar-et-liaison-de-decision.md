# ADR-015 — PDP Cedar (`policy-engine`) et liaison de décision (`decision-binding/v1`)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

L2.2 implémente `Decide(DecisionRequest) → DecisionResponse` (`decision.proto`), évalué contre le
corpus Cedar de L2.1 (ADR-014). `DecisionResponse.decision_hash`/`policy_version` doivent suffire
à un rejeu hors ligne bit-exact par un tiers — invariant explicite du contrat. Deux décisions
structurantes distinctes ont émergé pendant cette contribution : la conception de
`decision_hash`/`policy_version`, et une régression de canonicalisation découverte en cours de
route, plus grave que prévu au départ.

## Décisions

### `decision_hash`/`policy_version` passent par `zs_crypto::decision_binding`, pas par un hash « maison »

Consultation `referent-crypto` : ces empreintes finissent dans un événement d'audit scellé et
doivent rester cohérentes avec la canonicalisation JCS déjà établie (ADR-012/013) — un second
calcul de hash indépendant dans `zs-policy` aurait reproduit exactement le piège du double-hachage
`aws-lc-rs` découvert en L1.2c (deux canonicalisations divergentes du même contenu). Nouveau module
`zs_crypto::decision_binding` (suite `decision-binding/v1`) : **pas** une suite de signature (aucune
clé, pas d'émission/vérification), donc l'invariant d'hybridation PQC de `zs-crypto/CLAUDE.md`
(qui concerne signature/échange de clé) ne s'y applique pas — seul un hash d'intégrité SHA-256.

Deux fonctions distinctes, jamais un hash générique exporté :
- `bind_request` : empreinte de la requête (JCS + SHA-256, même schéma qu'ADR-012/013).
- `bind_policy_corpus` : empreinte du schéma + des fichiers `.cedar`, triés par chemin **octet
  par octet**, hachés individuellement puis combinés à longueur préfixée (jamais une concaténation
  naïve — ambiguïté de frontière : `["ab","c"]` collisionnerait avec `["a","bc"]`), incluant la
  liste des noms de fichiers et la version du crate `cedar-policy` (un upgrade du moteur change la
  sémantique d'évaluation à corpus textuellement identique). Rejet explicite d'un fichier non-UTF-8
  ou porteur d'un BOM.

**`policy_version` = l'empreinte seule** (`decision-binding/v1:<hex>`), jamais un couple
tag/empreinte — décision validée explicitement par l'utilisateur : purement dérivable, cohérent
avec « rejouable hors ligne » sans dépendre d'un registre externe non vérifiable par le rejeu
lui-même.

### Correctif du hook `no-direct-crypto` : `sha2`/`sha3`/`blake3`/`digest` manquaient au motif

`sha2` n'était pas dans `tools/lib/check-no-direct-crypto.sh` — un trou du hook, pas une
autorisation implicite à calculer un hash hors `zs-crypto`. Corrigé dans la même contribution
(prérequis bloquant, pas une tâche séparée) : sans ce correctif, `zs-policy` aurait pu importer
`sha2` directement pour improviser son propre calcul, exactement le risque que la façade existe
pour éviter.

### `Pdp` vit dans `crates/zs-policy`, `apps/policy-engine` reste un adaptateur mince

Cohérent avec la description déjà écrite dans `crates/zs-policy/Cargo.toml` (« types et évaluation
partagés ») et le patron `zs-crypto`/`zs-hsm` : la logique déterministe est testable sans serveur
réseau (`Pdp::decide` est synchrone, ne retourne jamais d'erreur Rust — un refus est une
`DecisionResponse` normale, P2). `apps/policy-engine` charge le `Pdp` une fois et le sert via
`PolicyDecisionServiceServer` (`tonic`) — premier serveur réseau réel du dépôt (`identity-provider`,
L1.1, a été délibérément cantonné à une bibliothèque). `src/lib.rs`/`src/main.rs` séparés
uniquement pour que `tests/` démarre de vraies instances en process avec un client `tonic` réel —
pas une dépendance croisée `apps/`.

**mTLS explicitement hors périmètre** : aucune intégration SPIFFE/SPIRE n'existe encore dans le
dépôt ; ce serait un prérequis d'infrastructure séparé, pas improvisé ici.

### Traduction `Resource`/`Action` : un type/attribut inconnu est un refus de traduction, pas un « deny » Cedar implicite

`Request::new`/`Entities::from_entities` reçoivent le schéma (`Some(&schema)`) et valident donc
strictement contre lui : une `Action.verb` non déclarée dans `contracts/cedar/schema.cedarschema.json`
produit une erreur de construction, remontée comme refus de traduction explicite (raison
`requete_invalide:...`), plutôt que de compter sur le comportement par défaut « aucune politique ne
matche » de Cedar. Cohérent avec le principe déjà posé par L2.1 (« schéma d'abord », toute action
nouvelle déclarée avant usage) : une action non instruite est une erreur documentée, pas un refus
qui *se trouve* correct par accident.

### `DecisionRequest.policy_version` en entrée : refus explicite si différent de la version chargée

Le PDP ne sert qu'**une seule** version de politiques à la fois (« sans état » inclut : pas de
magasin multi-version en mémoire). Si le champ 6 de la requête est non vide et diffère de la
version effectivement chargée par cette instance, refus explicite (`policy_version_indisponible`)
— jamais un repli silencieux sur la version courante. Rejouer une décision archivée relance ce même
binaire déterministe contre les fichiers de politiques au commit historique correspondant, ce n'est
pas une fonctionnalité de replay du serveur vivant.

### Annotation `@id` du corpus remappée explicitement (découverte à l'implémentation)

`PolicySet::from_str` (analyse en bloc du corpus concaténé, comme le fait déjà
`tools/cedar-test.sh`) attribue des identifiants auto-générés (`policy0`, `policy1`, …) —
l'annotation `@id("...")` du corpus (L2.1, en-tête obligatoire de `policies/CLAUDE.md`) n'est
**pas** l'identifiant interne Cedar, seulement une métadonnée. `Pdp::decide` remappe chaque
`PolicyId` retourné vers son annotation `id` (`PolicySet::annotation`) avant de le placer dans
`DecisionResponse.reasons` — sans ce remappage, les raisons exposées auraient divergé
silencieusement des identifiants stables déjà référencés par les règles Sigma de L2.1 (ex.
`guardrail-authority-domain-isolation`), cassant la traçabilité que ces règles supposent.

### Régression découverte : `cedar-policy-core` active `serde_json/preserve_order` pour tout le workspace

**La plus significative des découvertes de cette contribution.** `cargo tree -e features` a montré
que `cedar-policy-core` (dépendance transitive de `cedar-policy`) active `serde_json/preserve_order`
(via `indexmap`). Cargo unifiant les features d'une dépendance partagée sur tout le graphe compilé
dans une même invocation, `serde_json::Map` bascule d'un `BTreeMap` implicite (tri lexicographique)
vers un `IndexMap` (ordre d'insertion) **pour tout le workspace**, y compris `crates/zs-crypto`, dès
que les deux crates sont compilées ensemble (`cargo test --workspace`).

`zs_crypto::common::canonical_bytes` (JCS, ADR-012/013) reposait sur ce backing implicite —
documenté comme tel, mais jamais rendu robuste. Symptôme réel observé : le test de vecteurs figés
`zs-audit::chain_vectors` échouait (`NonCanonical`) sous `--workspace` mais passait en isolation.
Impact réel : les signatures `identity-assertion/v1` et `audit-seal/v1` — déjà en production dans ce
dépôt (L1.2c/L1.4b) — auraient cessé d'être canoniques dans tout contexte de build compilant
`policy-engine` aux côtés du reste, cassant `verify()` silencieusement (un refus systématique qui
ressemble à un bug ailleurs, pas un crash explicite).

**Correctif** (consultation `referent-crypto`, validé) : `canonical_bytes` trie désormais les clés
d'objet **explicitement et récursivement** (`sort_keys_recursively`), reconstruisant un `Value`
neuf plutôt que de compter sur un backing de map. Correct quel que soit le mode de `serde_json::Map`.
Règles retenues : tableaux jamais triés (RFC 8785 §3.2.3 — leur ordre est sémantique) ; comparaison
sur les octets UTF-8 (diverge de JCS/UTF-16 au-dessus de U+FFFF, sans conséquence ici — tous les
champs canonicalisés sont des littéraux ASCII, `bounded_ascii_string!`) ; nombre à virgule flottante
refusé explicitement (`assert!`) plutôt que signé sous une forme ambiguë (JCS impose la
sérialisation ES6 des flottants, non implémentée). Vérifié : les 43 tests `zs-crypto` existants et
les vecteurs figés `audit-seal-v1/chain.json` produisent des octets strictement identiques
avant/après correctif (le tri explicite reproduit l'ordre que `BTreeMap` produisait déjà) — **pas
de régénération des vecteurs**, une régression de signature aurait été traitée comme un incident,
pas comme un changement de format à absorber silencieusement.

Nouveau test de non-régression (`common::tests::cles_triees_quel_que_soit_lordre_dinsertion`) :
insère les clés en ordre inverse, exige la sortie triée — aurait été rouge sous `--all-features`
avant ce correctif.

## Conséquences

**Positives** — `decision_hash`/`policy_version` cohérents avec ADR-012/013, déclarés au CBOM.
`policy-engine` est le premier service réseau réel du dépôt, testé de bout en bout avec un vrai
client `tonic` (deux instances distinctes, même `decision_hash`). La canonicalisation JCS partagée
par toutes les suites d'émission (`identity_assertion`, `audit_seal`, `decision_binding`) ne dépend
plus d'un détail de compilation d'une dépendance tierce.

**Négatives** — le hook `no-direct-crypto` reste une liste blanche/noire de motifs, pas une preuve
structurelle : un futur crate pourrait introduire un autre hash direct sous un nom non encore
couvert. Le remappage `@id` ajoute une indirection entre l'identifiant Cedar interne et
l'identifiant exposé, à maintenir en cohérence avec `policies/CLAUDE.md`.

**Surface d'attaque** — `Pdp::decide` est exposé à un appelant réseau non authentifié (pas de mTLS
dans ce lot) : acceptable uniquement parce qu'`access-broker` (L2.3) n'existe pas encore et que ce
service tourne en développement local. À ne jamais déployer sans authentification de l'appelant.

## Critère de réexamen

Réexaminer `no-direct-crypto` si une nouvelle bibliothèque de hachage apparaît dans l'écosystème
Rust sous un nom non couvert par le motif actuel. Réexaminer l'authentification de l'appelant du
PDP à l'ouverture de L2.3 (`access-broker`) — mTLS/SPIFFE devient alors un prérequis bloquant, pas
une note en marge.
