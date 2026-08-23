# ADR-019 — Signature de décision (`decision-seal/v1`, H4, prérequis L2.4)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

En préparant L2.4 (`credential-issuer`), écart réel découvert : `docs/architecture.md` dit
explicitement que `credential-issuer` reçoit « la décision signée par le PDP », mais
`DecisionResponse` (`decision.proto`, L2.2) n'avait aucun champ de signature — seulement
`decision_hash` (`decision-binding/v1`, ADR-015), une empreinte d'intégrité calculable par
n'importe qui, pas une preuve d'origine PDP. Sans mTLS (différé partout ailleurs dans ce lot) ni
signature réelle, `credential-issuer` n'avait aucun moyen de distinguer une décision authentique
d'une décision fabriquée par un `access-broker` compromis. Décision validée par l'utilisateur :
scinder H4 avant L2.4, même patron que H1 (HSM) et H3 (vérification d'assertion).

## Décisions

### Nouvelle suite `decision-seal/v1`, distincte de `decision-binding/v1`

`decision-binding/v1` (hash, sans clé) ne couvre que requête + corpus de politiques — pas
`effect`/`reasons`/`max_ttl`/`constraints`. Signer `decision_hash` isolément aurait laissé un
`effect` substituable sous un `decision_hash` par ailleurs valide (démontré par test,
`effect_substitue_sous_un_decision_hash_valide_est_refuse`). Le message signé couvre l'ensemble
fermé : `request_id`, `decision_hash` (hex, réutilisé tel quel — pas recalculé), `policy_version`,
`effect`, `reasons`, `max_ttl` (entier de secondes, jamais flottant — cohérence Rust/Go),
`constraints`, `issued_at`. Domaine `zero-secret/decision-seal/v1`, SHA-256, ECDSA P-256 raw
`r‖s` hex — même construction que `identity_assertion`/`audit_seal` (ADR-012/013).

`request_id` n'est **pas** porté par `DecisionResponse` (choix de contrat antérieur, L2.2) — le
champ apparaît dans le message signé avec une valeur vide de ce côté du contrat aujourd'hui,
documenté explicitement dans le code (`zs-policy::pdp::decision_fields`) plutôt que silencieusement
omis. À corriger si `request_id` devient nécessaire à la corrélation côté `credential-issuer`.

### Clé HSM dédiée `zs-decision-seal-v1`, troisième clé séparée

Cohérent avec ADR-011 : jamais de réutilisation entre suites (rotation/révocation indépendantes,
fréquences et surfaces d'exposition différentes — le PDP est le composant le plus sollicité).

### `DecisionResponse` (protobuf), pas un document JSON opaque à reparser

Différence structurante avec `identity_assertion`/`audit_seal` : ces suites transmettent un blob
JSON qui EST les octets signés, reconstruit depuis une entrée non fiable (d'où
`NonCanonical`/`MalformedDocument`/clé dupliquée — une vraie surface d'attaque de parsing).
`decision-seal/v1` signe des champs déjà typés (décodés par `prost`/`tonic` des deux côtés) : la
canonicalisation JCS n'est qu'un détail de calcul interne du message signé, jamais un rempart
contre un document forgé. `decision_seal::verify` n'a donc pas cette classe d'erreurs — surface
plus simple par construction, pas par omission.

### Règle absolue #5 réinterprétée, `CLAUDE.md` non modifié

« Aucun appel réseau pendant l'évaluation » porte sur les **entrées** de la décision — le PDP ne
consulte aucune source externe pour DÉCIDER, garantissant déterminisme et rejeu hors ligne.
`Pdp::decide` (`zs-policy`) reste synchrone, pur, sans HSM, inchangé par H4. Le scellement est une
étape **postérieure et isolée** dans `apps/policy-engine` (pas dans `Pdp`) : évaluer et signer
restent deux opérations distinctes, seule la première est couverte par l'invariant. Décision
validée : documenté ici plutôt que d'éditer le fichier de gouvernance — réversible sans
re-valider `CLAUDE.md`.

**Conséquence tenue strictement** : un échec de scellement (HSM indisponible) devient une erreur
gRPC explicite sur `Decide()`, pas un refus métier — la décision elle-même n'existe pas sans
signature, `credential-issuer` refuserait de toute façon une réponse non signée. Distinct du
refus métier (P2), qui reste une `DecisionResponse` normale.

### Vérification hébergée dans `policy-engine` (`VerifyDecision`), pas un nouveau composant

Décision validée par l'utilisateur : même patron que H3 (`identity-provider` héberge déjà
vérification et future émission ensemble) — évite un quatrième service réseau Rust. `policy-engine`
vérifie ses propres décisions : la clé de vérification est dérivée de la clé de signature du
scelleur (`DecisionSealer::accepted_verifying_key`), pas configurée séparément.

**Compromis de défense en profondeur assumé et signalé** (`referent-crypto`) : signataire =
vérificateur dans le même service. Une compromission de `policy-engine` compromet les deux
fonctions ensemble, contrairement à un vérificateur hébergé ailleurs. Accepté pour la même raison
qu'en H3 — éviter la prolifération de services réseau non authentifiés (mTLS absent partout) tant
que l'infrastructure de confiance réseau n'existe pas.

### Régression de couverture de test assumée

Le test d'intégration réel de L2.2 (`apps/policy-engine/tests/decide_integration.rs`, deux
instances, même `decision_hash`) tournait sur ce poste sans dépendance externe. Depuis que
`policy_engine::serve` exige un `DecisionSealer` réel (HSM), ce test exige SoftHSM2 —
indisponible ici (Podman bloqué). `#[ignore]` avec `ZS_HSM_MODULE` requis, même patron que
`crates/zs-hsm/tests/pkcs11_integration.rs` (H1) — **signalé explicitement comme une régression
causée par ce lot**, pas comme une limite préexistante glissée sous le tapis. Les 9 tests
unitaires de `decision_seal.rs` (signeur déterministe) couvrent la logique cryptographique elle-
même, qui reste vérifiée réellement.

## Conséquences

**Positives** — `credential-issuer` (L2.4) pourra authentifier réellement l'origine d'une
décision avant tout appel à OpenBao, comblant l'écart entre `docs/architecture.md` et
l'implémentation. Le message signé ferme la classe d'attaque « `effect` substitué sous un
`decision_hash` valide », vérifiée par test dédié.

**Négatives** — `policy-engine` dépend désormais de `zs-hsm` (session HSM ouverte au démarrage,
échec dur si indisponible) — un composant auparavant pur-calcul devient dépendant d'un
périphérique matériel pour démarrer. Le test d'intégration réel de L2.2 ne tourne plus sur ce
poste. `request_id` absent du message signé (contrat antérieur non révisé).

**Surface d'attaque** — signataire et vérificateur cohabitent dans `policy-engine`, compromis de
défense en profondeur assumé. `VerifyDecision` reste exposé sans mTLS (même limite que `Decide`).

## Critère de réexamen

Réexaminer la cohabitation signataire/vérificateur si `credential-issuer` ou un tiers doit un
jour vérifier des décisions sans faire confiance à `policy-engine` lui-même (séparation en
composant dédié). Réexaminer l'absence de `request_id` dans le message signé si la corrélation
devient nécessaire côté `credential-issuer`. Réexaminer la réinterprétation de la règle #5 si un
futur lot rend le scellement lui-même consultatif (ex. quorum de signatures).
