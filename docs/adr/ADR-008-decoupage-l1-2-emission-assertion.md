# ADR-008 — Découpage de L1.2 et frontière d'émission de l'assertion d'identité

**Statut** : accepté
**Date** : 2026-08-22
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

Le backlog L1.2 (« Authentification et assertion ») demande trois choses dans une seule ligne :
vérifier une assertion WebAuthn via `zs-crypto`, détecter un clonage d'authentificateur par le
compteur de signature, et émettre une assertion d'identité **signée** portant l'AAL atteint et
la méthode employée (forme réservée par ADR-007).

Consulté avant toute modification de `zs-crypto`/`zs-hsm` (règle du `CLAUDE.md` de
`crates/zs-crypto`), `referent-crypto` a identifié que ces trois éléments ne sont pas de même
nature : les deux premiers sont de la vérification (réutilisent `authenticator-proof/v1`
existante, aucune nouvelle opération crypto) ; le troisième est une **émission** — le seul point
de conformité post-quantique 2027 réel du parcours (`identity-assertion/v1|v2`, ADR-007) — et
exige une intégration PKCS#11/SoftHSM2 réelle dans `crates/zs-hsm`, aujourd'hui un stub vide
(`//! Non implémenté.`).

Mélanger ces deux natures dans une seule contribution poserait un mauvais périmètre d'audit (le
relecteur RSSI/CESTI ne peut pas juger avec la même grille du parsing WebAuthn et de la seule
crate autorisée à contenir de l'`unsafe` FFI), introduirait une dépendance nouvelle non discutée
(`cryptoki` ou équivalent, règle absolue #10 du `CLAUDE.md` racine) et laisserait la sémantique
de perte de session HSM sans ADR dédié.

## Décision

L1.2 est livré en **trois contributions distinctes** :

- **L1.2a** (cette contribution) — `crates/zs-webauthn::authentication` : vérification d'une
  cérémonie d'authentification (`webauthn.get`) et détection de clonage par compteur de
  signature. Réutilise `authenticator-proof/v1` telle quelle. **Aucune ligne ajoutée à
  `zs-crypto` ni `zs-hsm`.**
- **L1.2b** (même contribution) — `AuthenticationClaims` : un type portant l'AAL déterminé et la
  méthode employée, **non sérialisable et non exporté au-delà de la frontière de crate**. Ce
  n'est pas une assertion, seulement ce qui la nourrira. Un type « assertion non signée » mais
  sérialisable serait un contournement d'authentification représentable — interdit par
  construction (règle absolue #2, refus par défaut), pas laissé à la discipline de revue.
- **L1.2c** (différée, contribution dédiée, nouvel ADR requis) — intégration PKCS#11/SoftHSM2
  réelle dans `crates/zs-hsm` et `zs_crypto::identity_assertion::seal`, produisant l'assertion
  signée `identity-assertion/v1` (ADR-007). Nécessite une analyse de dépendance (`cryptoki` ou
  équivalent — licence, maintenance, CVE) avant de démarrer.

### Frontières posées maintenant, sans attendre L1.2c

- **R5** — `crates/zs-webauthn` ne dépend jamais de `crates/zs-hsm`. Vérifié par un test
  d'architecture dédié (`tools/lib/check-webauthn-no-hsm.sh`, fixtures violation/clean), au même
  titre que les détecteurs L0.2.
- **R2** — la clé publique vérifiante provient exclusivement d'un `RegisteredCredential` fourni
  par l'appelant (registre), jamais reconstruite depuis l'entrée cliente. `accept_key` revalide
  l'encodage à chaque appel, comme à l'enregistrement.
- **Compteur figé à l'enregistrement** — `counter_supported` (migration 004) est déterminé une
  fois, jamais réévalué par assertion : un clone qui force `signCount = 0` ne peut pas désactiver
  rétroactivement la détection pour un authentificateur qui la supportait.
- **Sémantique d'atomicité des ports** — `ChallengeStore::consume` et `SignCounterStore::advance`
  sont livrés comme traits documentés (contrat d'atomicité explicite, comparaison et écriture en
  une seule opération), sans implémentation — cohérent avec le scope-cut DB de L1.1 (bibliothèque
  seule). La sémantique du contrat n'est pas différée, seulement son branchement réel.
- **R8 (rappel pour L1.2c)** — le format d'assertion signée devra porter un champ `suite`
  explicite et un conteneur de signature à N composantes dès `v1`, pour que l'hybridation `v2`
  (ADR-007) ne casse pas le format.
- **R7 (rappel pour L1.2c)** — ordre de chaînage retenu : `audit_event_id` (UUIDv7) généré
  d'abord, assertion scellée le portant, événement d'audit scellé portant
  `SHA-256(assertion)` — évite la circularité qu'aurait une référence dans les deux sens.
- **R6 (rappel pour L1.2c)** — aucun repli logiciel : une perte de session HSM doit produire un
  refus d'émettre, jamais une signature en mémoire applicative, même en dev.

## Conséquences

**Positives** — chaque contribution reste auditable par une seule grille de lecture. Aucune
dépendance nouvelle introduite par L1.2a/b. Le format v1 de l'assertion signée pourra être conçu
extensible dès le départ (R8) plutôt que corrigé après coup.

**Négatives** — le critère d'acceptation du backlog L1.2 (« assertion rejouée → refus ») n'est
démontré qu'au niveau de la cérémonie WebAuthn (challenge à usage unique, même mécanisme qu'en
L1.1) par cette contribution, pas au niveau de l'assertion d'identité signée elle-même — cette
dernière n'existe pas encore. Coché partiellement dans `docs/backlog.md`, avec cette note
explicite plutôt qu'silencieusement.

**Surface d'attaque** — aucune nouvelle primitive cryptographique. Le compteur de signature et
le challenge à usage unique sont des mécanismes déjà couverts par les invariants existants
(comparaison en temps constant pour le challenge, atomicité désormais explicite pour le
compteur).

## Critère de réexamen

Réexaminer au démarrage effectif de L1.2c : cet ADR fixe la frontière et les rappels R6/R7/R8,
pas la conception complète de l'intégration HSM. Un changement de cette frontière générale (par
exemple, `zs-webauthn` en viendrait à avoir besoin d'émettre) exige un nouvel ADR.
