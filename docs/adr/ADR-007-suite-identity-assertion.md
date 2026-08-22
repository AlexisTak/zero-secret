# ADR-007 — Spécification de la suite `identity-assertion` (émission, HSM)

**Statut** : accepté (spécification seule — implémentation différée à L1.2)
**Date** : 2026-08-22
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

L1.1 (`crates/zs-webauthn`, ADR-006) vérifie une preuve d'authentificateur. Ce qu'`identity-provider`
en fait ensuite — émettre une **assertion d'identité signée**, portant le niveau AAL atteint et
la méthode employée — est le vrai point de conformité post-quantique 2027 du parcours WebAuthn
(`docs/architecture.md` la désigne comme « la primitive de confiance de tout le système »), pas
la vérification de la signature de l'authentificateur elle-même (celle-ci est imposée par un
tiers non maîtrisé — voir ADR-006).

`referent-crypto` a signalé que la frontière entre `zs-webauthn` et `zs-crypto` risquait d'être
posée au mauvais endroit si cette suite n'était pas au moins nommée avant l'écriture de
`zs-webauthn` — d'où cet ADR, écrit en amont de L1.2, pour fixer la forme sans en faire
l'implémentation.

## Décision

**Nom de suite** : `identity-assertion`, à ajouter au tableau des cibles post-quantiques de
`crates/zs-crypto/CLAUDE.md`, aux côtés de `audit-seal` et `channel-kex` :

```
identity-assertion/v1  → ECDSA P-256                          (émission via zs-hsm)
identity-assertion/v2  → ECDSA P-256 + ML-DSA-65               (hybride, cible)
```

- **Émetteur, pas vérificateur** : contrairement à `authenticator-proof`, cette suite EST
  soumise à l'invariant 5 (hybridation stricte) dans toute sa force — c'est nous qui choisissons
  l'algorithme, l'hybridation `v2` est donc un objectif, pas une exception.
- **Clé privée exclusivement dans le HSM** (invariant 7) : la signature de l'assertion passe par
  `zs-hsm`/`credential-issuer` selon le flux déjà documenté dans `docs/architecture.md`, jamais
  par une clé manipulée en mémoire applicative.
- **Contenu de l'assertion** (à préciser en détail lors de l'implémentation L1.2, pas ici) :
  identifiant de principal, niveau AAL atteint (déterminé par la méthode effectivement
  vérifiée, jamais déclaré par le client — cf. modèle de menaces `identity-provider.md`,
  STRIDE Elevation of Privilege), méthode d'authentification, horodatage, référence à
  l'événement d'audit produit.
- **Ce que L1.1 doit anticiper** : la fonction de vérification de `zs-webauthn`
  (`verify_registration_ceremony` ou équivalent) doit renvoyer une valeur qui porte
  suffisamment d'information pour que L1.2 puisse construire cette assertion sans avoir à
  re-parser l'attestation — au minimum : identifiant de la clé publique acceptée, méthode
  déterminée (ex. `"webauthn/device-bound"` selon la présence de `attestedCredentialData` et le
  format d'attestation), horodatage de vérification. Aucune implémentation de signature n'est
  ajoutée à `zs-crypto` par cet ADR.

## Conséquences

**Positives** — la frontière de `zs-webauthn` (L1.1) est posée en connaissance de ce qui suivra
en L1.2, évitant une reprise de forme entre les deux lots. Le nom de suite est réservé,
évitant une collision de nommage future.

**Négatives** — spécifier avant d'implémenter introduit un risque que l'implémentation réelle de
L1.2 découvre un besoin non anticipé ici, nécessitant un ADR de révision. Accepté : le coût
d'un ADR de révision est inférieur au coût d'une mauvaise frontière entre deux crates.

**Surface d'attaque** — aucune nouvelle, cet ADR ne modifie aucun code. La surface réelle sera
traitée dans l'ADR ou la contribution qui implémentera L1.2.

## Critère de réexamen

Réexaminer dès le démarrage effectif de L1.2 : cet ADR n'est qu'une réservation de forme, pas
une conception complète. L'implémentation réelle peut amender le contenu précis de l'assertion
sans repasser par un nouvel ADR si la structure générale (émetteur, HSM, hybridation v2) reste
inchangée ; un changement de cette structure générale, lui, en exige un.
