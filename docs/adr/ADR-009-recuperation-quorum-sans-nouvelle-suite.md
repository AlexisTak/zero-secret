# ADR-009 — Récupération à quorum : réutilisation d'authenticator-proof, sans nouvelle suite

**Statut** : accepté
**Date** : 2026-08-22
**Décideurs** : responsable technique

## Contexte

Le backlog L1.3 demande une révocation d'authentificateur à effet immédiat et une récupération
« à quorum » (plusieurs porteurs distincts), « sous scellés, systématiquement alarmante ». Le
modèle de menaces `identity-provider.md` (ligne 35) anticipait un « analyseur de quorum » dédié,
sans en préciser la forme.

Deux approches étaient possibles pour faire approuver une récupération par plusieurs porteurs :

1. Une nouvelle suite cryptographique dédiée (ex. signature multi-partie, seuil BLS ou
   équivalent) — nouvelle primitive, nouvelle entrée CBOM, revue `referent-crypto` complète.
2. Réutiliser la suite `authenticator-proof/v1` déjà existante : chaque porteur approuve en
   effectuant sa **propre cérémonie d'authentification WebAuthn** (L1.2), et le quorum se réduit
   à compter des approbations déjà vérifiées, avec la garantie que chacune vient d'un porteur
   distinct.

## Décision

**Option 2, retenue.** `crates/zs-webauthn::recovery::verify_quorum` prend une liste
d'approbations — chacune construite uniquement à partir d'`AuthenticationClaims` réellement
produites par `verify_authentication_ceremony` (pas de constructeur permettant de fabriquer une
approbation sans authentification réelle) — et vérifie que le nombre de `credential_id`
**distincts** atteint le seuil demandé. Aucune ligne n'est ajoutée à `zs-crypto` ; aucune
nouvelle entrée CBOM n'est nécessaire.

Un plancher absolu (`MINIMUM_THRESHOLD = 2`) est imposé par le module lui-même, non
contournable par un paramètre d'appel : un appelant qui configurerait `threshold = 1` par erreur
se voit refusé structurellement — c'est le critère d'acceptation du backlog tenu par
construction, pas par convention.

**Révocation** : `RegisteredCredential.revoked` (nouveau champ), vérifié en tout premier dans
`verify_authentication_ceremony`, avant toute autre vérification — effet immédiat au sens où
aucune assertion ne peut plus réussir dès que le registre marque l'authentificateur révoqué,
sans fenêtre de grâce liée à un cache. La colonne `revoked_at` existait déjà dans le schéma
(migration 003) ; aucune migration nouvelle n'était nécessaire pour la révocation.

### Ce que cette décision ne couvre pas (différé, documenté)

- **Liaison entre les approbations et une récupération précise.** `verify_quorum` garantit la
  distinction des porteurs et le seuil, pas que N approbations portent sur la *même* demande de
  récupération. `Challenge` (`zs-crypto`) n'expose aucun constructeur déterministe (ADR-006 : un
  challenge est un CSPRNG, jamais dérivé d'un identifiant) — cette liaison est donc la
  responsabilité de l'appelant (`identity-provider`, pas encore construit), qui devra associer
  chaque challenge d'approbation à un identifiant de requête de récupération dans son propre
  stockage.
- **Scellement/chaînage réel de l'événement de récupération.** Différé à L1.4 (audit du
  parcours) — `zs-audit` est un stub vide à ce jour. `RecoveryOutcome` porte `#[must_use]` avec
  un message explicite pour qu'un appelant ne puisse pas ignorer silencieusement le résultat en
  attendant que L1.4 fournisse le scellement réel.
- **Implémentation des ports de stockage** (`ChallengeStore`, `SignCounterStore`, L1.2) —
  cohérent avec le scope-cut bibliothèque de L1.1/L1.2.

## Conséquences

**Positives** — aucune nouvelle primitive cryptographique, aucun risque de mauvaise
implémentation d'un schéma de seuil cryptographique non trivial. Le quorum est une propriété de
comptage sur des identifiants, entièrement dans le domaine du code applicatif classique — plus
simple à auditer qu'un schéma cryptographique nouveau.

**Négatives** — cette approche suppose que chaque porteur dispose déjà d'un authentificateur
WebAuthn enregistré (L1.1) : elle ne fonctionne pas pour un scénario de récupération où
justement *tous* les authentificateurs d'un principal auraient été perdus. Ce cas (récupération
« à froid », sans aucun authentificateur disponible) n'est pas couvert par L1.3 et reste hors
périmètre — à traiter par un mécanisme distinct si le besoin se confirme.

**Surface d'attaque** — aucune nouvelle primitive cryptographique. La déduplication par
`credential_id` (`HashSet`) est le seul mécanisme structurel empêchant un porteur unique de
compter plusieurs fois ; testé explicitement (`meme_porteur_repete_ne_compte_quune_fois`).

## Critère de réexamen

Réexaminer si un scénario de récupération « à froid » (sans authentificateur disponible) devient
un besoin réel — cela exigerait un mécanisme distinct, hors du réemploi d'`authenticator-proof/v1`
décrit ici, et probablement une nouvelle suite cryptographique à instruire avec `referent-crypto`.
