# ADR-024 — Frontière crypto TypeScript (`console-web`)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

L2.6 introduit le premier code TypeScript du dépôt (`apps/console-web`). Règle absolue #4 du
`CLAUDE.md` racine (« toute crypto passe par `crates/zs-crypto` ») ne mentionne que Rust/Go —
aucune façade équivalente n'existe côté TypeScript, et `tools/lib/check-no-direct-crypto.sh` ne
couvre que `*.rs`/`*.go`. `console-web` a malgré tout un besoin crypto-adjacent réel : un
identifiant de session opaque et imprévisible (jeton de session côté serveur, déjà exigé par
`security/threat-models/console-web.md`).

## Décision

### Zéro dépendance runtime — `node:http` natif, pas de framework

Même esprit qu'ADR-022 (Go, `net/http`) et le choix `axum` minimal d'ADR-023 (Rust) : aucun
framework de routage/templating (Next.js, Express, etc.) — `typescript`/`@types/node` restent
des `devDependencies` (compilation, jamais embarqués à l'exécution). Routage à la main
(`node:http`), templating par tagged template littéral local avec échappement systématique
(`src/html.ts`), client HTTP via `fetch` natif (Node ≥ 22). Justifié par la règle absolue #10 :
`console-web` n'a que 8 routes et 2 backends à appeler, un framework complet n'aurait rien
apporté qu'un routage à la main ne couvre pas déjà.

### `node:crypto` autorisé, liste blanche fermée, scopé à `console-web` seul

`console-web` peut utiliser directement le module standard `node:crypto` (backé par OpenSSL,
bibliothèque auditée — pas une primitive écrite à la main, invariant #3 respecté) pour
strictement : `randomBytes`, `randomUUID`, `timingSafeEqual`. Toute autre fonction du module
(`sign`, `verify`, `createCipheriv`, `createHash` sur une donnée du chemin de confiance, etc.)
est interdite dans `console-web` — cette exception ne couvre que la génération d'un identifiant
non prévisible, jamais une opération de confiance (signature, chiffrement, vérification).

**Scopé à `console-web` seul**, pas la première brique d'un `pkg/zscrypto-ts` partagé
hypothétique : aucun second consommateur TypeScript n'existe ni n'est planifié — en créer un
maintenant serait concevoir pour un besoin non instruit (même discipline que partout ailleurs
dans ce projet). Si un second composant TypeScript apparaît avec un besoin crypto-adjacent
similaire, réexaminer alors.

### `console-web` ne vérifie jamais une assertion — elle la relaie

Corollaire non négociable : `console-web` ne contient et ne contiendra aucun code de
vérification cryptographique (signature, canonicalisation JCS, comparaison de challenge).
L'assertion `identity-assertion/v1` reçue d'`identity-provider` est stockée opaque côté serveur
et rejouée telle quelle vers `access-broker` (`X-Identity-Assertion`) — jamais reconstruite,
réinterprétée ou re-signée par `console-web`. Toute vérification reste dans `zs-crypto`
(`identity_assertion::verify`, appelée par `identity-provider`/`access-broker`, ADR-016).

### Jeton de session : 256 bits, opaque, jamais un JWT

`crypto.randomBytes(32)` (256 bits — 128 bits serait le plancher acceptable, 256 est gratuit
ici), encodé base64url. Jamais de contenu signé/chiffré porté par le jeton lui-même (pas de
JWT) : la valeur de vérité vit côté serveur (la `Map` de session), le jeton n'est qu'une clé
d'accès à cette valeur — un JWT compromis resterait valide hors ligne jusqu'à expiration, un
jeton opaque compromis peut être révoqué immédiatement en supprimant l'entrée serveur.

### Session en mémoire, mono-instance — portée assumée, trois exigences

`Map<sessionId, {subjectId, identityAssertion, expiresAt}>`, même famille de coupe de portée
que `ConsumedDecisionStore` (L2.4) — mais avec trois exigences non négociables, pas une coupe
libre :
1. **Purge active périodique** sur `expiresAt` — sans ça la `Map` grossit sans borne (DoS
   mémoire), contrairement à une base de données avec `expires_at` interrogeable à la demande.
2. **Jamais journalisée** — l'assertion vit en clair dans le tas du processus ; aucun `console.log`
   ni trace ne doit exposer une entrée de session.
3. **Une seule réplique en déploiement** — signalé ici, pas encore câblé dans `deploy/` (aucun
   manifeste `console-web` n'existe encore) ; plusieurs répliques produiraient des 401 aléatoires
   selon l'instance qui reçoit la requête, pas seulement un problème de disponibilité.

### Cookie de session : `__Host-`, rotation, expiration côté serveur

`__Host-session` (`HttpOnly; Secure; SameSite=Strict; Path=/`, pas de `Domain` — le préfixe
`__Host-` interdit structurellement tout `Domain` et impose `Secure`+`Path=/`, rendant la
fixation de cookie inter-sous-domaine impossible par construction). Identifiant régénéré à
chaque ré-authentification réussie (anti-fixation de session). Expiration faisant autorité
côté serveur (`min(assertion.expires_at, inactivité)`) — jamais seulement le `Max-Age` du
cookie, qui ne protège rien si l'entrée serveur elle-même n'expire pas. Un `401` renvoyé par
`identity-provider`/`access-broker` déclenche la suppression de l'entrée serveur **puis**
l'effacement du cookie, dans cet ordre — jamais l'inverse (un cookie effacé sans l'entrée
serveur supprimée laisserait la session valide rejouable si le cookie était intercepté avant
son effacement effectif côté navigateur).

### CSRF : `SameSite=Strict` insuffisant seul

Contrôle explicite `Origin`/`Sec-Fetch-Site` sur tout `POST` — `SameSite=Strict` protège contre
la navigation cross-site classique mais pas contre toutes les variantes (sous-domaines,
navigateurs anciens, comportements non standard). Requête refusée si l'origine ne correspond
pas à celle configurée pour `console-web`.

## Conséquences

**Positives** — frontière crypto TypeScript explicite et étroite, alignée sur l'esprit de la
règle absolue #4 sans dupliquer inutilement une façade Rust pour un seul besoin (génération
d'aléa). Aucune primitive nouvelle, aucune entrée CBOM (pas une suite cryptographique au sens
du projet — identifiant unique, pas un mécanisme de confiance).

**Négatives** — pas de détecteur automatisé équivalent à `check-no-direct-crypto.sh` côté
TypeScript dans ce lot ; la discipline repose sur la revue de code jusqu'à ce qu'un second
composant TypeScript justifie d'écrire un tel outil. Session mono-instance : pas de haute
disponibilité pour `console-web` tant qu'un magasin partagé n'est pas introduit.

## Critère de réexamen

Réexaminer dès qu'un second composant TypeScript apparaît avec un besoin crypto-adjacent
similaire (évaluer un `pkg/zscrypto-ts` à ce moment, pas avant). Réexaminer la session en
mémoire dès qu'un déploiement multi-répliques de `console-web` est requis (magasin partagé,
probablement Postgres ou Redis — à instruire alors, pas anticipé ici). Envisager un détecteur
`check-no-direct-crypto` étendu au TypeScript si la liste blanche de ce ADR devient difficile à
maintenir par revue seule.
