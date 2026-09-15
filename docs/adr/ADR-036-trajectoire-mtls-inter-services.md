# ADR-036 — Trajectoire mTLS/SPIFFE-SPIRE pour les communications inter-services

**Statut** : proposé
**Date** : 2026-09-15
**Décideurs** : responsable technique, référent cryptographie

## Contexte

`docs/architecture.md` et `README.md` déclarent honnêtement, dans leurs sections « Limites
assumées » / « Non requis », qu'aucun mTLS n'est câblé entre les composants internes : les
liaisons gRPC (`access-broker` → `policy-engine`/`identity-provider`/`credential-issuer`,
`admin-api` → `identity-provider`/`audit-collector`, `credential-issuer` → `policy-engine`/
`audit-collector`) sont en clair. `apps/audit-sealer` fait exception : il n'est jamais exposé sur
un port réseau, uniquement sur un socket Unix colocalisé (ADR-026), ce qui déplace sa frontière
de confiance vers les permissions du système de fichiers plutôt que vers TLS.

Cette absence est déjà documentée dans le code (commentaires d'en-tête de chaque `main.go`) et
dans plusieurs modèles de menaces. Mais une revue contradictoire de `docs/adr/ADR-001-langages-et-frontieres.md`
a trouvé une formulation trompeuse : sa section Décision affirme *« La frontière entre Rust et Go
est **réseau (gRPC sur mTLS)**, pas FFI »* et *« Surface d'attaque — traitée par mTLS et identité
SPIFFE »*, au passé composé factuel, alors qu'aucune ligne de code ne configure de credentials TLS
sur un serveur ou un client gRPC interne (vérifié : aucune occurrence de `tls.`, `rustls`,
`InsecureSkipVerify` ou configuration TLS dans `apps/*/src`, `apps/*/internal`, `apps/*/main.go`).
La même confusion existait dans trois modèles de menaces (`access-broker.md`,
`credential-issuer.md`, `identity-provider.md`), qui labellisaient certains flux `(mTLS interne)`
dans leurs tableaux de frontières de confiance et de STRIDE, et cela réduisait artificiellement
une probabilité de risque (Tampering, Spoofing) sur la foi d'une protection absente — corrigé dans
la même contribution que cet ADR.

La règle 2 du `CLAUDE.md` racine exige que la sécurité inter-services soit décrite avec trois
états explicites (`IMPLEMENTED` / `EXPERIMENTAL` / `PLANNED`) et interdit de présenter des
communications comme authentifiées cryptographiquement si elles ne le sont pas réellement. Aucun
ADR dédié ne portait jusqu'ici cette décision — ADR-001 ne fait que la mentionner en passant, sans
trancher l'option retenue ni fournir de chemin de migration concret.

Référentiels normatifs : RFC 8446 (TLS 1.3), RFC 9525 (validation de nom de service X.509 pour
les clients TLS), SPIFFE X.509-SVID (spec SPIFFE, spiffe.io), NIST SP 800-207 (Zero Trust
Architecture, §3.4.2 sur l'identité de workload).

## Options envisagées

1. **Ne rien faire, laisser l'état actuel tel quel.** Avantage : zéro effort. Inconvénient :
   contrevient explicitement à la règle 2 du `CLAUDE.md`, qui exige un ADR et une abstraction de
   migration dès lors que le risque est identifié — ce n'est pas une option défendable devant un
   CESTI qui poserait la question.
2. **Implémenter mTLS statique (certificats longue durée, gérés hors bande) dès maintenant.**
   Avantage : ferme réellement la lacune. Inconvénient : pour un prototype à un seul opérateur,
   la gestion manuelle de certificats (génération, distribution, rotation, révocation) ajoute une
   charge opérationnelle et une surface de gestion de secrets (les clés privées des certificats)
   disproportionnées par rapport au risque réel à ce stade — et c'est un pas en arrière par
   rapport à l'objectif zero-secret si la rotation n'est pas automatisée dès le départ.
3. **SPIFFE/SPIRE avec SVID X.509 courts et rotation automatique, implémenté maintenant.**
   Avantage : c'est la cible déjà actée par ADR-001, cohérente avec l'absence de secret statique
   persistant (SVID courts, rotation automatique, pas de PKI manuelle à opérer). Inconvénient :
   un serveur SPIRE est un nouveau composant d'infrastructure à déployer, opérer et auditer
   (identité machine, attestation de workload, stockage de la CA SPIRE) — un investissement
   disproportionné tant que le prototype tourne sur un seul hôte de développement (`make up`,
   Podman) et n'a pas d'exigence de déploiement multi-hôte actée.
4. **Différer l'implémentation, documenter le risque, fournir une abstraction de code qui rend la
   migration future mécanique plutôt que d'être une réécriture.** Avantage : cohérent avec P10 du
   `CLAUDE.md` (« simplicité > complexité », « quel risque concret cette complexité
   supplémentaire réduit-elle ? ») — le risque réel aujourd'hui (accès réseau à
   `deploy/compose.dev.yml`, environnement de développement à hôte unique) ne justifie pas encore
   le coût d'exploitation d'une PKI ou d'un SPIRE. Inconvénient : le risque documenté ci-dessous
   reste réel jusqu'à l'implémentation ; un attaquant positionné sur le réseau interne (compromission
   d'un service, poste partageant le même segment) peut lire et, sous condition, tenter de
   modifier le trafic gRPC interne en clair.

## Décision

**Option 4.** Différer l'implémentation de mTLS/SPIFFE-SPIRE tant que le prototype reste à hôte
unique (backlog, pas de critère de passage en multi-hôte acté à ce jour), mais fermer l'écart
documentaire signalé en contexte et fournir dès maintenant l'abstraction de migration exigée par
la règle 2 du `CLAUDE.md`.

**État déclaré (trois niveaux imposés par la règle 2)** :

| Composant | État |
|---|---|
| Authentification WebAuthn/FIDO2 (utilisateur ↔ `identity-provider`) | `IMPLEMENTED` (hors périmètre de cet ADR, TLS navigateur classique) |
| Signature de décision PDP (`decision-seal/v1`, ADR-019) | `IMPLEMENTED` — authentifie l'origine d'une décision indépendamment du transport |
| Scellement d'événement d'audit (`audit-seal/v1`, ADR-013) | `IMPLEMENTED` — idem, indépendant du transport |
| mTLS entre binaires internes (gRPC) | **`PLANNED`** — aucune ligne de code, voir Conséquences |
| Identité de workload SPIFFE/SPIRE | **`PLANNED`** — aucune ligne de code |
| Socket Unix `audit-sealer` ↔ `audit-collector` | `IMPLEMENTED` (ADR-026) — hors périmètre mTLS par construction, jamais un port réseau |

**Abstraction fournie dans cette contribution** :

- Go : `pkg/zstransport` (`ServerOptions()`, `DialOptions()`) centralise la construction des
  quatre binaires gRPC internes (`access-broker`, `admin-api`, `audit-collector`,
  `credential-issuer`). Aujourd'hui : `ServerOptions()` ne retourne aucune credential,
  `DialOptions()` retourne explicitement `insecure.NewCredentials()` — un choix audité, pas un
  défaut implicite. Le jour où mTLS est accepté, seules ces deux fonctions changent ; aucun des
  quatre `main.go` n'a besoin d'être retouché pour la partie transport.
- Rust : `apps/policy-engine` et `apps/identity-provider` (les deux seuls serveurs tonic exposés
  sur un port réseau — `apps/audit-sealer` sert sur socket Unix, hors périmètre) portent
  désormais un commentaire de documentation sur leur fonction `serve()` pointant vers cet ADR :
  l'ajout de `.tls_config(...)` sur `Server::builder()` est le point d'insertion. Un crate dédié
  n'est pas créé pour deux points d'appel qui diffèrent déjà par leur signature — ce serait une
  abstraction sans bénéfice mesurable (P10 du `CLAUDE.md`, YAGNI).
- `docs/adr/ADR-001-langages-et-frontieres.md` est corrigé dans la même contribution pour ne plus
  affirmer mTLS comme acquis ; trois modèles de menaces (`access-broker.md`,
  `credential-issuer.md`, `identity-provider.md`) sont corrigés de même — voir Conséquences.

Ce choix applique P10 (simplicité > complexité, ne pas ajouter de technologie pour cocher une
case — cf. `CLAUDE.md` §2, « Ne jamais ajouter SPIFFE/SPIRE uniquement pour cocher une case ») et
respecte explicitement l'obligation de la règle 2 : documenter le risque, créer l'ADR, fournir une
abstraction de migration, ne pas prétendre que la propriété est acquise.

## Conséquences

**Positives** — la documentation (ADR-001, trois modèles de menaces) cesse d'affirmer une
protection inexistante ; un futur audit CESTI trouve un état cohérent entre le code, les ADR et
les modèles de menaces plutôt qu'une contradiction interne. La migration future est bornée à un
nombre de fichiers connu et petit (deux fonctions Go, deux points d'appel Rust) plutôt qu'une
reprise de six binaires.

**Négatives** — le risque documenté reste réel jusqu'à l'implémentation effective : un attaquant
ayant accès au segment réseau interne (compromission d'un service voisin, accès au réseau Podman
de `deploy/compose.dev.yml`) peut observer en clair le contenu des `DecisionRequest`/
`DecisionResponse`, ordres d'émission et événements d'audit en transit, et tenter de les modifier
— une modification est détectée par les signatures cryptographiques existantes
(`decision-seal/v1`, `audit-seal/v1`) mais pas empêchée par le transport. Cet ADR ne réduit pas ce
risque, il le documente et prépare la réduction future.

**Surface d'attaque** — inchangée par cet ADR (aucune ligne de comportement réseau ne change,
seule la construction du transport est refactorée derrière une fonction). Le risque réseau
préexistant demeure entier.

**Charge d'exploitation** — nulle ajoutée par cet ADR. Une future acceptation de l'option 3
(SPIFFE/SPIRE) ajouterait un composant d'infrastructure à opérer ; ce coût est délibérément
différé, pas nié.

**Réversibilité** — élevée : `pkg/zstransport` et les deux commentaires Rust sont un point
d'insertion, pas un engagement irréversible envers SPIFFE/SPIRE plutôt que mTLS statique ou toute
autre solution ; le choix de la technologie de migration reste ouvert à la date d'acceptation de
cette trajectoire.

**Trajectoire post-quantique** — sans effet : le transport gRPC (TLS 1.3) est un sujet distinct de
la trajectoire PQC des suites de signature applicatives (`security/crypto-inventory/suites.toml`,
ADR-030/031/032). Si TLS est un jour câblé, le choix de sa suite de chiffrement PQC/hybride sera
tranché par un ADR séparé, informé par l'état de l'écosystème TLS post-quantique au moment de
l'implémentation.

## Critère de réexamen

- Le prototype passe d'un déploiement à hôte unique (`make up`) à un déploiement multi-hôte ou
  multi-tenant réel — c'est l'événement qui rend le risque documenté ici concrètement
  exploitable par un attaquant réseau externe au poste de développement.
- Une revue de sécurité tierce (CESTI, pentest) qualifie ce point de bloquant pour la poursuite
  du programme.
- Le projet entre en phase de qualification ou de certification, qui exige une preuve
  d'authentification mutuelle entre composants.
