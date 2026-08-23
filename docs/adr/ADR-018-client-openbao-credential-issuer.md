# ADR-018 — Client OpenBao (`credential-issuer`, H2, prérequis L2.4)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique

## Contexte

H2 livre le client OpenBao de `credential-issuer` — prérequis symétrique à H1 (HSM) pour la
chaîne d'émission. `deploy/compose.dev.yml` (L0.6) fait déjà tourner OpenBao en mode `-dev`, mais
Podman/Docker sont bloqués par la politique de permission de cette session : aucun OpenBao réel
n'est joignable ici, même famille de limite que SoftHSM2 en H1.

## Décisions

### Client `github.com/openbao/openbao/api/v2`, pas `github.com/hashicorp/vault/api`

Vérifié disponible et versionné (MPL-2.0). ADR-002 a choisi OpenBao précisément pour sa licence
OSI (MPL-2.0) face à Vault (BUSL-1.1) — importer le client Vault, même API-compatible, aurait
introduit une dépendance dont la licence contredit la raison même de ce choix.

### Portée : client générique de bail, pas le moteur de secrets

`IssueLease(ctx, path, params)`/`Revoke(ctx, leaseID)` sont agnostiques du moteur OpenBao
(PostgreSQL dynamique, PKI, KV). Quel moteur pour quel verbe (`db.connect` → probablement des
identifiants PostgreSQL dynamiques, cohérent avec le fil rouge `db.connect` de L2.1-L2.3) est une
décision de L2.4, pas de H2 — H2 ne présuppose pas le moteur avant qu'un appelant réel en ait
besoin.

### Authentification par jeton en variable d'environnement — provisoire, signalé

`Config.Token`, alimenté par `ZS_CI_OPENBAO_TOKEN` côté `main.go` (pas encore câblé — H2 livre la
bibliothèque, pas le binaire). Même patron que H3 (`ZS_IDP_VERIFYING_KEY_HEX`) : en dev, OpenBao
génère son propre jeton root et l'affiche dans ses logs, jamais fixé en dur (règle absolue #1). Un
mécanisme d'authentification de production (AppRole, Kubernetes auth) n'est pas conçu ici.

### Retries désactivés explicitement

`MaxRetries = 0` sur le client OpenBao sous-jacent, plutôt que le défaut de la bibliothèque (2
essais avec backoff). Un retry automatique masquerait une indisponibilité réelle derrière un délai
variable, rendant le refus moins prévisible et plus difficile à tester déterministiquement. Une
politique de retry authentique (si nécessaire) reste à instruire séparément, pas empruntée
implicitement au défaut de la bibliothèque cliente.

### `Lease.String()`/`GoString()` masquent les données

Un `log.Printf("%v", lease)` ou `%+v` accidentel ne doit jamais faire fuiter un secret (règle
absolue #1). Vérifié par test : le texte formaté ne contient jamais la valeur injectée, y compris
via `%+v` (qui passe par `GoString()` pour un type qui l'implémente).

### Indisponibilité = `ErrUnavailable`, jamais un repli

Toute erreur réseau, réponse non-2xx, timeout, ou réponse sans `lease_id` exploitable remonte
`ErrUnavailable` — jamais un bail vide traité comme absence de contrainte, jamais un credential
généré localement en secours (R2, critère d'acceptation explicite du backlog H2). Vérifié par
test avec un serveur `httptest` simulant chacun de ces cas, y compris un dépassement de délai réel
mesuré (le timeout est respecté, pas seulement déclaré).

## Conséquences

**Positives** — `credential-issuer` (L2.4) aura un client réel à appeler, testé sur tous les
chemins de refus. La licence de la dépendance reste cohérente avec ADR-002. Aucun secret ne peut
fuiter par un log de débogage naïf sur le type `Lease`.

**Négatives** — l'authentification par jeton en variable d'environnement est un mécanisme
provisoire, à remplacer avant toute mise en production réelle (pas de rotation, pas de révocation
de jeton). Les retries désactivés déplacent la responsabilité de résilience vers l'appelant
(L2.4) ou l'infrastructure, pas résolue ici.

**Surface d'attaque non couverte, signalée** : test d'intégration réel contre un vrai OpenBao
(`deploy/compose.dev.yml`) **non exécuté** — Podman/Docker bloqués sur ce poste, même limite que
SoftHSM2 (H1). Différé à CI/Jenkins Linux ou à un humain avec Podman disponible.

## Critère de réexamen

Réexaminer l'authentification par jeton à l'ouverture de L2.4 si un déploiement au-delà du
développement local est envisagé. Réexaminer la politique de retry si des indisponibilités
transitoires d'OpenBao s'avèrent fréquentes en usage réel.
