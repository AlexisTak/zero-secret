# ADR-025 — Entrée réseau réelle pour `credential-issuer` + câblage `access-broker` (L2.4 suite)

**Statut** : accepté
**Date** : 2026-08-24
**Décideurs** : responsable technique

## Contexte

`apps/credential-issuer` (L2.4) était une bibliothèque testée (`internal/issuer`,
`internal/openbao`, H2) mais totalement inaccessible en réseau — `main.go` un stub qui échouait
immédiatement (ADR-020, ADR-018). `access-broker` ne l'appelait jamais : `Broker.Decide`
retournait juste la `Decision` sans déclencher d'émission (commentaire explicite dans
`internal/broker/types.go`, ADR-017). Aucun contrat n'existait entre les deux.

## Décision de portée

Livrer uniquement : serveur réseau réel pour `credential-issuer`, câblage `access-broker` →
`credential-issuer` après une décision `ALLOW`, émission OpenBao réelle de bout en bout.
**`credential.issued` reste non scellé** — même angle mort que `policy.decided`
(`access-broker`) et l'événement d'`admin-api`, reconfirmé explicitement ici plutôt que
silencieusement répété : aucun pont d'audit Rust↔Go n'a été construit dans ce dépôt (aucun
composant Go ne scelle un événement d'audit à ce jour). Le construire exigerait un nouveau
service gRPC Rust de scellement, appelé par tous les composants Go concernés — décision
structurante distincte, non instruite ici, discutée et explicitement différée avec
l'utilisateur avant ce lot.

## Décisions

### gRPC, pas HTTP

`access-broker` → `credential-issuer` est un appel service-à-service interne, comme
`policy-engine`/`identity-provider` — pas une entrée navigateur (HTTP est réservé aux endpoints
BFF-facing d'`access-broker`/`admin-api`/`identity-provider`, déjà établis pour `console-web`,
ADR-022/ADR-023). Nouveau contrat `contracts/proto/credential/v1/emission.proto`
(`CredentialIssuanceService.Emit`/`Revoke`), même style que `policy/v1`/`identity/v1` —
`EmissionOrder`/`EmissionResult` plutôt que `EmitRequest`/`EmitResponse` pour rester aligné avec
le vocabulaire déjà établi côté Go (`internal/issuer`), même raisonnement que
`DecisionRequest`/`DecisionResponse` dans `policy/v1`.

### `ConsumedDecisionStore` implémenté en mémoire — fermeture de trou, pas un ajout de portée

`VerifyDecision` (H4) valide la signature d'une `DecisionResponse` mais ne détecte pas le rejeu
d'une décision déjà consommée. Tant que `credential-issuer` était inaccessible en réseau,
ADR-020 pouvait légitimement différer cette question (« reste inutilisable »). Une fois le
serveur réel, une décision `ALLOW` signée rejouée deux fois émettrait deux credentials pour une
seule autorisation — un cas d'espèce direct de la règle absolue #2 (refus par défaut). Fermer ce
trou n'est donc plus une coupe de portée légitime à ce stade.

Implémentation : `InMemoryConsumedDecisionStore` (`apps/credential-issuer/internal/issuer/
consumed_decisions.go`), `map[string]struct{}` protégée par mutex, clé = `decision_hash`.
Section critique couvrant lecture ET écriture (jamais un `get` puis `set` séparés — même mise
en garde TOCTOU que `ChallengeStore`/`SignCounterStore`, H5/ADR-023). Mono-instance, pas de
purge (une décision consommée n'est jamais retirée, même après expiration de son `max_ttl` —
un rejeu après expiration reste un rejeu). Même famille de coupe que `SessionStore`
(`console-web`, ADR-024) et `ConsumedDecisionStore` dans son état d'origine (ADR-020) : portée
réduite assumée, documentée, pas cachée.

### `broker.Decision.Signed` — nouveau champ porteur de la décision complète

`broker.Decision` (forme aplatie utilisée pour la réponse JSON à `console-web`) ne portait pas
les champs de scellement (`decision_signature`, `decision_signature_key_id`, `issued_at`,
`effect`, `constraints`) nécessaires à `VerifyDecision` côté `credential-issuer`. Un nouveau
champ `Signed *policyv1.DecisionResponse` porte la réponse complète du PDP, peuplé uniquement
quand `Allowed = true` (`nil` sinon — aucune décision signée à transmettre pour un refus).
`internal/httpapi/handler.go` l'utilise pour construire l'`EmissionOrder`, jamais reconstruit
depuis les champs aplatis.

### Échec d'émission ≠ invalidation de la décision

Un échec d'émission (OpenBao indisponible, décision déjà consommée) ne rend jamais la décision
elle-même invalide : la réponse HTTP reste `200` avec `allowed: true`, mais `lease_id`/
`lease_duration_seconds` restent absents (`contracts/openapi/access-broker.yaml`, `Decision`).
Le client doit distinguer « refusé » d'« autorisé mais rien n'a pu être émis » — documenté
explicitement dans le contrat, testé (`TestEmissionEchoueeNinvalidePasLaDecisionMaisOmetLeBail`).

### Pas de TLS/mTLS

Même dette que partout ailleurs (L2.2/H3/H4/H5/ADR-022/ADR-023).

## Conséquences

**Positives** — `credential-issuer` a un vrai chemin d'émission de bout en bout, testé par un
serveur gRPC réel en process (`apps/credential-issuer/internal/grpcapi/handler_test.go`,
y compris un test de rejeu). Le trou de rejeu identifié par ADR-020 est fermé au moment précis
où il devient exploitable, pas avant (aurait été une anticipation non instruite) ni après
(aurait laissé une fenêtre réelle ouverte).

**Négatives** — `credential.issued` toujours non scellé : la traçabilité d'une émission réussie
repose sur le journal applicatif, pas sur un événement d'audit vérifiable hors ligne, tant que
le pont d'audit Rust↔Go n'existe pas. Pas de TLS.

**Surface d'attaque** — nouvelle : un service gRPC interne supplémentaire, en clair. Le risque
le plus direct (rejeu d'une décision ALLOW pour multiplier les émissions) est neutralisé par
construction (`ConsumedDecisionStore`). Le mapping verbe → moteur OpenBao reste minimal
(`db.connect` seul, ADR-020) — aucun verbe supplémentaire n'est ajouté par ce lot.

## Critère de réexamen

Réexaminer `credential.issued` non scellé dès qu'un pont d'audit Rust↔Go est instruit (probable
candidat : étendre `audit-collector`, aujourd'hui un stub, en service gRPC de scellement partagé
par tous les composants Go — décision à instruire séparément, pas anticipée ici). Réexaminer le
TLS/mTLS dès que SPIFFE/SPIRE est câblé dans ce dépôt.
