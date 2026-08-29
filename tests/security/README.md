# tests/security/

Suite de tests de pénétration automatisés (voir `penthtest.md` à la racine du dépôt et
`docs/superpowers/specs/2026-08-25-security-test-suite-design.md` pour la conception complète).

## Pourquoi les tests ne sont pas ici

Chaque app Go (`access-broker`, `admin-api`, `audit-collector`, `credential-issuer`) est son
propre module Go (`go.work`) et sa logique HTTP/gRPC vit sous un chemin `internal/` — la règle de
visibilité `internal` de Go interdit à un module externe de l'importer. Les tests de sécurité
vivent donc **co-localisés dans le module de l'app qu'ils testent** :

- `apps/admin-api/internal/httpapi/security_*_test.go`
- `apps/access-broker/internal/httpapi/security_*_test.go`
- `apps/audit-collector/internal/collector/security_*_test.go`
- `apps/console-web/src/security.test.ts`
- `apps/identity-provider/src/httpapi.rs` (module `#[cfg(test)] mod tests` existant, étendu)

Ce dossier ne contient que ce qui n'a pas besoin d'importer un `internal/` d'app :
- `report/aggregate/` — lit les JSON écrits par chaque module et produit un résumé Markdown.
- `infrastructure/` — contrôle statique de `deploy/compose.dev.yml`.
- `dependencies/` — pointe vers `make audit`, déjà en CI.

## Catégories hors périmètre (aucune surface réelle trouvée)

Confirmé par lecture du code le 2026-08-25 (voir la spec pour le détail par catégorie) :
- **SSRF** : aucune URL sortante dérivée d'une entrée utilisateur.
- **Uploads** : aucun `multipart`/`FormFile` dans `apps/`.
- **IA / RAG** : aucun LLM, agent, RAG ou vector store dans le dépôt.

Si l'une de ces surfaces apparaît dans une future contribution, relire la spec avant de rouvrir
la catégorie correspondante — ne pas fabriquer de test pour une fonctionnalité qui n'existe pas
encore (règle 19 de `penthtest.md`).

## Lancer les tests

```bash
make security-quick   # Phase 1 — pas d'infra requise, CI
make security-fuzz     # fuzzing natif Go, budget borné
make security-full     # Phase 2 — nécessite make up (Postgres + SoftHSM2), voir backlog ci-dessous
```

## Backlog Phase 2 (nécessite Postgres + SoftHSM2 réels — `make up`)

Ces tests ne sont **pas** écrits dans cette itération : `apps/identity-provider` enveloppe un
`sqlx::PgPool` concret (`src/store.rs:17-19`, pas de trait), et `AssertionSealer`/`AuditSealer`
scellent via un HSM réel (même famille que `DecisionSealer` de `policy-engine`, qui exige
SoftHSM2). Aucun double en process n'est possible sans changer la production pour la rendre
testable — hors périmètre de ce lot.

1. **Bypass de cérémonie** — appeler `registration_verify`/`authentication_verify`
   (`apps/identity-provider/src/httpapi.rs:164,296`) sans challenge préalablement émis par
   `registration_challenge`/`authentication_challenge` (`:127,248`) — doit être refusé
   (`challenge_invalide`, déjà le comportement attendu ; à couvrir par un test réel contre
   Postgres).
2. **Rejeu de challenge consommé** — appeler `registration_verify` deux fois avec le même
   `client_data_json` (même challenge) — `consume_challenge` (`store.rs`) doit refuser le second
   appel (retourne `None`).
3. **Race condition sur `consume_challenge`** — deux requêtes concurrentes consomment le même
   challenge (`store.rs`, appelé depuis `httpapi.rs:175-180`) — une seule doit réussir. Nécessite
   une vraie connexion Postgres pour observer l'atomicité réelle de la requête
   `UPDATE ... RETURNING`.
4. **Rate-limit sous charge réelle** — rafale contre `registration/challenge` avec un vrai
   `access-broker`/`identity-provider` démarrés (`make up`), pour mesurer latence/CPU/RAM en plus
   du simple constat d'absence (déjà couvert en Phase 1 par
   `apps/admin-api/internal/httpapi/security_rate_limit_test.go`, sans charge réelle).
5. **Habilitation de l'appelant sur `admin-api`** : l'authentification est faite (ADR-035 —
   assertion `X-Identity-Assertion` de niveau AAL3 vérifiée avant toute évaluation du quorum,
   verrouillée par `security_authorization_test.go`). Reste ouvert : rien ne vérifie que cet
   appelant a le droit d'initier **cette** opération. La levée suppose de trancher la granularité
   des rôles d'administration, angle mort explicite d'ADR-021 — `SEC-ADMIN-API-AUTHZ-001` reste
   journalisé en MEDIUM non bloquant jusque-là.
