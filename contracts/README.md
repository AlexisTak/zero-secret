# contracts/

Source de vérité. Types et clients sont **générés** (`make generate`), jamais écrits à la main.

```
contracts/
  openapi/    OpenAPI 3.1 — API HTTP publiques (access-broker, admin-api)
  proto/      protobuf — contrats gRPC internes (ex. policy/v1/decision.proto)
  events/     JSON Schema — événements d'audit (contracts/events/)
  cedar/      schéma d'entités Cedar — policies/access/
```

Toute modification ici est suivie de `make generate`, sinon la compilation des consommateurs
divergera silencieusement. Compatibilité ascendante vérifiée en CI (`buf breaking` pour les proto).
