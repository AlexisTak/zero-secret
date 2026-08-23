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
divergera silencieusement. Compatibilité ascendante vérifiée en CI (`buf breaking` pour les
proto, stage `contrats (buf lint + breaking)` du `Jenkinsfile` — voir ADR-005).

**Génération** : `buf.yaml`/`buf.gen.yaml` pilotent le lint et la génération Go (`pkg/gen/`,
committé). Le Rust (`crates/zs-policy`, `crates/zs-identity`) n'est **pas** généré par `buf` :
chaque `build.rs` appelle `tonic-prost-build` directement sur son `.proto` à la compilation,
sortie non committée — voir [ADR-004](../docs/adr/ADR-004-generation-code-rust-proto.md) pour la
raison (incompatibilité constatée entre `protoc-gen-prost`/`protoc-gen-tonic` séparés).

`proto/` porte aujourd'hui deux contrats de service : `policy/v1/decision.proto` (PDP,
`policy-engine`) et `identity/v1/assertion_verification.proto` (vérification d'assertion,
`identity-provider`, H3 — voir [ADR-016](../docs/adr/ADR-016-service-verification-assertion.md)).
