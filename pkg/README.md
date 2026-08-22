# pkg/

Bibliothèques Go internes, partagées entre les composants Go de `apps/`.

| Package | Rôle |
|---|---|
| `zstelemetry` | Instrumentation OpenTelemetry/Prometheus commune — clients, traces, métriques |

Erreurs enveloppées avec contexte, `context.Context` propagé partout, aucune variable globale
mutable, timeouts explicites sur tout appel sortant (voir [CLAUDE.md](../CLAUDE.md)).
