---
description: Crée un nouveau composant (app ou crate) conforme à la structure et aux règles du projet
argument-hint: [nom] [rust|go] [app|lib]
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(make:*), Bash(cargo:*), Bash(go:*)
---

Crée le composant : **$ARGUMENTS**

Ne génère rien avant d'avoir répondu à ces trois questions avec l'utilisateur si elles ne sont
pas déjà tranchées :
- Quel **plan** (contrôle / données / observation) ? Cela détermine les exigences de latence,
  de disponibilité et de réplication.
- Quelle **responsabilité unique** ? Si tu ne peux pas la formuler en une phrase, le découpage
  est mauvais.
- Quelles **dépendances entrantes et sortantes** ? Rappel : aucune dépendance entre composants
  de `apps/`.

Ensuite, produis dans cet ordre :

1. **Contrat** dans `contracts/` (OpenAPI si externe, protobuf si interne) et schémas
   d'événements d'audit dans `contracts/events/`.
2. `make generate`.
3. **Modèle de menaces STRIDE** dans `security/threat-models/<nom>.md` — les six catégories,
   même si une case est « non applicable, car… ».
4. **Squelette** :
   - Rust : `#![forbid(unsafe_code)]`, erreurs typées `thiserror`, aucune `unwrap` hors tests,
     instrumentation via `zs-telemetry`, arrêt propre sur signal.
   - Go : `context.Context` propagé, timeouts explicites sur tout appel sortant, erreurs
     enveloppées, arrêt propre.
   - Dans les deux cas : santé/readiness, configuration par variables d'environnement validées
     au démarrage (échec au démarrage plutôt que comportement dégradé), identité SPIFFE et mTLS
     pour tout appel inter-composants.
5. **Tests** : squelette unitaire, un test de propriété, un cas adverse, et l'enregistrement du
   composant dans le test d'architecture qui vérifie les règles de dépendance.
6. **Déploiement** : quadlet Podman dans `deploy/quadlets/` et entrée dans `make up`.
7. **Documentation** : `README.md` du composant (responsabilité, contrat, configuration,
   runbook minimal, chemin de réversibilité).

Termine par la liste de ce qui reste à décider ou à implémenter, et rappelle qu'un ADR est
nécessaire si ce composant introduit un choix structurant.
