# policies/

Politiques et leurs tests — cas nominaux **et** cas d'attaque, dans la même contribution que la
politique. Voir [policies/CLAUDE.md](CLAUDE.md) pour les règles locales (prioritaires ici).

```
policies/
  access/     Cedar — décisions d'accès (policy-engine)
  platform/   Rego/OPA — conformité plateforme, CI, admission
  sigma/      règles de détection SIEM
  tests/      cas nominaux et cas d'attaque pour access/ et platform/
```

Un test qui ne vérifie que le chemin heureux est un test incomplet sur ce projet. Assouplir une
politique dans `access/` ou supprimer un cas de test de refus exige une validation explicite.
