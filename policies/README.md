# policies/

Politiques et leurs tests — cas nominaux **et** cas d'attaque, dans la même contribution que la
politique. Voir [policies/CLAUDE.md](CLAUDE.md) pour les règles locales (prioritaires ici).

```
policies/
  access/     Cedar — décisions d'accès (policy-engine)
  platform/   Rego/OPA — conformité plateforme, CI, admission
  detection/  Sigma — règles de détection SIEM livrées avec le produit
  tests/      cas nominaux et cas d'attaque pour access/ et platform/
```

Vérification du corpus Cedar : `bash tools/cedar-test.sh` (appelé par `make test`) — validation
stricte contre `contracts/cedar/schema.cedarschema.json` puis exécution des cas de
`policies/tests/`. Nécessite le CLI Cedar : `cargo install cedar-policy-cli --locked`.

Un test qui ne vérifie que le chemin heureux est un test incomplet sur ce projet. Assouplir une
politique dans `access/` ou supprimer un cas de test de refus exige une validation explicite.
