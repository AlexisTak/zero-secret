# policies/

Politiques et leurs tests — cas nominaux **et** cas d'attaque, dans la même contribution que la
politique. Voir [policies/CLAUDE.md](CLAUDE.md) pour les règles locales (prioritaires ici).

```
policies/
  access/     CORE      Cedar — décisions d'accès (policy-engine), chemin critique
  detection/  OPTIONAL  Sigma — contenu de détection pour un SIEM EXTERNE
  tests/      cas nominaux et cas d'attaque de access/
```

La conformité plateforme (Rego/OPA) a quitté ce dossier : elle vit dans
[`extensions/policy-platform/`](../extensions/policy-platform/), au statut EXPERIMENTAL. Aucun
composant de `apps/` ni de `crates/` ne l'évalue, et son retrait ne changerait rien au
comportement du MVP. **Cedar reste le seul moteur d'autorisation.**

Vérification du corpus Cedar : `bash tools/cedar-test.sh` (appelé par `make test`) — validation
stricte contre `contracts/cedar/schema.cedarschema.json` puis exécution des cas de
`policies/tests/`. Nécessite le CLI Cedar : `cargo install cedar-policy-cli --locked`.

Un test qui ne vérifie que le chemin heureux est un test incomplet sur ce projet. Assouplir une
politique dans `access/` ou supprimer un cas de test de refus exige une validation explicite.
