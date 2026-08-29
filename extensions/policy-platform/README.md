# policy-platform — conformité plateforme (Rego / OPA)

**Statut : EXPERIMENTAL — hors Core MVP.**

Politiques de conformité d'infrastructure évaluées **hors du chemin critique** : durcissement des
manifestes Podman/Compose (`compose.rego`) et gestion des exemptions datées (`exemption.rego`).

## Pourquoi hors du Core

Aucun composant de `apps/` ni de `crates/` n'importe OPA ni n'évalue de Rego. Ces politiques ne
participent à aucune décision d'accès : elles vérifient des fichiers de déploiement, comme le
ferait un linter d'infrastructure. Le retrait complet de ce dossier ne change rien au
comportement du MVP.

**Le moteur d'autorisation du MVP est Cedar, et lui seul** — `policies/access/`, évalué par
`policy-engine` via `crates/zs-policy` (ADR-003). Rego ne remplace ni ne double Cedar.

## Exécution

```bash
make test-extensions     # depuis la racine du dépôt
```

ou directement :

```bash
opa test extensions/policy-platform/policies extensions/policy-platform/tests -v
```

Nécessite le CLI [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) (`make setup`
l'installe). Son absence ne bloque pas la construction du Core.

## Contenu

| Fichier | Objet |
|---|---|
| `policies/compose.rego` | Refus des manifestes de déploiement non durcis (privilèges, capacités, binds non-loopback) |
| `policies/exemption.rego` | Exemptions explicites et datées, refusées par défaut passé leur échéance |
| `tests/*_test.rego` | Cas nominaux **et** cas de refus attendus |

## Rapport au Core

```text
CORE        policies/access/*.cedar   → décision d'accès, chemin critique
EXPERIMENTAL extensions/policy-platform/ → conformité d'infrastructure, hors chemin critique
```

Voir `docs/adr/ADR-003-moteur-de-politiques.md` pour la décision d'origine, conservée telle
quelle : elle reste valide, seul le statut de la partie Rego change.
