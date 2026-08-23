# contracts/cedar/

Schéma d'entités Cedar — contrat typé des politiques de `policies/access/`, évaluées par
`policy-engine`. Voir [ADR-003](../../docs/adr/ADR-003-moteur-de-politiques.md).

`schema.cedarschema.json` est écrit en **format JSON** et non en syntaxe humaine
`.cedarschema`, pour rester homogène avec `contracts/events/*.schema.json`. La syntaxe humaine
peut être obtenue à la lecture : `cedar translate-schema --direction json-to-cedar`.

Contrairement au reste de `contracts/`, ce fichier n'est **pas** généré : il est écrit à la main
et c'est lui la source. Il n'est consommé par aucun générateur de code aujourd'hui.

## Pourquoi un type d'entité par type de ressource métier

`Resource.attributes` de `decision.proto` est une `map<string, string>` : c'est le format de
transport, pas le modèle d'évaluation. Le traduire tel quel en un type d'entité générique
porteur d'un enregistrement ouvert rouvrirait exactement la **confusion de requête** qu'ADR-003
prétend fermer par le typage statique — deux ressources de natures différentes deviendraient
indistinguables pour le validateur.

Règle : **un type d'entité Cedar par type de ressource métier**, avec ses attributs déclarés et
typés. `policy-engine` (L2.2) est responsable de la traduction `Resource.type` → type d'entité
Cedar et de la conversion typée des `attributes` ; un `Resource.type` inconnu ou un attribut
manquant produit un refus, jamais une entité partielle.

Premier type livré : `Database` (L2.1), correspondant au verbe `db.connect`.

## Correspondance avec `policy/v1/decision.proto`

La correspondance est champ à champ. Toute divergence est un écart à justifier ici.

| `decision.proto` | Schéma Cedar | Type Cedar | Note |
|---|---|---|---|
| `Principal.subject_id` | `Principal.subject_id` | `String` | identifiant stable, non nominatif |
| `Principal.aal` (`enum AuthLevel`) | `Principal.aal` | `String` | `"AAL1"`/`"AAL2"`/`"AAL3"` |
| `Principal.auth_method` | `Principal.auth_method` | `String` | |
| `Principal.authenticated_at` | `Principal.authenticated_at` | `Long` | epoch secondes |
| `Principal.roles` | `Principal.roles` | `Set<String>` | |
| `Principal.authority_domain` | `Principal.authority_domain` | `String` | cloisonnement multi-zone |
| `Action.verb` | `Action::"db.connect"` | — | le verbe **est** l'identifiant d'action |
| `Resource.type` | type d'entité Cedar | — | `"Database"` → `ZeroSecret::Database` |
| `Resource.id` | identifiant d'entité Cedar | — | |
| `Resource.authority_domain` | `Database.authority_domain` | `String` | |
| `Resource.attributes["environment"]` | `Database.environment` | `String` | ex. `"production"`, `"staging"` |
| `Context.requested_at` | `context.requested_at` | `Long` | epoch secondes |
| `Context.source_network` | `context.source_network` | `String` | |
| `Context.posture.*` | `context.posture` | `Record` | `managed`, `disk_encrypted`, `agent_version`, `evaluated_at` |
| `Context.ticket_ref` | `context.ticket_ref` | `String` | chaîne vide = absence de ticket |
| `Context.justification` | `context.justification` | `String` | |
| `Context.approvals[]` | `context.approvals` | `Set<Record>` | `approver_id`, `approved_at` |
| `Approval.signature` | **absent** | — | voir ci-dessous |

### Écarts assumés

- **`Approval.signature` n'est pas exposé au PDP.** La signature d'approbation est vérifiée via
  `zs-crypto` **avant** l'appel à `Decide` et n'est jamais réévaluée pendant l'évaluation. La
  mettre dans le contexte donnerait à une politique les moyens de raisonner sur une signature
  qu'elle ne peut pas vérifier — une politique ne fait pas de cryptographie. Le PDP ne constate
  que la présence d'approbations déjà validées.
- **Les horodatages sont des `Long` (epoch secondes)**, pas l'extension `datetime` de Cedar :
  arithmétique de comparaison triviale, aucune dépendance à une extension dont la disponibilité
  varie selon la version du crate et du CLI. La conversion `Timestamp` → `Long` est faite par
  l'appelant ; une conversion impossible est un refus.
- **`aal` est une `String` et non un enum Cedar.** Cedar n'a pas d'enum natif portable entre
  versions ; une comparaison de chaîne exacte suffit et reste lisible dans le journal d'audit.
  Conséquence directe : `AUTH_LEVEL_UNSPECIFIED` doit être traduit en chaîne vide (ou en toute
  valeur hors `{"AAL1","AAL2","AAL3"}`) et refuse alors par comparaison exacte. Cas de test :
  `refus-a-aal-non-renseigne`.
- **Tous les attributs sont obligatoires** (`"required": true`). C'est volontaire : Cedar refuse
  une entité ou un contexte incomplet à la construction, donc une requête partiellement remplie
  échoue avant même l'évaluation des politiques. Un attribut optionnel serait une porte ouverte
  à la requête ambiguë.

## Évolution

Toute entité ou action nouvelle est déclarée **ici avant** d'être utilisée dans
`policies/access/` (`policies/CLAUDE.md`). Après modification :
`bash tools/cedar-test.sh` — la validation stricte échoue sur toute politique qui référence un
attribut non déclaré.
