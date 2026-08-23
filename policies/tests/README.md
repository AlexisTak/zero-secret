# policies/tests/

Cas nominaux **et** cas de refus attendus. Un test qui ne vérifie que le chemin heureux est un
test incomplet ici (`policies/CLAUDE.md`).

## Cedar

`db_connect/cases.json` — format `cedar run-tests` : tableau JSON d'objets
`{name, request, entities, decision, reason, num_errors}`. Le champ `"//"` porte l'intention du
cas ; il est ignoré par le CLI et sert à la relecture.

Chaque cas est **auto-porté** : il embarque son propre jeu d'entités. C'est verbeux à dessein —
un cas de refus doit pouvoir être relu et rejoué isolément, sans reconstituer un état partagé.

Exécution : `bash tools/cedar-test.sh` (ou `make test`).

> Le script agrège `policies/tests/**/*.json`. Ne pas déposer ici de fichier JSON qui ne soit
> pas un jeu de cas Cedar (données de test OPA comprises) : il serait exécuté comme tel.

### Couverture des six catégories d'attaque imposées par `policies/CLAUDE.md`

| Catégorie | Cas |
|---|---|
| — (nominal) | `nominal-aal3-ticket-approbation-posture-fraiche` |
| 1. principal légitime hors conditions | `refus-a-principal-legitime-en-aal2`, `refus-a-aal-non-renseigne` |
| 2. principal voisin | `refus-b-principal-voisin-autre-domaine-autorite` |
| 3. escalade par combinaison | `refus-c-escalade-aal3-seul-sans-ticket-ni-approbation`, `refus-c-escalade-ticket-et-approbation-sans-aal3`, `refus-c-escalade-aal3-et-ticket-sans-approbation` |
| 4. requête ambiguë ou partielle | `refus-d-requete-partielle-ticket-vide` |
| 5. ressource proche hors périmètre | `refus-e-ressource-hors-perimetre-staging`, `refus-e-ressource-domaine-autorite-voisin` |
| 6. dépassement de durée de vie maximale | `refus-f-posture-perimee-au-dela-de-3600s`, `refus-f-posture-datee-dans-le-futur` |

La catégorie 6 est instanciée sur la **fraîcheur de posture** (`context.posture.evaluated_at`
face à `context.requested_at`), seule durée de vie que la politique elle-même borne à ce stade.
Le plafond de durée de vie du *credential* (`max_ttl` de `DecisionResponse`) est porté par les
métadonnées de la politique et appliqué par `policy-engine` — L2.2, pas ici.

### Ce que le champ `reason` prouve

`reason` liste les identifiants (`@id`) des politiques ayant déterminé la décision. Un refus
avec `reason: []` est un refus **par défaut** : aucune politique ne s'applique. Un refus avec
un `reason` non vide est un refus **explicite** par un garde-fou `forbid`. La distinction est
volontairement figée dans les cas : elle documente lequel des deux mécanismes protège chaque
scénario, et elle casse si l'on retire un garde-fou en croyant qu'un `permit` restrictif suffit.
