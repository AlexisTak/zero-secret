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

## Rego — déplacé hors du Core

Les cas des politiques de conformité plateforme vivent désormais dans
[`extensions/policy-platform/tests/`](../../extensions/policy-platform/tests/), avec les
politiques qu'ils couvrent. Exécution : `make test-extensions`.

Ils ne font plus partie de `make test`, qui couvre le périmètre Core : ces politiques ne
participent à aucune décision d'accès.

Chaque cas construit son entrée **en entier dans le cas lui-même** (aucune donnée partagée, donc
aucun fichier JSON de fixture — voir l'avertissement ci-dessus, qui rendrait ces données
exécutables comme des cas Cedar). Même intention que pour Cedar : un cas de refus doit pouvoir
être relu et rejoué isolément.

Les assertions portent sur l'**ensemble exact** des identifiants de règle déclenchés, jamais sur
une simple appartenance : un cas qui vérifierait `"PLT-001" in ids` passerait aussi si la
politique déclenchait cinq autres règles au passage. On prouve ce qui est refusé *et* ce qui ne
l'est pas.

### Couverture des six catégories d'attaque, côté plateforme

Les mêmes catégories que ci-dessus, transposées d'un principal vers une configuration
d'infrastructure :

| Catégorie | Cas (extraits) |
|---|---|
| — (nominal) | `test_nominal_service_conforme_est_autorise`, `test_exemption_valide_leve_la_violation` |
| 1. légitime hors conditions | `test_exemption_hors_developpement_refusee`, `test_exemption_en_staging_refusee`, `test_exemption_echue_refusee` |
| 2. voisin | `test_plt002_adresse_locale_voisine_refusee`, `test_cle_de_label_voisine_ne_couvre_pas`, `test_plt004_registre_avec_port_sans_etiquette_refuse` |
| 3. escalade par combinaison | `test_exemption_ne_leve_jamais_un_secret_en_dur`, `test_exemption_d_un_autre_service_ne_couvre_pas`, `test_plt003_secret_deplace_en_ligne_de_commande_refuse`, `test_plt001_socket_moteur_conteneurs_refuse` |
| 4. entrée ambiguë ou partielle | `test_plt000_port_numerique_refuse`, `test_plt000_contexte_absent_refuse_un_service_conforme`, `test_justification_a_deux_dates_refusee`, `test_plt004_empreinte_sha256_tronquee_refusee` |
| 5. ressource proche hors périmètre | `test_plt003_chemin_de_fichier_en_argument_conforme`, `test_cle_de_label_sans_prefixe_ne_couvre_pas` |
| 6. dépassement de durée de vie | `test_exemption_au_dela_de_la_borne_refusee`, `test_exemption_perpetuelle_refusee`, `test_exemption_a_la_borne_de_366_jours_acceptee` |

La catégorie 6 est instanciée sur la **durée de vie d'une exemption** : le plafond (366 jours,
`max_exemption_days`) est exprimé dans la politique et jamais dans l'outil appelant, et la date
d'évaluation arrive en entrée (`input.context.evaluated_at`) pour que l'évaluation reste
rejouable hors ligne — même contrainte que `context.requested_at` côté Cedar.

### Le cas qui fige l'état réel

`test_compose_dev_reel_ecart_constate` transcrit `deploy/compose.dev.yml` tel qu'il est et
affirme l'ensemble **exact** de ses non-conformités actuelles (4 au 2026-08-25). Il est censé
être fragile : toute règle ajoutée ou toute correction de `deploy/` le fait échouer et oblige à
reconstater l'écart au lieu de le découvrir en CI.

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
