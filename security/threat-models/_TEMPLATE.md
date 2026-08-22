# Modèle de menaces — <composant>

**Dernière révision** : AAAA-MM-JJ — **Déclencheur** : <évolution d'architecture, pas une date fixe>

## Périmètre

Ce que fait ce composant, ce qu'il ne fait pas. Les frontières de confiance qu'il traverse.

## Actifs

Ce qui a de la valeur pour un attaquant ici : matériel cryptographique, capacité de décision,
capacité d'émission, intégrité du journal, disponibilité.

## Entrées non fiables

| Entrée | Origine | Analyseur | Couverte par fuzzing ? |
|---|---|---|---|
| | | | |

Toute entrée non fiable sans analyseur identifié est un angle mort. Toute entrée non fuzzée est
une dette à inscrire au backlog, pas une case à laisser vide.

## STRIDE

Les six catégories sont obligatoires. « Non applicable car… » est une réponse valide ; un tiret
ne l'est pas.

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | | | | | |
| **T**ampering | | | | | |
| **R**epudiation | | | | | |
| **I**nformation Disclosure | | | | | |
| **D**enial of Service | | | | | |
| **E**levation of Privilege | | | | | |

Un risque sans risque résiduel écrit est un risque mal analysé. Le risque résiduel est
l'information la plus utile de ce tableau : c'est ce qu'un auditeur cherchera en premier.

## LINDDUN — volet vie privée

À renseigner si le composant traite une donnée personnelle. Rappel : le système ne traite aucune
donnée biométrique côté serveur. Si cette propriété est remise en cause ici, c'est un signalement
immédiat et une mise à jour de l'analyse d'impact.

## Scénarios d'attaque testés

Référencer les tests de `tests/adversarial/` qui couvrent ces menaces. Une menace identifiée sans
test associé reste théorique.

| Menace | Test | Statut |
|---|---|---|
| | | |

## Hypothèses de sécurité

Ce sur quoi ce composant compte sans le vérifier lui-même (HSM intègre, horloge synchronisée,
mTLS établi en amont, politiques signées valides). Une hypothèse non écrite est une hypothèse
qui sera violée sans que personne ne s'en aperçoive.
