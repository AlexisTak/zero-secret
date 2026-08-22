# ADR-003 — Cedar pour les décisions d'accès, OPA pour la plateforme

**Statut** : accepté
**Date** : 2026-08-22
**Décideurs** : responsable technique, référent politiques

## Contexte

Le PDP est le composant dont une faille logique compromettrait l'ensemble du modèle. Le modèle de
menaces identifie explicitement la **confusion de requête** comme vecteur : deux requêtes
différentes produisant le même contexte d'évaluation, ou un champ mal typé permettant à une
politique de s'appliquer à une ressource qu'elle n'était pas censée couvrir.

Le langage de politiques doit donc offrir plus qu'une expressivité : une capacité de vérification
statique et un typage des entités.

## Options envisagées

1. **OPA / Rego seul** — projet CNCF diplômé, très largement déployé et audité, écosystème
   inégalé, vivier d'expertise important. Inconvénient : Rego est non typé et son expressivité
   rend l'analyse statique difficile ; il est facile d'écrire une politique correcte à la lecture
   mais permissive à l'exécution.
2. **Cedar seul** — écrit en Rust, conçu pour l'analyse formelle, schéma d'entités typé, validation
   statique des politiques contre le schéma. Inconvénient : écosystème plus restreint, moins
   d'intégrations de plateforme, communauté plus petite.
3. **Moteur d'autorisation interne** — écarté. Écrire un moteur de politiques, c'est concentrer
   dans du code non éprouvé exactement le risque que l'architecture prétend réduire.

## Décision

**Cedar pour les décisions d'accès** (`policies/access/`, évaluées par le `policy-engine`) :
le typage du schéma et la validation statique répondent directement à la menace de confusion de
requête. Cedar étant écrit en Rust, il s'intègre au `policy-engine` sans frontière FFI ni
sérialisation supplémentaire dans le chemin critique.

**OPA / Rego pour les politiques de plateforme** (`policies/platform/` : admission, conformité
d'infrastructure), où l'écosystème et les intégrations existantes sont déterminants et où une
erreur n'accorde pas directement un accès à une ressource.

Les deux corpus sont strictement séparés. Une politique de plateforme ne peut jamais accorder un
accès applicatif, et réciproquement.

Applique P2 (refus par défaut), P4 (standards ouverts), P10 (simplicité auditée).

## Conséquences

**Positives** — les politiques d'accès sont validables statiquement contre un schéma avant même
l'exécution des tests ; l'intégration Rust évite une sérialisation dans le chemin critique, ce qui
aide à tenir la cible de 25 ms au p99 ; le schéma d'entités devient un contrat versionné dans
`contracts/cedar/`.

**Négatives** — deux langages de politiques à maîtriser et à faire relire ; risque de confusion
sur « où va cette règle », à contenir par la séparation stricte des dossiers et par
`policies/CLAUDE.md` ; moins de ressources publiques et d'exemples pour Cedar que pour Rego.

**Surface d'attaque** — le schéma d'entités devient un artefact critique : une entité mal typée
rouvre la porte à la confusion de requête. Toute évolution du schéma passe par `contracts/`
et par une revue.

## Critère de réexamen

- Si la validation statique Cedar ne détecte pas une classe d'erreur que Rego aurait détectée en
  test, réexaminer.
- Réexaminer si le maintien de deux langages de politiques génère plus d'incidents de
  cloisonnement qu'il n'en prévient.
