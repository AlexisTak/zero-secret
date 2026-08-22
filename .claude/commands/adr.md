---
description: Rédige une décision d'architecture (ADR) au format imposé du projet
argument-hint: [sujet de la décision]
allowed-tools: Read, Write, Glob, Grep, Bash(git log:*)
---

Rédige un ADR pour : **$ARGUMENTS**

Avant d'écrire :
1. Liste `docs/adr/` pour trouver le prochain numéro et vérifier qu'aucun ADR existant ne couvre
   ou ne contredit ce sujet. S'il en existe un, propose de le remplacer plutôt que d'en ajouter un.
2. Relis les principes P1–P10 et le chapitre 3 (cadre normatif) du plan de développement.

Crée `docs/adr/ADR-NNN-titre-en-kebab-case.md` avec exactement cette structure :

```markdown
# ADR-NNN — Titre

**Statut** : proposé
**Date** : <date du jour>
**Décideurs** : <rôles concernés>

## Contexte
Situation, contrainte, exigence normative applicable. Cite la référence
(RFC, NIST, ANSSI, W3C) plutôt que d'affirmer.

## Options envisagées
1. Option A — description, avantages, inconvénients
2. Option B — description, avantages, inconvénients
(au moins deux options réellement envisagées ; une option unique n'est pas une décision)

## Décision
Option retenue et justification, avec référence explicite aux principes P1–P10
et aux référentiels du chapitre 3.

## Conséquences
Positives, négatives, effet sur la surface d'attaque, sur la charge d'exploitation,
sur la réversibilité, sur la trajectoire post-quantique.

## Critère de réexamen
Événement ou date qui déclenchera la réévaluation.
```

Règles :
- Le statut reste **proposé**. Tu ne passes jamais un ADR en « accepté » toi-même.
- Si tu ne peux pas produire une seconde option crédible, dis-le : c'est le signe que la décision
  est en réalité une contrainte, et il faut la formuler comme telle.
- Pas de conséquence uniquement positive. Si tu n'identifies aucun inconvénient, tu n'as pas
  assez creusé.
