# Démarrage avec Claude Code

Guide d'amorçage. À lire une fois, puis à oublier — le contexte vit dans les fichiers, pas ici.

## 1. Mise en place

```bash
git init zero-secret && cd zero-secret
# copier le contenu de ce kit à la racine
chmod +x scripts/hooks/*.sh
git add -A && git commit -S -m "chore: socle de contexte projet"
claude
```

Puis, en session : `/permissions` pour vérifier quelle règle vient de quel fichier, et `/memory`
pour voir exactement quels fichiers d'instructions sont chargés. Si une règle ne s'applique pas,
c'est presque toujours qu'elle n'est pas chargée là où tu crois.

## 2. Comment le contexte est organisé

| Fichier | Chargé | Rôle |
|---|---|---|
| `CLAUDE.md` | à chaque session | règles courtes, non négociables, valables partout |
| `crates/zs-crypto/CLAUDE.md`, `policies/CLAUDE.md` | au travail dans ces dossiers | règles locales, prioritaires dans leur périmètre |
| `docs/architecture.md`, `docs/adr/`, `docs/backlog.md` | **à la demande** | vérité de référence, lue quand c'est utile |
| `.claude/settings.json` + `scripts/hooks/` | permanent | ce qui est **appliqué**, pas suggéré |

**Le point à ne pas confondre** : `CLAUDE.md` est du contexte, pas de la configuration. Claude le
traite comme une consigne forte, sans garantie d'exécution. Ce qui doit tenir quoi qu'il arrive
vit dans `permissions.deny` ou dans un hook `PreToolUse`. C'est pourquoi « aucun secret en dur »
et « aucun import crypto direct » sont des hooks, pas des phrases.

**Pourquoi `docs/` n'est pas importé avec `@`** : un `@import` est chargé intégralement au
démarrage de chaque session et consomme du contexte en permanence. `architecture.md` et les ADR
sont longs et rarement tous utiles en même temps. On les référence par chemin ; Claude les lit
quand la tâche l'exige. Garde `CLAUDE.md` sous ~200 lignes : au-delà, l'adhérence baisse.

## 3. Première session — vérification du socle

Prompt à coller tel quel :

> Lis `CLAUDE.md`, `docs/architecture.md` et `docs/adr/`. Puis, sans écrire une seule ligne de
> code, réponds à ces questions :
> 1. Quelles contradictions ou zones ambiguës vois-tu entre ces documents ?
> 2. Quelles informations te manquent pour implémenter la tâche L0.2 du backlog ?
> 3. Quelles règles du `CLAUDE.md` sont, selon toi, inapplicables ou invérifiables en pratique ?
>
> Ne propose aucun plan d'implémentation. Je cherche les trous dans le contexte, pas du code.

C'est la session la plus rentable du projet : elle révèle ce qui est ambigu **avant** que 3 000
lignes ne soient écrites dessus.

## 4. Deuxième session — le premier vrai code

Mode plan (`Shift+Tab`), puis :

> Tâche L0.2 du backlog : les tests d'architecture.
> Contrainte : écris d'abord les violations que ces tests doivent détecter (un composant de
> `apps/` important un autre composant de `apps/`, un import crypto hors `zs-crypto`, un fichier
> généré divergent), sous forme de fixtures. Ensuite seulement, écris les tests.
> Un test qui passe sur un dépôt sain sans avoir jamais échoué sur une violation ne prouve rien.
> Présente ton plan avant d'écrire.

Ce cadrage — écrire la violation d'abord — est la traduction concrète de la culture du projet.
Applique-le à toutes les tâches sécurité.

## 5. Rythme de session

```
Ouverture   → annoncer la tâche du backlog
Plan        → obligatoire si crypto, politiques, schéma d'audit ou contrat public
Exécution   → contrat → make generate → tests (refus d'abord) → implémentation → événement d'audit
Clôture     → /pre-pr, puis revue humaine
```

Sous-agents : `revue-securite` avant toute PR touchant l'authentification, l'autorisation,
l'émission ou l'audit. `referent-crypto` avant de toucher à `zs-crypto`. `auteur-politiques`
pour `policies/`.

Commandes : `/adr <sujet>`, `/pre-pr`, `/cbom`, `/nouveau-composant <nom> <langage> <type>`.

## 6. Entretien du contexte

- **Une règle par erreur.** Chaque fois que Claude Code fait une erreur qu'une ligne aurait
  évitée, ajoute cette ligne — et une seule. Une règle qui ne prévient aucune erreur observée est
  du bruit qui dilue les autres.
- **Les décisions vont dans un ADR**, pas dans `CLAUDE.md`. Ce dernier dit *quoi faire* ; les ADR
  disent *pourquoi*. Sans ADR, chaque session rediscute les mêmes arbitrages.
- **Le backlog se met à jour en fin de session**, pas au début de la suivante.
- **Relis `CLAUDE.md` tous les mois** : les instructions s'accumulent, certaines deviennent
  redondantes, d'autres se contredisent.
- **Ce qui est personnel** (URLs locales, préférences) va dans un import depuis ton home
  (`@~/.claude/zero-secret.md`), pas dans le dépôt.

## 7. Le piège principal

Claude Code est très bon pour produire du code plausible. Sur ce projet, le code plausible est
exactement le risque : une politique lisible mais permissive, un chemin d'erreur qui autorise,
un événement d'audit émis mais jamais vérifié.

D'où la règle qui traverse tout ce kit : **le test de refus prime sur le test nominal**. Quand tu
relis une contribution, ne demande pas « est-ce que ça marche ». Demande « qu'est-ce qui échoue,
et est-ce que je l'ai vu échouer ».
