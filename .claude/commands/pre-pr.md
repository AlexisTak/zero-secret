---
description: Vérifie la Definition of Done du projet avant de proposer une contribution
allowed-tools: Read, Grep, Glob, Bash(git diff:*), Bash(git status), Bash(make check), Bash(make test), Bash(make audit)
---

Passe la Definition of Done sur les modifications en cours. Lis le diff complet
(`git diff` et `git diff --staged`), pas seulement le résumé de la session.

Exécute `make check`, `make test`, puis `make audit`.

Réponds point par point avec ✅ / ❌ / ⚠️ non applicable, et une ligne de justification. Une case
cochée sans preuve est un échec.

1. Le contrat correspondant est publié dans `contracts/` et la compatibilité est vérifiée.
2. `make generate` a été relancé si un contrat a changé, et les fichiers générés sont à jour.
3. Tests unitaires **et** de propriété : cas nominal **et** au moins un cas adverse explicite.
4. Couverture : ≥ 85 % général, ≥ 95 % sur `zs-crypto`, `zs-policy`, `zs-audit`.
5. Les événements d'audit associés sont spécifiés, produits, signés, vérifiés par test.
6. Les politiques concernées ont leurs cas de refus attendus.
7. Le modèle de menaces du composant est révisé si la surface d'attaque évolue.
8. Toute opération cryptographique passe par `zs-crypto` et est déclarée au CBOM.
9. Aucun secret, clé, jeton complet ni donnée personnelle dans le code, les tests, les journaux.
10. Aucune alerte statique haute, aucune vulnérabilité critique ou haute exploitable.
11. Aucune dépendance croisée entre composants de `apps/`.
12. Aucun fichier généré modifié à la main.
13. Le comportement en cas d'indisponibilité d'une dépendance est un refus explicite.
14. Documentation et runbook à jour ; chemin de réversibilité documenté.
15. Un ADR existe si la contribution acte un choix structurant.

Termine par :
- **Verdict** : PRÊT / NON PRÊT
- **Bloquants** : liste ordonnée de ce qu'il reste à faire
- **Message de commit proposé** (conventionnel, référençant l'exigence ou l'ADR) — sans exécuter
  le commit.

Si le diff touche l'authentification, l'autorisation, l'émission de credentials ou l'audit,
lance également le sous-agent `revue-securite` et intègre ses constats au verdict.
