# ADR-033 — GitHub Actions remplace Jenkins pour la CI

**Statut** : accepté
**Date** : 2026-08-24
**Décideurs** : responsable technique
**Remplace** : ADR-005 (fichier retiré du dépôt)

## Contexte

ADR-005 avait basculé la CI de GitHub Actions vers une instance Jenkins existante, avec deux
dérogations documentées et encadrées : exécuteurs Docker jetables (au lieu de l'éphémérité
native des exécuteurs GitHub-hosted) et une clé de signature `cosign` stockée dans le Jenkins
Credentials Store (dérogation explicite à la règle absolue #1, en attendant une fédération OIDC
que l'instance Jenkins ne fournissait pas nativement).

Décision de l'utilisateur : l'instance Jenkins n'est plus utilisée. Retour à GitHub Actions,
qui était déjà l'implémentation originale du backlog L0.4 (`.github/workflows/ci.yml`,
`contracts.yml`, PR #3) avant la bascule d'ADR-005.

## Décision

**Restauration des workflows GitHub Actions**, mis à jour pour refléter l'état actuel du dépôt
(les deux fichiers historiques dataient de L0.4, avant l'existence d'`audit-sealer` en Rust et
de `console-web` en TypeScript) :

- `.github/workflows/ci.yml` : mêmes étapes qu'ADR-005 décrivait pour Jenkins (format → lint →
  détection de secrets → build → tests → tests d'architecture → analyse de dépendances → SBOM →
  CBOM → build reproductible informatif → signature/attestation), plus un job `console-web`
  (`npm ci && npm run build && node --test`) qui n'existait pas encore à l'écriture du fichier
  original. `identity-provider`/`policy-engine`/`audit-sealer` (les trois binaires Rust
  déployables) sont désormais tous les trois construits et attestés — `audit-sealer` n'existait
  pas non plus lors de la première version de ce fichier.
- `.github/workflows/contracts.yml` : restauré sans changement, toujours valide (lint/breaking
  `buf`, `pkg/gen` à jour).
- `Jenkinsfile` supprimé.

**Les deux dérogations d'ADR-005 disparaissent, pas seulement se déplacent** :

1. **Exécuteurs jetables** : redevient natif (exécuteurs GitHub-hosted, détruits après chaque
   job), sans avoir besoin de reconstruire l'éphémérité via des conteneurs Docker.
2. **Secret de signature durable** : redevient inutile. `actions/attest-build-provenance@v1`
   signe via OIDC keyless (Sigstore/Fulcio), sans aucune clé stockée dans le dépôt ni dans un
   coffre externe. La dérogation à la règle absolue #1 que portait ADR-005 (clé `cosign` dans le
   Jenkins Credentials Store, rotation à 90 jours) **n'a plus lieu d'être** — elle n'est pas
   remplacée par une dérogation équivalente côté GitHub Actions, elle est supprimée.

**Portée non touchée** : le job `attest`, le stage `build reproductible (informatif)` et sa
limite déjà documentée (non-déterminisme connu de `cargo build --release` sans configuration
dédiée), et le contenu des autres jobs restent identiques à ce qu'ADR-005 avait déjà validé pour
Jenkins — seule la plateforme d'exécution change.

## Conséquences

**Positives**
- Suppression nette d'une dérogation à la règle absolue #1 (secret de signature durable), sans
  nouvelle dérogation en échange.
- Suppression de la dépendance à une instance Jenkins auto-hébergée à maintenir, patcher,
  superviser.
- `console-web` (TypeScript) et `audit-sealer` (Rust) entrent dans la CI pour la première fois —
  ils n'étaient couverts par aucune vérification automatisée depuis leur introduction (session
  précédente), un trou de couverture comblé au passage, pas seulement une migration de
  plateforme.

**Négatives — assumées**
- Aucune régression identifiée : les deux dérogations d'ADR-005 étaient déjà documentées comme
  temporaires (« en attendant une fédération d'identité », « coût et délai de mise en place non
  négligeables pour un lot L0 »), leur suppression est la résorption d'une dette assumée, pas la
  création d'une nouvelle.
- Le job `reproducible-build` reste `continue-on-error: true`, limite héritée et déjà documentée
  par ADR-005 — non résolue par ce changement de plateforme, hors périmètre ici.
- `branches/main/protection` (backlog L0.4, débloqué séparément le 2026-08-24) ne référence pas
  encore de `required_status_checks` — GitHub Actions publie des status checks nativement,
  contrairement à l'instance Jenkins qui n'en publiait aucun (`commits/main/status` vide,
  constaté lors du déblocage de la protection de branche). Activer `required_status_checks` sur
  les jobs de ce fichier redevient possible ; non fait dans ce lot, signalé pour un lot séparé.

## Alternatives rejetées

- **Conserver Jenkins et migrer la clé de signature vers une fédération OIDC externe.** Rejeté :
  aurait résolu la dérogation #2 sans résoudre le motif réel du changement — l'utilisateur
  n'utilise plus l'instance Jenkins elle-même, indépendamment de la qualité de sa CI.
- **Réécrire les workflows GitHub Actions de zéro plutôt que restaurer l'historique.** Rejeté :
  la version d'avant ADR-005 (commit `25e1d43~1`) était déjà correcte et couvrait l'intégralité
  du backlog L0.4 ; la restaurer et la mettre à jour pour les deux composants ajoutés depuis
  (`console-web`, `audit-sealer`) est strictement moins risqué que réécrire un pipeline de CI de
  sécurité depuis une page blanche.

## Critère de réexamen

- Si une instance Jenkins redevient nécessaire pour une raison non anticipée ici (contrainte
  d'hébergement, politique organisationnelle), rouvrir un ADR dédié plutôt que de rétablir
  ADR-005 tel quel — les dérogations qu'il documentait ne doivent pas être reproduites sans
  réexamen.
- Dès qu'un nouvel `apps/` déployable est ajouté au dépôt (ex. `audit-anchor`, ADR-031), étendre
  la liste des binaires construits/attestés dans le job `attest` et, le cas échéant,
  `reproducible-build` — même discipline que l'ajout d'`audit-sealer`/`console-web` ici.
