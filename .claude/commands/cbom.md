---
description: Vérifie et met à jour l'inventaire cryptographique (CBOM) et la trajectoire post-quantique
allowed-tools: Read, Grep, Glob, Bash(make sbom), Bash(rg:*), WebSearch
---

Audite l'inventaire cryptographique du projet.

1. **Recense l'usage réel.** Parcours `crates/zs-crypto` et relève toute suite déclarée :
   intention, version, algorithmes, tailles de clé, emplacement de stockage des clés, durée de vie.
2. **Détecte les écarts.** Cherche dans tout le dépôt les usages cryptographiques qui ne passent
   pas par la façade (imports directs, algorithmes en dur, constantes suspectes, appels PKCS#11
   hors `zs-hsm`). Tout écart est un défaut bloquant.
3. **Compare au CBOM publié** (`security/crypto-inventory/`). Signale toute entrée manquante,
   obsolète ou incohérente.
4. **Évalue la trajectoire post-quantique.** Pour chaque suite :
   - est-elle purement pré-quantique ?
   - existe-t-il une suite hybride cible correspondante ?
   - la vérification accepte-t-elle encore les deux versions (période de recouvrement) ?
   - une signature hybride est-elle rejetée si **une seule** composante est valide ?
   Cibles : `X25519 + ML-KEM-768`, `ECDSA P-256 + ML-DSA-65`.
5. **Vérifie la doctrine en vigueur** par recherche web — les positions ANSSI et NIST sur la
   migration post-quantique évoluent, et le plan de développement date du 22/08/2026. Signale
   tout écart entre la doctrine actuelle et les choix du projet, avec la source et sa date.
6. **Régénère** le CBOM via `make sbom` et présente le diff.

Sortie attendue :
- tableau des suites : intention, version, algorithmes, statut PQC, échéance ;
- liste des écarts bloquants ;
- liste des actions à mener, ordonnées par échéance réglementaire ;
- veille : ce qui a changé depuis la dernière revue, avec sources datées.

Rappel de contexte : l'ANSSI cesse en 2027 d'accepter en qualification les produits sans
composante post-quantique. Une suite non hybridée à cette échéance est un risque d'éligibilité,
pas un détail d'implémentation.
