# policies/ — politiques d'accès et de plateforme

Ce dossier contient du code de sécurité, pas de la configuration. Il se teste, se versionne et
se justifie comme du code. Ces instructions priment sur le `CLAUDE.md` racine ici.

```
access/      Cedar — décisions d'accès évaluées par le PDP
platform/    Rego — admission, conformité d'infrastructure
detection/   Sigma — règles de détection livrées avec le produit
tests/       cas nominaux ET cas d'attaque attendus en refus
```

## Règles

- **Une politique sans cas de refus attendu n'est pas terminée.** Écris les tests avant la règle.
- **Refus par défaut.** Une modification ne doit jamais élargir un accès par effet de bord.
  En cas de doute sur la portée, restreins et documente.
- **Le plafond de durée de vie du credential est exprimé ici**, jamais laissé au code appelant.
- **Aucune dépendance externe.** Le contexte arrive en entrée : le PDP doit rester déterministe
  et rejouable hors ligne à partir du seul journal d'audit.
- **Schéma d'abord.** Toute entité ou action nouvelle est déclarée dans `contracts/cedar/` avant
  usage. Un type flou ouvre la porte à la confusion de requête — c'est une menace identifiée au
  modèle STRIDE du projet.
- **En-tête obligatoire** sur chaque politique : exigence couverte, référence ADR, date de
  réexamen.
- **Ne supprime jamais un cas de test de refus** pour faire passer une politique. Si un cas de
  refus devient invalide, c'est un changement d'exigence : il passe par un ADR.

## Cas d'attaque à couvrir systématiquement

Pour chaque règle ajoutée, teste au minimum :

1. le principal légitime hors conditions (heure, réseau, posture du poste, ticket absent) ;
2. un principal voisin qui ne doit pas bénéficier de la règle ;
3. l'escalade par combinaison de deux règles légitimes prises isolément ;
4. la requête ambiguë ou partiellement remplie ;
5. la ressource proche mais hors périmètre (préfixe commun, nom voisin) ;
6. le dépassement de la durée de vie maximale.

## Contrepartie en détection

Toute politique d'accès sensible doit avoir sa règle Sigma dans `detection/` : que verrait-on
dans le SIEM si cette règle était contournée ou abusée ? Si tu ne peux pas répondre, la
politique n'est pas terminée.

## Vérification

`make test` exécute `cedar test`, `opa test` et le harnais de rejeu. Une politique modifiée sans
exécution du rejeu sur le corpus historique est un changement non vérifié.
