# ADR-002 — OpenBao comme gestionnaire de secrets

**Statut** : accepté
**Date** : 2026-08-22
**Décideurs** : responsable technique

## Contexte

Le système a besoin d'un gestionnaire de secrets pour générer des credentials dynamiques
(rôles PostgreSQL, certificats, tokens), les faire expirer automatiquement et les révoquer.
Écrire ce composant serait une faute : c'est un logiciel de sécurité mature, disponible, audité.

Le projet est porté par une association loi 1901 qui propose son architecture à des acteurs
publics et s'engage sur la réversibilité (P8) et l'absence de verrou technologique. La licence et
la gouvernance de la brique retenue ne sont donc pas un détail juridique : ce sont des propriétés
techniques du dossier.

## Options envisagées

1. **HashiCorp Vault** — le plus mature, la plus longue expérience opérationnelle, offre
   commerciale et réplication multi-site en édition Enterprise. Inconvénient : licence BUSL-1.1,
   non approuvée OSI, produit IBM depuis l'acquisition. Un acteur public exigeant de l'open source
   au sens OSI, ou une association revendiquant la neutralité, se retrouve en porte-à-faux.
2. **OpenBao** — fork de Vault sous MPL-2.0, gouverné par la Linux Foundation au sein de l'OpenSSF,
   compatible API avec Vault. Espaces de noms multi-tenants inclus dans le cœur open source.
   Inconvénient : écosystème plus jeune, pas de réplication de reprise après sinistre intégrée,
   support commercial assuré par des tiers plutôt que par un éditeur unique.
3. **Implémentation interne** — écartée d'emblée. Écrire un gestionnaire de secrets, c'est écrire
   la partie du système la plus difficile à auditer, pour un gain nul.

## Décision

**Option 2 — OpenBao**, en conservant la compatibilité API avec Vault comme propriété de sortie.

Justification : la gouvernance vendor-neutral et la licence approuvée OSI sont la condition
concrète de la réversibilité que le projet met en avant. La compatibilité d'API rend la bascule
vers Vault, ou l'inverse, essentiellement une modification de configuration — ce qui neutralise
le risque de mauvais pari.

Tout accès à OpenBao passe exclusivement par `credential-issuer`. Aucun autre composant ne connaît
son adresse ni ne détient de jeton pour lui.

Applique P4 (standards ouverts), P8 (réversibilité), P10 (simplicité auditée).

## Conséquences

**Positives** — pas de dépendance à une décision unilatérale de licence ; argument défendable
devant un acheteur public ; moteurs de secrets dynamiques PostgreSQL, PKI et SSH disponibles
nativement ; migration vers Vault possible si un partenaire l'exige.

**Négatives** — la réplication de reprise après sinistre n'est pas fournie et devra être traitée
par sauvegarde et procédure documentée dans le lot L6 ; le support repose sur la communauté et des
prestataires tiers ; l'écosystème d'intégrations est moins fourni que celui de Vault.

**Surface d'attaque** — OpenBao devient une cible de premier rang. Descellement adossé au HSM,
politiques ACL strictes, journal d'audit propre exporté vers le SIEM, aucune exposition réseau
hors du `credential-issuer`.

## Critère de réexamen

- Si un partenaire public impose formellement Vault Enterprise, la bascule est une modification
  de configuration : réexaminer sans réécriture.
- Réexaminer si la réplication DR n'est toujours pas disponible au moment d'aborder le lot L6.
