# ADR-001 — Langages et frontières de composants

**Statut** : accepté
**Date** : 2026-08-22
**Décideurs** : responsable technique, référent cryptographie

## Contexte

Le prototype est destiné à une revue de code indépendante et à des tests d'intrusion. Le choix
des langages conditionne autant la sécurité intrinsèque que la capacité d'un tiers à auditer le
code sans acculturation préalable.

Les publications de la CISA, de la NSA et de l'ONCD recommandent explicitement les langages à
sécurité mémoire pour les composants critiques. La classe de vulnérabilités mémoire représente
encore l'essentiel des CVE critiques sur les bases de code C/C++.

## Options envisagées

1. **Tout en Rust** — sécurité mémoire maximale, cohérence d'écosystème. Inconvénient : bibliothèques
   d'infrastructure moins matures pour l'orchestration (clients OpenBao, SPIRE, OTel) ; vitesse de
   développement moindre sur du code d'intégration sans criticité mémoire ; vivier d'auditeurs plus
   restreint que Go dans l'écosystème sécurité cloud.
2. **Tout en Go** — écosystème de sécurité cloud-native de référence, développement rapide.
   Inconvénient : absence de garantie mémoire au niveau du typage, ramasse-miettes rendant
   l'effacement du matériel sensible en mémoire non garanti, ce qui est disqualifiant pour la
   manipulation de matériel cryptographique.
3. **Rust pour les composants critiques, Go pour l'orchestration** — répartition par nature du
   risque. Inconvénient : deux chaînes de compilation, deux jeux d'outils, une frontière FFI ou
   réseau à maintenir, coût cognitif pour un contributeur unique.

## Décision

**Option 3.**

- **Rust** : `policy-engine`, `identity-provider`, tous les `crates/`. Justification : ce sont les
  composants qui manipulent du matériel cryptographique, analysent des entrées réseau non fiables
  (attestations CBOR, jetons, requêtes de politique) et doivent garantir l'effacement du matériel
  sensible. `#![forbid(unsafe_code)]` partout, sauf `zs-hsm` (FFI PKCS#11).
- **Go** : `access-broker`, `credential-issuer`, `audit-collector`, `admin-api`, tous les `pkg/`.
  Justification : Kubernetes, OpenBao, SPIRE, cert-manager, Trivy et sigstore sont écrits en Go.
  Faire auditer ou reprendre du Go dans l'écosystème sécurité est immédiat.
- **TypeScript** : `console-web` uniquement, sans logique de sécurité, budget de dépendances
  plafonné, rendu côté serveur.

La frontière entre Rust et Go est **réseau (gRPC sur mTLS)**, pas FFI. Une frontière FFI aurait
réintroduit une surface mémoire non sûre exactement là où on cherche à l'éliminer.

Applique P3 (sécurité mémoire), P7 (frontières vérifiables), P10 (simplicité auditée).

## Conséquences

**Positives** — argument de sécurité mémoire défendable devant un auditeur ; les composants
critiques bénéficient du typage le plus strict ; l'orchestration reste rapide à écrire et à faire
relire.

**Négatives** — deux chaînes d'outillage à maintenir en CI ; sérialisation gRPC entre deux
composants qui auraient pu être une seule bibliothèque, donc latence supplémentaire à mesurer ;
charge cognitive réelle pour une équipe réduite ; risque de divergence de conventions entre les
deux moitiés du dépôt, à contenir par des tests d'architecture.

**Surface d'attaque** — la frontière réseau interne devient une surface à protéger, traitée par
mTLS et identité SPIFFE.

## Critère de réexamen

- Si la latence de la frontière `access-broker` → `policy-engine` dépasse durablement 10 ms au p99,
  réévaluer la fusion des deux en un binaire Rust unique.
- Si le projet passe sous les 0,5 ETP, réévaluer la réduction à un seul langage.
