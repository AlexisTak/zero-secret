# zero-secret — Instructions projet

Infrastructure d'accès sans secrets statiques : identités cryptographiques (FIDO2/WebAuthn),
moteur de politiques, credentials éphémères JIT.

**Documents de référence** (lire avant toute décision d'architecture) :
- `docs/adr/` — décisions d'architecture actées
- `security/threat-models/` — modèles de menaces STRIDE par composant
- `docs/backlog.md` — exigences (`R`/`L`) et critères d'acceptation

Ce code est destiné à être audité par des tiers (RSSI, CESTI, red team). Toute contribution
doit être lisible et justifiable par quelqu'un qui n'a jamais parlé à son auteur.

---

## Règles absolues

Ces règles ne se négocient pas en session. Si une demande utilisateur les contredit, **signale
le conflit et propose une alternative** au lieu d'exécuter.

1. **Aucun secret durable.** Jamais de mot de passe, clé, token ou credential écrit dans le code,
   les tests, les fixtures, les commentaires, les fichiers `.env` ou les journaux. Les fixtures de
   test utilisent des clés générées à l'exécution.
2. **Refus par défaut.** Tout chemin d'erreur, timeout, politique absente ou entrée malformée
   produit un refus explicite. Jamais de `unwrap_or(true)`, jamais de valeur par défaut permissive,
   jamais d'autorisation en cas d'échec de vérification.
3. **Aucune primitive cryptographique écrite ici.** On compose des bibliothèques auditées, on n'en
   écrit pas. Pas de comparaison de secret non constante, pas de nonce dérivé maison, pas de KDF
   improvisée.
4. **Toute crypto passe par `crates/zs-crypto`.** Aucun autre module n'importe `ring`, `rustls`,
   `aws-lc-rs`, `p256`, `ed25519-*`, `crypto/*` (Go) ni équivalent. Le hook `no-direct-crypto`
   bloque la violation ; ne le contourne pas, ajoute l'opération à la façade.
5. **Pas d'appel réseau dans `policy-engine` pendant l'évaluation.** Le contexte arrive en entrée.
   Le PDP doit rester déterministe et rejouable hors ligne.
6. **Standards ouverts uniquement.** Aucun format ou protocole propriétaire dans le chemin de
   confiance. Toute primitive doit renvoyer à une RFC, une spec W3C/FIDO, une publication NIST ou
   un référentiel ANSSI — cite-la dans le code ou l'ADR.
7. **Un composant de `apps/` ne dépend jamais d'un autre composant de `apps/`.** Le partage passe
   par `crates/` (Rust) ou `pkg/` (Go).
8. **`contracts/` est la source de vérité.** Types et clients sont générés (`make generate`),
   jamais écrits à la main. Ne modifie jamais un fichier généré.
9. **Pas de fonctionnalité sans son événement d'audit.** L'événement est spécifié dans
   `contracts/events/`, produit, signé et couvert par un test — dans la même contribution.
10. **Pas de nouvelle dépendance sans justification.** Si une dépendance est nécessaire :
    explique pourquoi, vérifie la licence (OSI, pas de copyleft fort), l'activité de maintenance
    et l'historique de CVE. Propose, ne l'ajoute pas d'autorité.

---

## Stack

| Domaine | Techno | Où |
|---|---|---|
| Composants critiques | Rust (édition 2024) | `apps/identity-provider`, `apps/policy-engine`, `crates/` |
| Orchestration, API | Go 1.23+ | `apps/access-broker`, `apps/credential-issuer`, `apps/audit-collector`, `apps/admin-api`, `pkg/` |
| Interface | TypeScript, rendu serveur | `apps/console-web` — aucune logique de sécurité côté client |
| Secrets dynamiques | OpenBao (MPL-2.0) | via `apps/credential-issuer` uniquement |
| Identité machine | SPIFFE / SPIRE | SVID X.509 courts, mTLS entre composants |
| Politiques | Cedar (accès) + Rego/OPA (plateforme) | `policies/` |
| Persistance | PostgreSQL 17+ | 4 schémas cloisonnés : `identity`, `authz`, `issuance`, `audit` |
| HSM | PKCS#11 (SoftHSM2 en dev) | `crates/zs-hsm` uniquement |
| Observabilité | OpenTelemetry, Prometheus | via `pkg/zstelemetry` |

---

## Commandes

```bash
make setup          # dépendances, SoftHSM2, hooks git, outils
make generate       # régénère types et clients depuis contracts/  ← après toute modif de contrat
make check          # fmt + lint + tests d'architecture (rapide, à lancer souvent)
make test           # unitaires + propriété + politiques
make test-crypto    # vecteurs Wycheproof, conformité WebAuthn
make fuzz TARGET=x  # fuzzing ciblé
make audit          # cargo-audit, govulncheck, gitleaks, cargo-deny
make sbom           # SBOM CycloneDX + CBOM
make up / make down # environnement local complet (Podman)
make replay         # rejeu des décisions depuis le journal d'audit
```

Lance `make check` avant de proposer toute contribution. Lance `make generate` dès qu'un fichier
de `contracts/` change, sinon la compilation divergera silencieusement.

---

## Où écrire quoi

```
apps/          binaires déployables — 1 dossier = 1 artefact, pas de dépendance croisée
crates/        bibliothèques Rust internes (zs-crypto, zs-webauthn, zs-policy, zs-audit, zs-hsm)
pkg/           bibliothèques Go internes
contracts/     OpenAPI 3.1, protobuf, JSON Schema d'événements, schéma Cedar — SOURCE DE VÉRITÉ
policies/      Cedar, Rego, règles Sigma + leurs tests (cas nominaux ET cas d'attaque)
deploy/        OpenTofu, Ansible, quadlets Podman, manifestes k8s durcis
security/      modèles de menaces, SBOM, CBOM, attestations, advisories
tests/         e2e, conformance, charge, scénarios adverses
docs/adr/      décisions d'architecture — format imposé, voir /adr
```

Certains dossiers ont leur propre `CLAUDE.md` (notamment `crates/zs-crypto/` et `policies/`).
Il prime sur ce fichier dans son périmètre.

---

## Conventions

**Rust** — `#![forbid(unsafe_code)]` dans tous les crates sauf `zs-hsm` (FFI PKCS#11, justifié par
ADR). Pas de `unwrap()` ni `expect()` hors tests et démarrage. Erreurs typées via `thiserror`,
jamais de `Box<dyn Error>` dans une API publique. Pas de `panic!` atteignable depuis une entrée
réseau.

**Go** — erreurs enveloppées avec contexte, jamais ignorées. `context.Context` propagé partout.
Pas de variable globale mutable. Timeouts explicites sur tout appel sortant.

**Commun** — noms en anglais dans le code, commentaires et documentation en français. Commits
conventionnels signés, référençant l'exigence ou l'ADR. Les journaux ne contiennent jamais de
credential, de clé, de jeton complet ni de donnée personnelle non nécessaire.

**Tests** — chaque fonctionnalité a au moins un cas nominal et un cas adverse explicite.
Couverture ≥ 85 % sur `crates/` et `pkg/`, ≥ 95 % sur `zs-crypto`, `zs-policy`, `zs-audit`.

---

## Méthode de travail attendue

Pour toute tâche non triviale, dans cet ordre :

1. **Lire avant d'écrire.** Modèle de menaces du composant, contrat concerné, ADR existants.
2. **Proposer un plan court** et attendre validation si la tâche touche la crypto, les politiques,
   le schéma d'audit ou un contrat public.
3. **Contrat d'abord**, puis `make generate`, puis tests, puis implémentation.
4. **Écrire le cas d'attaque en même temps que le cas nominal.** Un test qui ne vérifie que le
   chemin heureux est un test incomplet sur ce projet.
5. **Spécifier et produire l'événement d'audit.**
6. **Mettre à jour** le modèle de menaces si la surface d'attaque change, le CBOM si une opération
   cryptographique est ajoutée, le runbook si l'exploitation change.
7. **Vérifier la checklist** de `/pre-pr` avant de conclure.

Quand un choix structurant est fait (langage, dépendance, protocole, modèle de données), rédige
un ADR via `/adr` plutôt que d'enfouir la justification dans un commentaire.

---

## Ce que tu ne fais jamais sans validation explicite

- Modifier `crates/zs-crypto` : changement de suite, d'algorithme, de paramètre.
- Modifier une migration déjà appliquée, ou toucher aux droits du schéma `audit`.
- Changer le format ou le chaînage d'un événement d'audit (casse la vérifiabilité de l'historique).
- Assouplir une politique dans `policies/access/` ou supprimer un cas de test de refus.
- Ajouter une dépendance, un appel réseau sortant, ou un accès à un service externe.
- Désactiver, contourner ou modifier un hook, un lint, ou une étape de CI.
- Toucher à `deploy/` sur un environnement autre que `dev`.

En cas de doute sur l'une de ces zones : décris ce que tu ferais et pourquoi, puis arrête-toi.

---

## Contexte réglementaire à ne pas perdre de vue

- **Post-quantique** : l'ANSSI cesse en 2027 d'accepter en qualification les produits sans
  composante PQC. Toute opération cryptographique ajoutée doit être déclarée au CBOM et exprimée
  comme une *suite versionnée* dans `zs-crypto`, jamais comme un algorithme en dur. Cibles
  d'hybridation : `X25519 + ML-KEM-768` (échange de clés), `ECDSA P-256 + ML-DSA-65` (signature).
- **RGPD** : le système ne traite aucune donnée biométrique côté serveur. Si une contribution
  introduit une donnée personnelle, elle doit être signalée — l'analyse d'impact doit être mise
  à jour.
- **CRA** : SBOM à chaque version, gestion documentée des vulnérabilités, divulgation coordonnée.
