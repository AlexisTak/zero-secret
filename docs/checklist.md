# Reste à faire — état au 2026-08-22

Snapshot, pas un journal vivant : à relire (pas à faire confiance aveuglément) si consulté plus
tard. Croiser avec `docs/backlog.md` (source de vérité des critères d'acceptation) et `git log`
avant d'agir dessus.

## PR ouvertes, à merger dans l'ordre

- [ ] [#10](https://github.com/Biscuits-ia/biscuits-shield/pull/10) — L1.2a/b : authentification WebAuthn + détection de clonage (ADR-008)
- [ ] [#11](https://github.com/Biscuits-ia/biscuits-shield/pull/11) — L1.3 : révocation + récupération à quorum (ADR-009), empilée sur #10
- [ ] [#12](https://github.com/Biscuits-ia/biscuits-shield/pull/12) — L1.4a : construction + chaînage des événements d'audit (ADR-010), empilée sur #11 mais sans dépendance fonctionnelle réelle (peut être rebasée sur `main`)

## Prérequis partagé — H1 : intégration HSM réelle

Bloque **deux** lots à la fois, à faire une seule fois :

- [ ] `crates/zs-hsm` : intégration PKCS#11/SoftHSM2 réelle (aujourd'hui un stub vide). Conçue
      avec deux consommateurs en tête (`identity-assertion` et `audit-seal`, ce dernier étant
      l'opération HSM la plus fréquente du système).
- [ ] Analyse de dépendance `cryptoki` (ou équivalent) : licence, maintenance, historique CVE,
      couverture PKCS#11 v3.2 (ML-DSA/ML-KEM) — déterminant pour la disponibilité de la cible v2.
- [ ] Sémantique de perte de session HSM : refus d'émettre, jamais de repli logiciel (même en dev).
- [ ] Initialiser `security/crypto-inventory/` (CBOM) — actuellement vide, invariant 9 de
      `zs-crypto/CLAUDE.md` non outillé (rien ne fait échouer un build qui ajouterait une suite
      sans entrée CBOM).
- [ ] Mesurer (pas estimer) la latence d'un aller-retour PKCS#11 par signature — chiffre décisif
      pour le modèle « une signature par événement d'audit » retenu (ADR-010).
- [ ] ADR dédié à H1 avant de coder (référent-crypto + validation humaine).

## Débloqués par H1

- [ ] **L1.2c** — `identity-assertion/v1` scellée réellement (ADR-007/008). Format à N
      composantes de signature dès `v1` pour que l'hybridation `v2` ne casse pas le format (R8).
- [ ] **L1.4b** — `audit-seal/v1` scellée réellement, vecteurs de chaînage figés avec une vraie
      signature, ancrage périodique (`event_type: "audit.chain_verified"`, déjà réservé au
      contrat) pour détecter une troncature en queue de chaîne (limite du chaînage seul, non
      couverte par L1.4a).

## Dettes signalées explicitement (backlog L0/L1), pas des oublis

- [ ] Branche `main` protégée sur GitHub — bloqué par le plan GitHub Free sur dépôt privé (403 sur
      `branches/main/protection`). Nécessite un changement de plan ou de rendre le dépôt public —
      décision humaine, sans lien avec la CI Jenkins.
- [ ] `make up && make test-e2e` jamais exécuté de bout en bout dans une session Claude Code
      (Podman/Docker bloqués par la politique de permission) — écrit et relu avec soin, mais le
      premier run réel reste à faire par un humain ou en CI/Jenkins.
- [ ] Stockage DB réel des challenges/compteurs de signature (`identity.challenges`,
      `identity.authenticators`) — schéma prêt (migrations 003/004), aucun pilote Postgres async
      câblé dans `identity-provider` (n'existe pas encore comme serveur HTTP).
- [ ] Fuzzing de l'analyseur d'attestation jamais exécuté sur ce poste (libFuzzer/ASan absent sous
      Windows) — code compile (`cargo +nightly check`), à lancer en CI/Jenkins (Linux) une fois
      le pipeline Jenkins fonctionnel de bout en bout.
- [ ] Oracle différentiel de test contre `webauthn-rs` (recommandé par `referent-crypto` en L1.1)
      — reporté, aucun test différentiel écrit à ce jour.
- [ ] Ports de stockage posés en traits seuls, jamais implémentés : `ChallengeStore`,
      `SignCounterStore` (zs-webauthn), `AuditChainStore`, `AuditSink` (zs-audit) — attendent
      `identity-provider` comme serveur réel, qui n'existe pas encore.
- [ ] Récupération « à froid » (principal sans aucun authentificateur disponible) — non couverte
      par L1.3 (ADR-009), nécessiterait un mécanisme distinct si le besoin se confirme.
- [ ] Liaison cryptographique entre N approbations de récupération et une demande précise
      (ADR-009) — responsabilité de l'appelant (`identity-provider`), pas encore construit.

## Jenkins / CI

- [ ] Vérifier que le build Jenkins tourne bien de bout en bout maintenant que le pipeline
      protoc/libprotobuf-dev est corrigé (PR #8, #9 mergées) — dernier statut connu : build
      relancé après merge de #9, résultat pas revérifié depuis dans cette session.
- [ ] Le fuzzing (ci-dessus) et `make test-e2e` (Podman) dépendent tous deux d'un Jenkins Linux
      fonctionnel pour être exécutés pour de vrai.

## Hors périmètre de ce fichier

- `identity-provider` comme serveur HTTP réel (WebAuthn ceremonies, DB, sessions) n'existe pas
  encore — toutes les cérémonies vérifiées à ce jour sont des bibliothèques (`zs-webauthn`,
  `zs-audit`), pas un service exposé.
- Lots L2 et suivants : non détaillés ici, voir `docs/plan-dev.pdf` — ce fichier ne couvre que
  L0 (fait) et L1 (en cours).
