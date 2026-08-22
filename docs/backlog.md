# Backlog — Lot L0 (socle) et amorce L1

Une session Claude Code = une tâche de ce fichier. Ouvrir une session sans tâche identifiée
produit du code plausible et non aligné.

Chaque tâche porte un critère d'acceptation vérifiable. « Ça marche » n'est pas un critère.

---

## L0 — Socle et gouvernance (semaines 1 à 4)

**Critère de passage du lot** : une contribution triviale traverse toute la chaîne et produit un
artefact signé et attesté.

### L0.1 — Squelette du dépôt et outillage
- [ ] Arborescence complète (`apps/`, `crates/`, `pkg/`, `contracts/`, `policies/`, `deploy/`,
      `security/`, `tests/`, `docs/`, `tools/`) avec un `README.md` par dossier de premier niveau
- [ ] Workspace Cargo et modules Go initialisés
- [ ] `Makefile` fonctionnel : toutes les cibles existent, même en no-op documenté
- [x] `.gitignore`, `SECURITY.md`, `CODEOWNERS` — pas de `LICENSE` : dépôt propriétaire, réservé
- [ ] Hooks git : format, détection de secrets, commits signés
- **Acceptation** : `make setup && make check` passe sur un dépôt fraîchement cloné.

### L0.2 — Test d'architecture
- [x] Test qui échoue si un composant de `apps/` importe un autre composant de `apps/`
- [x] Test qui échoue si un module hors `zs-crypto` / `zs-hsm` importe une bibliothèque crypto
- [x] Test qui échoue si un fichier généré diffère de ce que produirait `make generate`
- **Acceptation** : les trois tests échouent quand on introduit volontairement la violation,
  et passent une fois retirée. Écrire la violation d'abord.
  Fait : `tests/architecture/run.sh` (8/8), détecteurs dans `tools/lib/`, câblés dans
  `tools/check-arch.sh` / `make test-arch`. Le check generated-up-to-date reste no-op contre
  le vrai dépôt tant que `buf` est absent de l'environnement de dev — le mécanisme lui-même
  est prouvé par la fixture `generated-drift` (générateur injectable, sans dépendance à buf).

### L0.3 — Contrat de décision et génération
- [x] `contracts/proto/policy/v1/decision.proto` complété et validé (`buf lint`)
- [x] `contracts/events/audit-event.schema.json` complété
- [x] `make generate` produit les types Go (committés, `pkg/gen/`) ; Rust généré à la
      compilation par `crates/zs-policy/build.rs` (ADR-004, pas via buf — incompatibilité
      constatée entre protoc-gen-prost/protoc-gen-tonic sur ce poste), aucun fichier généré
      écrit à la main
- [x] Vérification de compatibilité ascendante en CI (`buf breaking`) — `.github/workflows/contracts.yml`
- **Acceptation** : une suppression de champ dans le proto fait échouer la CI. Vérifié localement
  (`tools/check-arch.sh` détecte la divergence de `pkg/gen`) ; `buf breaking` prend le relais en
  CI une fois `contracts/buf.yaml` présent sur `main`.

### L0.4 — Chaîne d'intégration continue
- [x] Étapes : format → lint → détection de secrets → build → tests → tests d'architecture →
      analyse de dépendances → SBOM → CBOM → build reproductible → signature → attestation
      (`.github/workflows/ci.yml`)
- [x] Exécuteurs éphémères (GitHub-hosted, par construction), aucun secret durable (attestation
      keyless via OIDC — `actions/attest-build-provenance`, aucune clé stockée)
- [ ] Branche principale protégée — **bloqué** : dépôt privé + plan GitHub Free renvoie 403
      sur `branches/main/protection` et sur `rulesets` (« Upgrade to GitHub Pro or make this
      repository public »). Nécessite un changement de plan GitHub (facturation — décision
      humaine) ou de rendre le dépôt public. À refaire dès que l'un des deux est tranché.
- **Acceptation** : un secret introduit volontairement dans une branche est bloqué avant fusion.
  Vérifié localement (`gitleaks detect` sur un commit de test, secret détecté, commit annulé) ;
  `gitleaks/gitleaks-action` reproduit ça en CI sur toute PR.
- **Limite constatée et assumée** : le job `reproducible-build` est informatif
  (`continue-on-error`), pas bloquant. Un `cargo build --release` identique, réexécuté à
  l'identique, produit deux binaires différents bit à bit (non-déterminisme connu de l'écosystème
  Rust sans configuration dédiée). À reprendre via un ADR si la reproductibilité devient un
  critère de qualification (ANSSI/CESTI) plutôt qu'un objectif déclaré.

### L0.5 — Modèle de menaces v1
- [x] `security/threat-models/` : un fichier par composant, les six catégories STRIDE renseignées
      (« non applicable car… » est une réponse valide, « — » ne l'est pas) — 7 fichiers, un par
      composant de `docs/architecture.md` (`identity-provider`, `policy-engine`, `access-broker`,
      `credential-issuer`, `audit-collector`, `admin-api`, `console-web`)
- [x] Reprise des six scénarios d'attaque de `docs/architecture.md` — vérifié par grep, chaque
      scénario référencé dans au moins un fichier
- **Acceptation** : chaque risque critique a une mesure compensatoire **et** un risque résiduel
  écrit. Un modèle sans risque résiduel est un modèle incomplet.
- **Hors périmètre, signalé** : pas de modèle de menaces dédié pour `crates/zs-crypto` et
  `crates/zs-hsm` (bibliothèques, pas des « composants » au sens du tableau de
  `docs/architecture.md`) — leurs risques apparaissent en creux dans les hypothèses de sécurité
  des composants qui en dépendent. À revoir avec `referent-crypto` si un modèle dédié devient
  nécessaire (probable avant qualification).
- **Angles morts explicites remontés** (à trancher avant L2, pas des oublis) :
  authentification de l'approbateur non spécifiée (`access-broker`), distinction contexte
  vérifié/déclaré dans `DecisionRequest.Context` non tranchée (`access-broker`), ordre
  audit/émission non tranché (`credential-issuer`), granularité des rôles d'administration non
  définie et chemin de modification de politique à chaud non clarifié (`admin-api`).

### L0.6 — Environnement de développement
- [ ] `make up` : PostgreSQL, OpenBao en mode dev, SoftHSM2, collecteur OTel — via Podman
- [ ] Migrations initiales : quatre schémas, rôles séparés, `UPDATE`/`DELETE` révoqués sur `audit`
- **Acceptation** : le rôle applicatif `audit_writer` échoue explicitement sur un `DELETE`.
  Le prouver par un test, pas par une lecture du fichier de migration.

---

## L1 — Noyau d'identité FIDO2 (à partir de la semaine 3)

**Critère de passage du lot** : vecteurs de conformité verts, hameçonnage simulé bloqué, fuzzing
de l'analyseur d'attestation sans incident.

### L1.1 — Enregistrement d'authentificateur
- [ ] Génération et stockage du challenge, expiration courte, usage unique
- [ ] Vérification de `origin`, `rpId`, type, et de la structure d'attestation
- [ ] Politique d'attestation configurable, refus par défaut si non satisfaite
- **Acceptation** : challenge rejoué → refus ; `origin` incorrect → refus ; attestation absente
  alors que la politique l'exige → refus. Trois tests, trois refus.

### L1.2 — Authentification et assertion
- [ ] Vérification de signature via `zs-crypto`, jamais directement
- [ ] Gestion du compteur de signature et détection de clonage
- [ ] Assertion d'identité signée portant le niveau AAL atteint et la méthode employée
- **Acceptation** : compteur régressif → alerte et refus ; assertion rejouée → refus.

### L1.3 — Cycle de vie
- [ ] Révocation d'authentificateur, effet immédiat
- [ ] Récupération à quorum (plusieurs porteurs distincts), sous scellés, systématiquement alarmante
- **Acceptation** : un seul porteur ne peut jamais déclencher une récupération. Le prouver par test.

### L1.4 — Audit du parcours
- [ ] Événements : enregistrement, révocation, tentative, succès, échec, récupération
- [ ] Chaînage et signature vérifiés par test
- **Acceptation** : aucune action du parcours ne réussit sans produire son événement — vérifié par
  un test qui compte les événements attendus, pas par relecture.

---

## Règles de session

1. Une tâche à la fois. Annoncer laquelle en ouverture de session.
2. Mode plan pour toute tâche touchant crypto, politiques, schéma d'audit ou contrat public.
3. Contrat → `make generate` → tests → implémentation → événement d'audit → documentation.
4. Écrire le test de refus avant l'implémentation. Sur ce projet, c'est le test qui compte.
5. `/pre-pr` avant de conclure. Cocher la case reste à l'humain.
