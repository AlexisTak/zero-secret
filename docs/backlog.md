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
- [ ] `contracts/proto/policy/v1/decision.proto` complété et validé (`buf lint`)
- [ ] `contracts/events/audit-event.schema.json` complété
- [ ] `make generate` produit les types Rust et Go, aucun fichier généré écrit à la main
- [ ] Vérification de compatibilité ascendante en CI (`buf breaking`)
- **Acceptation** : une suppression de champ dans le proto fait échouer la CI.

### L0.4 — Chaîne d'intégration continue
- [ ] Étapes : format → lint → détection de secrets → build → tests → tests d'architecture →
      analyse de dépendances → SBOM → CBOM → build reproductible → signature → attestation
- [ ] Exécuteurs éphémères, aucun secret durable, branche principale protégée
- **Acceptation** : un secret introduit volontairement dans une branche est bloqué avant fusion.

### L0.5 — Modèle de menaces v1
- [ ] `security/threat-models/` : un fichier par composant, les six catégories STRIDE renseignées
      (« non applicable car… » est une réponse valide, « — » ne l'est pas)
- [ ] Reprise des six scénarios d'attaque de `docs/architecture.md`
- **Acceptation** : chaque risque critique a une mesure compensatoire **et** un risque résiduel
  écrit. Un modèle sans risque résiduel est un modèle incomplet.

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
