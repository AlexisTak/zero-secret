# ADR-005 — Jenkins remplace GitHub Actions pour la CI, clé de signature stockée (dérogation)

**Statut** : accepté
**Date** : 2026-08-22
**Décideurs** : responsable technique

## Contexte

Le backlog L0.4 a d'abord été implémenté sur GitHub Actions (`.github/workflows/ci.yml`,
`contracts.yml`) : exécuteurs GitHub-hosted (éphémères par construction), signature et
attestation de provenance keyless via OIDC natif (`actions/attest-build-provenance`, Sigstore
Fulcio) — aucun secret de dépôt à gérer.

Décision explicite de faire tourner la CI sur une instance Jenkins existante à la place. Deux
propriétés que GitHub Actions offrait nativement doivent être reconstruites :

1. **Exécuteurs éphémères** (règle absolue implicite du backlog L0.4) — Jenkins par défaut
   utilise des agents persistants.
2. **Aucun secret durable** (règle absolue #1 du `CLAUDE.md` racine) — la signature keyless
   OIDC de GitHub n'a pas d'équivalent prêt à l'emploi sur une instance Jenkins auto-hébergée.

## Options envisagées

**Pour les exécuteurs (1)** :
- Agents Jenkins statiques (VM permanente) — écarté, contredit directement l'exigence
  d'éphémérité, pas de discussion possible.
- Agents Docker jetables (plugin Docker Pipeline) — un conteneur par stage, détruit après.
  **Retenu.**
- Agents Kubernetes (plugin Kubernetes) — équivalent en éphémérité, mais suppose un cluster
  Kubernetes existant, non disponible actuellement (`deploy/k8s` est un dossier vide, pas un
  cluster opérationnel).

**Pour la signature (2)** :
1. **Clé de signature stockée dans le Jenkins Credentials Store** — secret durable, contredit
   la règle absolue #1 à la lettre. Simple, immédiatement opérationnel.
2. **Keyless externe** (Jenkins configuré comme fournisseur OIDC de confiance auprès de
   Sigstore/Fulcio) — respecterait la règle à la lettre, mais demande une fédération
   d'identité que l'instance Jenkins actuelle ne fournit pas nativement ; coût et délai de mise
   en place non négligeables pour un lot L0 dont l'objectif est un pipeline fonctionnel de bout
   en bout.
3. **Ne pas signer** — écarté d'emblée : contredirait le critère de passage du lot L0
   (« une contribution triviale traverse toute la chaîne et produit un artefact **signé et
   attesté** »).

## Décision

**Docker jetable** pour les exécuteurs (option retenue ci-dessus, sans ambiguïté).

**Option 1 pour la signature** : clé cosign stockée dans le Jenkins Credentials Store
(`zero-secret-cosign-key` + `zero-secret-cosign-password`). C'est une **dérogation explicite et
documentée** à la règle absolue #1, pas un contournement silencieux. Elle est encadrée :

- **Rotation** : la paire de clés est régénérée tous les 90 jours, ou immédiatement en cas de
  suspicion de compromission de l'instance Jenkins. La date de dernière rotation est consignée
  dans `security/advisories/` (à créer au premier tour de rotation).
- **Portée** : la clé ne signe que des artefacts de build et l'attestation de provenance
  (`tools/generate-provenance.sh`) — elle n'a aucun usage en dehors du stage
  `signature + attestation` du `Jenkinsfile`, exécuté uniquement sur `main`.
- **Accès** : seul le job Jenkins de ce dépôt a accès à ces identifiants (scoping natif du
  Credentials Store par Folder/Job — à vérifier lors de la configuration de l'instance).
- **Réexamen obligatoire** si l'instance Jenkins gagne une intégration OIDC vers Sigstore : ce
  cas ferait tomber la dérogation, l'option 2 deviendrait la cible.

L'attestation de provenance elle-même (`tools/generate-provenance.sh`) reproduit la forme d'un
statement in-toto/SLSA simplifié — pas une conformité complète à la spec SLSA, documentée comme
telle. Signée par la même clé cosign.

## Conséquences

**Positives** — la CI ne dépend plus de la disponibilité ou du plan tarifaire de GitHub Actions ;
réutilise une instance déjà exploitée par l'association ; cohérent avec un futur pipeline de
déploiement (CD) potentiellement sur la même instance.

**Négatives** — une clé de signature durable existe désormais dans le système, contrairement à
l'approche GitHub Actions initiale ; sa compromission permettrait de signer des artefacts
frauduleux tant qu'elle n'est pas révoquée. Deux plateformes de CI ont été construites puis
l'une abandonnée (`.github/workflows/` retiré) — coût de contexte pour un lecteur qui verrait
l'historique git, atténué par cet ADR expliquant la bascule.

**Surface d'attaque** — le Jenkins Credentials Store devient un actif critique du système :
sa compromission expose la clé de signature. À traiter avec le même sérieux qu'un HSM applicatif
dans le modèle de menaces d'un futur composant CI/CD dédié (hors périmètre actuel, cf.
« Hors périmètre, signalé » de `docs/backlog.md` L0.5 — les modèles de menaces couvrent les
composants applicatifs, pas encore l'infrastructure CI elle-même).

## Critère de réexamen

- Si l'instance Jenkins gagne une fédération OIDC compatible Sigstore : migrer vers l'option 2,
  retirer la clé stockée.
- Si la rotation à 90 jours n'est pas tenue deux fois de suite : c'est un signal que la
  dérogation coûte plus cher en discipline opérationnelle qu'elle n'en vaut la peine —
  réévaluer GitHub Actions ou une autre plateforme avec OIDC natif.
- Si un cluster Kubernetes devient disponible pour l'association : réévaluer les agents
  Kubernetes plutôt que Docker (meilleure isolation, cohérent avec `deploy/k8s`).
