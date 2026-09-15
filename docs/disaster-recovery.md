# Disaster Recovery — zero-secret

```text
DR STATUS = NOT READY
```

Aucun exercice de destruction/reconstruction n'a été exécuté à ce jour. Ce document décrit la
procédure de référence et ses prérequis — il ne décrit pas un mécanisme opérationnel. `CLAUDE.md`
§10 : *« un mécanisme DR n'est considéré comme opérationnel que s'il a été testé »* et *« ne jamais
transformer une procédure théorique en garantie opérationnelle »*. `docs/architecture.md`
mentionne déjà ce statut en une ligne (« Limites assumées ») ; ce document le développe.

## Pourquoi ce n'est pas encore fait

Le prototype tourne aujourd'hui sur un seul hôte de développement (`make up`, Podman), sans
environnement de production ni exercice planifié. Écrire une procédure DR maintenant sert deux
buts : rendre explicite ce qui manque avant qu'un incident réel ne le découvre, et fournir la
checklist que le lot correspondant du backlog (référencé « lot L6 » dans
`docs/architecture.md`, pas encore détaillé dans `docs/backlog.md`) devra exécuter et chronométrer.

## Ce qui doit être vrai avant de déclarer `DR STATUS = READY`

Les huit étapes ci-dessous ont été **exécutées au moins une fois, sur une copie représentative de
l'environnement**, avec un temps mesuré à chaque étape. Une procédure lue et jugée correcte sans
être exécutée reste `NOT READY` — c'est la distinction que ce document refuse de brouiller.

## Actifs à restaurer

| Actif | Composant | Nature |
|---|---|---|
| Schéma `identity` | PostgreSQL | Identités, authentificateurs, clés publiques, compteurs de signature |
| Schéma `authz` | PostgreSQL | Politiques, affectations, approbations |
| Schéma `issuance` | PostgreSQL | Baux de credentials, états d'expiration |
| Schéma `audit` | PostgreSQL | Journal en ajout seul, chaîné et signé |
| Clé `zs-identity-assertion-v1` | HSM (PKCS#11) | Signe les assertions d'identité (ADR-012) |
| Clé `zs-audit-seal-v1` | HSM (PKCS#11) | Scelle les événements d'audit (ADR-013) |
| Clé `zs-decision-seal-v1` | HSM (PKCS#11) | Scelle les décisions du PDP (ADR-019) |
| Configuration OpenBao | OpenBao | Montages de moteurs de secrets, rôles, politiques d'émission — **pas** les credentials émis eux-mêmes, éphémères par construction |
| Politiques Cedar/Rego | Git (`policies/`) | Déjà versionnées, restauration = `git clone` |
| Contrats | Git (`contracts/`) | Idem |

Ce qui n'a délibérément **pas** besoin d'être restauré, par conception zero-secret : les
credentials émis (baux OpenBao, courts, réémis sur demande après une décision fraîche) et les
mots de passe applicatifs PostgreSQL (générés à l'exécution par `tools/migrate.sh`, jamais
persistés hors de `.env.dev`, gitignoré). Un DR qui chercherait à restaurer ces valeurs
reproduirait exactement le modèle à secrets statiques que ce projet évite — la restauration porte
sur les *mécanismes* qui réémettent des credentials, pas sur les anciens credentials eux-mêmes.

## Procédure de test de référence (huit étapes, `CLAUDE.md` §10)

### 1. Destruction

`make down` (retire les conteneurs et les volumes Postgres/SoftHSM2 de `deploy/compose.dev.yml`)
puis suppression explicite de tout volume/hôte restant (répertoire de données Postgres, répertoire
de jetons SoftHSM2) pour simuler une perte totale, pas un simple redémarrage.

**Non testé.**

### 2. Reconstruction

`make setup && make up` sur un hôte neuf (ou équivalent — VM jetable, runner CI éphémère).
Reconstruit l'infrastructure (PostgreSQL, OpenBao en mode dev, SoftHSM2, collecteur OTel) et les
six binaires applicatifs à partir du code source versionné.

**Limite connue, à instruire avant le premier exercice** : `deploy/compose.dev.yml` démarre
OpenBao en mode dev (`server -dev`), dont le stockage est **en mémoire, non persistant par
conception** — un `make down` perd déjà toute configuration OpenBao aujourd'hui, indépendamment
d'un sinistre. La reconstruction de la configuration OpenBao (moteurs, rôles) n'est donc pas
« restaurée », elle est réappliquée depuis une source versionnée qui **n'existe pas encore** dans
ce dépôt (aucun script d'initialisation OpenBao committé à ce jour) — prérequis à écrire avant le
premier exercice DR, pas seulement pour cet exercice.

**Non testé.**

### 3. Restauration

Reconnexion des composants applicatifs à l'infrastructure reconstruite : variables
d'environnement (`ZS_*_ADDR`, `ZS_HSM_MODULE`, `ZS_*_DATABASE_URL`), migrations PostgreSQL
(`tools/migrate.sh`, idempotent — rejoue uniquement ce qui manque).

**Non testé.**

### 4. Restauration des données

Restauration d'une sauvegarde PostgreSQL (`pg_dump`/`pg_restore` ou équivalent) sur les quatre
schémas. **Aucune procédure de sauvegarde PostgreSQL n'existe à ce jour dans ce dépôt** —
`deploy/` ne contient ni tâche planifiée de `pg_dump`, ni politique de rétention. C'est un
prérequis manquant, pas seulement une étape non testée.

**Non testé — prérequis (sauvegarde) manquant.**

### 5. Restauration des mécanismes cryptographiques

Restauration des trois clés HSM (`zs-identity-assertion-v1`, `zs-audit-seal-v1`,
`zs-decision-seal-v1`) dans un token neuf. **Aucune procédure de sauvegarde/export de clé n'existe
à ce jour** : `deploy/softhsm/init-token.sh` initialise un token **vide** à chaque exécution — il
ne restaure rien, il régénère un environnement de développement jetable avec de nouvelles clés.

Ceci a une conséquence de sécurité directe, pas seulement opérationnelle : si les clés HSM sont
perdues, la chaîne d'audit existante ne peut plus être **prolongée** de façon vérifiable avec la
même identité de signature — seules les clés publiques déjà distribuées (ex.
`ZS_IDP_VERIFYING_KEY_HEX`, ADR-016) permettent de **vérifier** rétroactivement les événements déjà
scellés, pas d'en produire de nouveaux sous la même autorité. Pour un HSM matériel de production,
ceci nécessiterait un mécanisme de sauvegarde/clonage de clé propre au vendeur (ex. carte à puce
M-parmi-N) — **aucun choix n'est fait à ce jour, ADR requis avant qualification.**

**Non testé — prérequis (sauvegarde de clé) manquant, décision non prise.**

### 6. Vérification d'intégrité

Après restauration : rejouer `crates/zs-audit::chain::verify_chain` sur le journal restauré pour
confirmer l'absence de rupture (`prev_hash`), et vérifier chaque signature via `zs-crypto` avec la
clé publique restaurée. `bash tests/e2e/jit_flow_demo.sh` (étape 5) exerce déjà ce mécanisme sur
des vecteurs figés — l'exécuter contre les données réellement restaurées, pas seulement contre les
vecteurs de test, est la vérification propre à cette étape.

**Non testé.**

### 7. Test d'accès

Dérouler un parcours JIT complet contre l'environnement restauré — `make demo-jit`
(`tests/e2e/jit_flow_demo.sh`) est le candidat naturel pour cette étape une fois les étapes 1 à 6
franchies : si le parcours nominal fonctionne bout en bout après restauration, l'environnement est
fonctionnellement rétabli.

**Non testé.**

### 8. Mesure du temps

Chronométrer chacune des étapes 1 à 7, isolément et cumulé (« RTO » de fait). Aucune mesure
n'existe : `DR STATUS = NOT READY` le restera tant qu'aucun chiffre n'est publié ici.

**Non mesuré.**

## Prérequis à lever avant le premier exercice réel

1. Script d'initialisation OpenBao versionné (moteurs, rôles, politiques) — actuellement inexistant.
2. Procédure de sauvegarde PostgreSQL (`pg_dump` planifié ou équivalent, politique de rétention).
3. Décision ADR sur la sauvegarde/clonage des clés HSM (dev : export SoftHSM2 s'il existe une
   voie sûre ; production : mécanisme propre au HSM matériel retenu — hors périmètre tant qu'aucun
   HSM matériel cible n'est choisi, voir backlog H1).
4. Un hôte ou runner CI jetable pour simuler une destruction réelle sans affecter le poste de
   développement principal.

## Critère de passage à `DR STATUS = READY`

Les huit étapes ci-dessus exécutées de bout en bout, sur un hôte représentatif, avec un temps
mesuré et publié dans ce document (matériel, date, durée par étape) — pas avant. Tant que cette
section n'a pas été remplacée par un résultat daté, le statut reste `NOT READY`.
