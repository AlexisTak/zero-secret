# Modèle de menaces — admin-api

**Dernière révision** : 2026-08-24 — **Déclencheur** : câblage sur `audit-collector`
(`quorum.operation`, ADR-028)

## Périmètre

Administration des politiques, identités et approbations. **Quorum sur les opérations
critiques.** C'est le plan de contrôle : tolère une indisponibilité brève (contrairement au
plan de données), mais toute compromission ici a un effet différé sur l'ensemble du système
(une politique modifiée n'a d'impact qu'à la prochaine évaluation, mais cet impact peut être
large et silencieux).

**Depuis ADR-028** : chaque vérification de quorum ayant au moins un porteur réellement vérifié
émet un `quorum.operation` par porteur distinct vers `audit-collector` (réseau normal, même
dette de TLS que partout ailleurs) — best-effort, une panne ou un refus métier sont journalisés
mais ne bloquent jamais la réponse HTTP. Rien n'est audité pour un refus avant vérification
(seuil sous le plancher, corps malformé) : sans identité établie, il n'y a personne à qui
attribuer l'événement.

## Actifs

- La capacité de modifier les politiques d'accès — équivalent fonctionnel à modifier le
  périmètre d'autorisation de tout le système sans passer par le PDP lui-même.
- La capacité de gérer le cycle de vie des identités (révocation, quorum de récupération) —
  détournée, elle permettrait soit de bloquer un utilisateur légitime, soit de faciliter la
  récupération frauduleuse d'un accès révoqué.
- Le mécanisme de quorum lui-même — c'est la seule protection contre un administrateur unique
  compromis initiant une opération critique seul.

## Entrées non fiables

| Entrée | Origine | Analyseur | Couverte par fuzzing ? |
|---|---|---|---|
| Requête de modification de politique | Administrateur authentifié, HTTP | Validation de schéma OpenAPI, puis validation Cedar statique avant tout déploiement | Non prévu — surface HTTP structurée |
| Requête de révocation/récupération d'identité | Administrateur ou porteur de quorum, HTTP | Vérification de quorum (plusieurs porteurs distincts requis) | Non prévu |
| Approbations multiples pour une opération de quorum | Plusieurs porteurs distincts | Vérification que chaque approbation provient d'un porteur réellement distinct, non réutilisable | À spécifier précisément — surface sensible, candidate à un test adversarial dédié plutôt qu'à du fuzzing |

## STRIDE

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | Un attaquant se fait passer pour un administrateur ou un porteur de quorum | Faible (authentification forte attendue, AAL3 cohérent avec les accès privilégiés) | Critique | Authentification WebAuthn AAL3 pour toute opération d'administration (cohérent avec `docs/architecture.md` : « authentification WebAuthn (AAL3 pour les accès privilégiés) ») | Dépend de la robustesse de l'authentification amont (`identity-provider`) — une faille là-bas se répercute intégralement ici |
| **T**ampering | Une politique est modifiée pour élargir un accès, en contournant la revue humaine | Faible à moyenne selon le processus de déploiement | Critique | Validation Cedar statique avant déploiement, revue humaine obligatoire hors bande (CODEOWNERS sur `policies/access/` au niveau du dépôt — mais une modification via `admin-api` en production est un chemin distinct du dépôt git, à sécuriser séparément) | **Angle mort structurel** : ce modèle suppose que les politiques passent par le dépôt versionné et revu, mais `admin-api` expose potentiellement un chemin de modification à chaud qui contournerait cette revue — à clarifier avant L2 : `admin-api` peut-il modifier une politique sans passage par CI/revue, ou seulement déclencher un déploiement d'une version déjà validée ? |
| **R**epudiation | Une opération d'administration critique est contestée (qui a initié la révocation ?) | Faible | Élevé (surtout pour les opérations à quorum, où l'attribution individuelle compte) | Chaque approbation de quorum et chaque modification produit un événement d'audit signé, portant l'identité de chaque porteur distinct | Si le mécanisme de quorum ne distingue pas correctement des porteurs collusoires d'un véritable quorum indépendant, la non-répudiation individuelle reste formellement correcte mais trompeuse sur la réalité du contrôle — risque organisationnel plus que technique, à documenter |
| **I**nformation Disclosure | Fuite de la configuration des politiques ou de la liste des identités administrées | Moyenne (surface d'administration, cible naturelle) | Moyen à élevé selon le contenu exposé | Contrôle d'accès strict, principe du moindre privilège sur les rôles d'administration | Les politiques elles-mêmes ne sont pas des secrets (elles sont versionnées en clair dans `policies/`) — le risque porte surtout sur les métadonnées d'identité, à traiter comme une donnée personnelle |
| **D**enial of Service | Un attaquant sature `admin-api` pour empêcher une révocation urgente | Faible à moyenne | Élevé si ça retarde une révocation critique (fenêtre d'exposition prolongée) | Le plan de contrôle tolère une indisponibilité brève selon l'architecture — mais une révocation urgente est justement le cas où cette tolérance est la plus dangereuse | Tension explicite entre « le plan de contrôle tolère l'indisponibilité » (conception) et « une révocation doit être immédiate » (backlog L1.3, délai < 5 s) — à trancher : la révocation passe-t-elle uniquement par `admin-api`, ou existe-t-il un chemin de révocation d'urgence isolé du reste du plan de contrôle ? Non tranché, risque résiduel explicite |
| **E**levation of Privilege | Un administrateur aux droits limités (ex. gestion d'identités seulement) parvient à modifier une politique d'accès | Faible si les rôles d'administration sont finement séparés | Critique | Séparation des rôles d'administration par domaine (politiques, identités, approbations) — à spécifier précisément lors de l'implémentation | Non encore implémenté ; la granularité réelle des rôles d'administration reste à définir, c'est une dette de conception explicite avant L2 |

## LINDDUN — volet vie privée

Traite des identités administrées (liste des principaux, leurs rôles, leur statut) — donnée
personnelle par nature (identifie des personnes). Pas de donnée biométrique. Une analyse
d'impact est requise avant tout déploiement traitant des utilisateurs réels, conformément à la
contrainte RGPD du `CLAUDE.md` racine — ce composant est probablement celui qui la déclenchera
en premier, étant la surface d'administration des identités.

## Scénarios d'attaque testés

| Menace | Test | Statut |
|---|---|---|
| Récupération à un seul porteur | `tests/adversarial/` — un seul porteur ne peut jamais déclencher une récupération (backlog L1.3) | Non écrit |
| Modification de politique sans revue | `tests/adversarial/` — chemin de modification à chaud testé contre le contournement de CI | Non écrit, dépend de la clarification de l'angle mort ci-dessus |
| Révocation retardée par saturation | `tests/adversarial/` — délai de révocation sous charge | Non écrit |
| Rôle d'administration limité élevant ses droits | `tests/adversarial/` — tentative de modification de politique par un rôle « identités seulement » | Non écrit |
| Quorum déclenché par un appelant anonyme (ADR-021) | `apps/admin-api/internal/httpapi/security_authorization_test.go` — en-tête absent, assertion invalide, AAL2, AAL absent, vérificateur indisponible | Écrit, passe — corrigé par ADR-035 |
| Quorum atteint sans habilitation de l'appelant | même fichier — un appelant AAL3 authentifié initie une opération sans lien démontré | Écrit, constat non bloquant — angle mort des rôles |
| Absence de limitation de débit | `apps/admin-api/internal/httpapi/security_rate_limit_test.go` — rafale de 200 requêtes | Écrit, constat non bloquant |
| Entrées malformées provoquant une fuite ou un 5xx | `apps/admin-api/internal/httpapi/security_api_test.go` — matrice de 11 cas | Écrit, passe |
| Panique du décodeur sur entrée arbitraire | `apps/admin-api/internal/httpapi/fuzz_test.go` — `make security-fuzz` | Écrit, passe |

## Menaces introduites par l'authentification de l'appelant (ADR-035)

Ce contrôle ferme le déclenchement anonyme mais crée sa propre surface, revue et traitée :

| Catégorie STRIDE | Menace | Traitement |
|---|---|---|
| Élévation de privilège | Un porteur se déclare aussi initiateur : le quorum de 2 est atteint avec un seul approbateur réellement indépendant de lui | `excludeInitiator` retire le sujet de l'initiateur des porteurs comptés avant réévaluation du seuil — `TestSecurityInitiateurNestJamaisComptePorteur` |
| Répudiation | L'événement de l'initiateur est indiscernable de celui d'un porteur : l'auditeur compte un approbateur de trop, ou la déduplication efface la trace de déclenchement | `actor.aal` et `actor.auth_method` renseignés sur le seul événement d'initiateur, tous deux refusés vides (502) — `TestSecurityEvenementInitiateurEstDistinguableDesPorteurs` |
| Répudiation | L'exclusion de l'initiateur efface du journal le fait qu'il avait aussi soumis une assertion de porteur : une campagne d'auto-approbation devient indétectable a posteriori | `context.justification` de l'événement d'initiateur porte le fait (champ existant du contrat, schéma inchangé) — `TestSecurityExclusionDeLinitiateurEstAuditee` |
| Déni de service | Corps décodé avant authentification (le seuil et le domaine en dépendent) : allocation non bornée par un anonyme, et amplification d'une requête en N appels gRPC sortants | `http.MaxBytesReader` 512 Kio, 64 assertions au plus, budget d'évaluation de 25 s (appelant puis porteurs, en série) dont 5 s pour l'appelant — `TestSecurityPorteursLentsSontBornes` |
| Répudiation | Un appelant qui consomme le budget de traitement supprime les N+1 événements d'audit d'une opération pourtant **réussie** : le levier est entre ses mains, il choisit le nombre d'assertions donc la latence cumulée | Budget d'audit propre (`delaiAudit`) et détaché par `context.WithoutCancel` — `TestSecurityAuditNestJamaisSupprimeParLeBudgetDevaluation` |
| Divulgation | La réponse recopiait `err.Error()` du module quorum : adresse d'identity-provider, code gRPC et état de santé fuitaient vers un appelant authentifié | Erreurs typées : seuil invalide → 400 générique, toute autre cause → `502 verification_des_porteurs_indisponible` |
| Usurpation | L'appelant choisit le domaine d'autorité contre lequel il est vérifié : contrôle tautologique dès qu'un identity-provider accepte plus d'un domaine | Domaine épinglé par `ZS_ADMIN_API_EXPECTED_AUTHORITY_DOMAIN`, **obligatoire au démarrage** (pas de valeur par défaut), refus 400 si le corps en propose un autre |
| Divulgation | Les contrôles de domaine et de plafond, placés avant l'authentification, laissaient un anonyme énumérer la configuration par réponse différentielle | Déplacés après `verifyCaller` ; seul `MaxBytesReader`, qui ne renvoie aucune information, protège le chemin anonyme |

Le décodeur base64 du binding généré n'est pas strict (il cascade sur quatre alphabets et ne
vérifie pas les bits de bourrage) : la canonicité de l'en-tête est donc revalidée dans
`verifyCaller` par ré-encodage et comparaison — `TestSecurityEncodageNonCanoniqueDeLassertionEstRefuse`.
Sans cela, une même assertion admettrait plusieurs chaînes d'en-tête, et tout mécanisme
indexant sur cette chaîne verrait plusieurs clés pour une seule identité.

Menace résiduelle assumée : un refus d'appelant ne produit aucun événement d'audit — une campagne
de sondage de l'endpoint reste invisible au journal. Auditer un refus supposerait d'attribuer un
événement à une identité non établie, ce que le projet refuse ailleurs (ADR-027).

## Risques acceptés

| Identifiant | Description | Depuis | Réexamen | Suivi |
|---|---|---|---|---|
| `SEC-ADMIN-API-AUTHZ-001` | L'appelant est authentifié depuis ADR-035 (assertion AAL3 vérifiée avant toute évaluation du quorum), mais son **habilitation** n'est pas vérifiée : un porteur AAL3 légitime peut initier une opération critique qui ne le concerne pas. Sévérité ramenée de HIGH à MEDIUM. OWASP API1:2023, CWE-862. | 2026-08-29 | 2026-11-29 | Verrou de non-régression vert en CI (`TestSecurityQuorumExigeUnAppelantAuthentifie`) ; la levée complète suppose de trancher la granularité des rôles d'administration |
| `SEC-ADMIN-API-RATE-001` | Aucune limitation de débit sur l'entrée HTTP non authentifiée. Sévérité MEDIUM, OWASP API4:2023, CWE-770. | 2026-08-29 | 2026-11-29 | Constat non bloquant journalisé à chaque exécution de la suite |

Ces deux entrées sont produites et vérifiées automatiquement : elles ne peuvent pas se périmer en
silence, contrairement à un commentaire dans le code. Retirer une ligne de ce tableau sans corriger
le composant fait apparaître un finding bloquant hors baseline dans le rapport agrégé.

## Intégrité de la chaîne de vérification

La suite de tests de sécurité (`tests/security/`, `make security-quick`) est elle-même un actif :
la confiance accordée aux autres contrôles dépend de sa fiabilité. Hypothèses explicites, chacune
adossée à un mécanisme :

- **Fail-closed.** Un test en échec fait échouer la cible même s'il ne produit aucun rapport — les
  codes de sortie de chaque étape sont conservés puis rejoués (`Makefile`, cible `security-quick`).
  Une chaîne qui avale les échecs pour produire un rapport est pire que pas de chaîne.
- **Décision portée par les données, pas par la mise en forme.** C'est l'agrégateur qui sort en
  code 1 lorsqu'un finding `blocking=true` subsiste, après désérialisation du champ — jamais un
  motif textuel sur le JSON, qu'un changement d'indentation neutraliserait en silence.
- **Pas de cache.** `-count=1` garantit que les tests sont réellement réexécutés : un résultat
  servi depuis le cache de `go test` n'écrit aucun rapport, et le dossier vide serait interprété
  comme « aucun finding ».
- **Écriture vérifiable.** Le dossier de rapport est résolu en remontant jusqu'à `go.work` ; une
  racine introuvable fait échouer le test au lieu d'écrire hors du dépôt.
- **Actions CI épinglées par SHA.** Les neuf références des trois workflows sont épinglées au
  condensat de commit ; un tag repointé ne peut plus modifier ce qui s'exécute. Le jeton par
  défaut est réduit à `contents: read` au niveau de `ci.yml` et `contracts.yml`.
- **Contrôle infra parsé, pas grepé.** `check_compose_dev.py` charge le YAML et refuse
  explicitement si PyYAML est absent — un motif textuel ne couvre pas les formes équivalentes
  (`- 5432:5432`, syntaxe longue, `network_mode: host`).

Menace résiduelle non couverte : rien n'empêche techniquement un contributeur de neutraliser un
test (`t.Skip`, passage de `Blocking` à `false`, retrait du job CI). Seule la revue de code le
détecte — d'où la présence des identifiants ci-dessus dans le tableau des risques acceptés, qui
rend une neutralisation visible dans le diff.

## Hypothèses de sécurité

- L'authentification WebAuthn AAL3 est appliquée à toute opération d'administration critique —
  ce composant ne redéfinit pas ce niveau, il en dépend.
- Le mécanisme de quorum garantit des porteurs réellement distincts et non colludés — hypothèse
  organisationnelle autant que technique, non vérifiable uniquement par le code.
- Les politiques déployées via `admin-api` ont, d'une manière ou d'une autre, traversé la
  validation Cedar statique — le mécanisme précis (déploiement d'une version pré-validée vs.
  modification à chaud) reste à clarifier, voir STRIDE Tampering ci-dessus.
