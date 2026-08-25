# ADR-034 — Crate `zs-replay` : rejeu hors ligne des décisions archivées

**Statut** : proposé
**Date** : 2026-08-25
**Décideurs** : responsable technique, porteur du projet — brouillon de scope produit par
instruction outillée, à relire avant tout travail d'implémentation. Aucune ligne de code
n'accompagne ce document.

## Note méthodologique

`docs/plan_dev.pdf` (référencé `docs/plan-dev.pdf` par le `CLAUDE.md` racine — nom de fichier
réellement présent avec un tiret bas, pas un trait d'union, à corriger séparément) est un fichier
de 0 octet : aucun contenu à lire. Les principes P1-P10 qu'un ADR doit normalement citer
explicitement (gabarit `/adr`) ne sont donc pas vérifiables depuis cette source. Aucun des 33 ADR
existants du dépôt ne les cite non plus — la pratique réelle établie est de référencer les règles
absolues du `CLAUDE.md`, les identifiants `R`/`L` du `docs/backlog.md`, et des ADR antérieurs.
Ce document suit cette pratique réelle plutôt que le gabarit sur ce point précis, et signale le
fichier vide comme un défaut à corriger indépendamment de ce sujet.

## Contexte

`make replay` (`Makefile`) invoque `cargo run -p zs-replay -- --from $(FROM) --to $(TO)`, mais
aucun crate `zs-replay` n'existe dans le workspace. La cible échouait sur une erreur de crate
manquant ; elle a été neutralisée avec un message explicite en attendant cet ADR (audit du dépôt,
2026-08-24, §5.4).

Le critère d'acceptation de L2.2 (`docs/backlog.md:415-419`) pose déjà l'exigence : « rejeu hors
ligne d'une décision archivée produit exactement le même `effect`/`decision_hash` », et précise
le mécanisme visé : « un rejeu relance ce même binaire déterministe contre les fichiers du commit
historique correspondant » (`docs/backlog.md:430-431`). `Pdp::decide`
(`crates/zs-policy/src/pdp.rs`) est construit pour ça : synchrone, sans état, aucun appel réseau
pendant l'évaluation (règle absolue #5 du `CLAUDE.md`), tout le contexte de décision arrive en
entrée. C'est un argument de vérifiabilité central pour un produit destiné à l'audit CESTI/RSSI
(`CLAUDE.md`, en-tête) — correct en théorie, mais aujourd'hui invérifiable en pratique faute
d'outil.

Ce que le journal d'audit contient réellement pour une décision (objet `decision` de
`contracts/events/audit-event.schema.json`) : `request_id`, `decision_hash`, `policy_version`,
`reasons`, éventuellement `granted_ttl_seconds`. Ce qu'il ne contient **pas** : la
`DecisionRequest` d'origine (`principal`, `action`, `resource`, `context` —
`contracts/proto/policy/v1/decision.proto`). Un rejeu suppose donc de se procurer cette requête
ailleurs — question non résolue par ce document, voir Q1.

## Options envisagées

1. **Bibliothèque + binaire `crates/zs-replay`, in-process.** Appelle `Pdp::decide` directement
   (pas de réseau), checkout Git temporaire du commit correspondant au `policy_version` visé, la
   `DecisionRequest` d'origine est fournie en entrée par l'opérant (fichier JSON), pas récupérée
   automatiquement. Avantages : colle exactement au mécanisme déjà décrit par L2.2, aucune
   dépendance réseau ni HSM, scope minimal, cohérent avec la règle absolue #5. Inconvénients :
   l'outil vérifie « si l'on rejoue CETTE requête, obtient-on CE hash », pas « voici
   automatiquement ce qui s'est passé sur cet incident » — la source de la requête d'origine reste
   un problème non résolu (Q1). Exige un accès à l'historique Git complet, pas garanti sur tous
   les postes (clones superficiels).

2. **Nouvel artefact `apps/zs-replay` (ou service), rejeu par gRPC.** Démarre réellement un
   `policy-engine` historique (checkout + build + run temporaire, harnais proche de
   `apps/policy-engine/tests/decide_integration.rs`) et rejoue via l'API réseau. Avantages : teste
   le chemin réellement emprunté en production, y compris l'adaptateur `apps/policy-engine` et le
   scellement HSM. Inconvénients : bien plus lourd (build + run d'un binaire historique par
   requête, exige SoftHSM2/HSM pour le scellement), disproportionné par rapport au besoin
   (vérifier `decision_hash`, pas retester l'infrastructure réseau), contredit l'esprit « rejeu
   simple, déterministe, sans infrastructure » de L2.2.

3. **Aucun crate dédié.** Documenter une procédure de rejeu manuel (checkout + script ponctuel),
   retirer `make replay` du Makefile. Avantages : aucun développement, aucun outil à maintenir qui
   pourrait diverger silencieusement du comportement réel de `Pdp`. Inconvénients : contredit
   l'argument de vérifiabilité mis en avant par le projet — un tiers qui doit réécrire son propre
   outillage pour vérifier une propriété présentée comme centrale n'est pas vraiment servi par
   « rejouable hors ligne ». Ne fait que déplacer le problème initial (`make replay` resterait
   cassé ou absent).

## Décision

Option 1 proposée : la plus proche du critère d'acceptation déjà écrit dans `docs/backlog.md`
(L2.2), la moins coûteuse à maintenir, cohérente avec la règle absolue #5 (symétrique au fait que
`policy-engine` lui-même n'a aucun appel réseau pendant l'évaluation) et avec la règle absolue #7
(`crates/`, pas `apps/` — c'est un outil de vérification, pas un service déployé).

Cette proposition ne résout pas Q1 : sans source pour la `DecisionRequest` d'origine, l'outil
démontre la propriété « rejouable » mais ne couvre pas encore le scénario d'usage complet
(instruire un incident réel a posteriori). Ce document pose le scope pour arbitrage ; il ne
tranche ni Q1 ni les questions suivantes.

## Conséquences

**Positives** : rend vérifiable une propriété aujourd'hui seulement affirmée ; donne à un
auditeur CESTI/RSSI un outil concret plutôt qu'une procédure à réinventer ; débloque `make
replay`.

**Négatives** : nouveau crate à maintenir et tester (couverture ≥ 85 % exigée sur `crates/`) ;
nouvelle surface qui doit elle-même rester dans les clous des règles absolues — lit le journal
d'audit et ré-exécute l'évaluation de politique hors du chemin de production, sans chemin
d'écriture, mais `crates/` n'a aujourd'hui aucun modèle de menaces dédié (audit du dépôt, §5.7:
angle mort déjà signalé) ; dépendance à un historique Git complet, qui doit produire un refus
explicite si l'opérant n'a qu'un clone superficiel (règle absolue #2 : refus par défaut, jamais un
faux positif silencieux) ; ne clôt pas à lui seul l'écart Q1 — livrer l'outil sans clarifier ce
point peut créer une fausse impression de capacité de rejeu complète.

**Trajectoire post-quantique** : aucun impact crypto direct. L'outil compare des `decision_hash`
déjà produits par `zs_policy`/`zs_crypto::decision_binding`, sans signer ni vérifier de signature
lui-même. Si `decision-binding` évolue vers une suite hybride, `zs-replay` en hérite sans
changement propre à lui.

**Réversibilité** : élevée. Crate isolé, aucune donnée persistante propre ; suppression sans effet
sur le reste du système si l'approche s'avère inadaptée.

## Critère de réexamen

Avant tout début d'implémentation : arbitrage de Q1 (source de la `DecisionRequest`). Si la
réponse retenue exige que le produit conserve ou expose lui-même la requête d'origine (option Q1b
ci-dessous), ce document doit être amendé avant implémentation — cela change le scope vers un
changement de contrat public (`contracts/events/audit-event.schema.json` ou équivalent), qui
exige sa propre validation explicite (`CLAUDE.md`, liste des modifications jamais faites sans
validation). Réexamen également si ADR-030 (`audit-seal/v2` hybride) change la façon dont
`decision_hash`/`policy_version` sont calculés, puisque c'est la cible de comparaison de
`zs-replay`.

## Questions ouvertes — arbitrage humain requis avant « Statut : accepté »

**Q1 — Source de la `DecisionRequest` d'origine à rejouer.** Rien ne la conserve aujourd'hui sous
une forme rejouable (le journal d'audit ne porte que le hash/`policy_version`, pas les champs
sources). (a) l'opérant la fournit manuellement, export depuis ses propres journaux applicatifs
hors périmètre du produit — scope minimal, correspond à l'Option 1 proposée. (b) le produit doit
la conserver ou l'exposer lui-même — changement de contrat public, à instruire comme un ADR
séparé si retenu.

**Q2 — Comment retrouver le corpus de politiques historique pour un `policy_version` donné ?**
`policy_version` est une empreinte (`decision-binding/v1:<hex>`), pas un tag ni un hash de commit
Git. Il faut soit une table de correspondance `policy_version` → commit, soit une recherche dans
l'historique (potentiellement coûteuse, et non garantie unique — deux commits peuvent produire la
même empreinte sur un contenu identique, ce qui est normal, pas une anomalie).

**Q3 — `crates/zs-replay` ou nouvel artefact `apps/` ?** Ce document propose `crates/`. Si Q1(b)
est retenue, l'outil ressemblerait davantage à un service interrogeant PostgreSQL et basculerait
vers `apps/`.

**Q4 — Comparaison : `decision_hash` seul, ou aussi `reasons`/`effect` explicitement ?** Plus
lisible pour un humain en cas d'échec, redondant avec le hash pour la détection elle-même.

**Q5 — Modèle de menaces.** `crates/` n'a aujourd'hui aucun modèle de menaces dédié (audit du
dépôt, §5.7). `zs-replay` lit le journal d'audit et exécute `Pdp::decide` hors du chemin de
production. Faut-il lui en écrire un propre avant acceptation, ou le couvrir dans celui de
`policy-engine` (même logique d'évaluation, même invariants) ?
