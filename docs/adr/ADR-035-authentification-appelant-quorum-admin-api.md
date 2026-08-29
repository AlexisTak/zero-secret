# ADR-035 — Authentification de l'appelant sur le quorum `admin-api`

**Statut** : accepté
**Date** : 2026-08-29
**Décideurs** : responsable technique, porteur du projet

## Contexte

ADR-021 a livré le quorum sur les opérations critiques en portée volontairement réduite, en
laissant deux angles morts explicites, hérités de `security/threat-models/admin-api.md` :
le chemin de modification à chaud des politiques, et la granularité des rôles d'administration.
Le handler HTTP portait ce constat en commentaire :

> ce composant ne sait toujours pas quelle opération critique il protège ni qui a le droit de
> l'initier

La suite de tests de sécurité Phase 1 a transformé ce commentaire en fait vérifiable.
`TestSecurityQuorumAcceptedSansVerificationDeLAppelant` a reproduit l'exploitation : un appelant
**anonyme**, sans aucune assertion, obtenait `200 / reached=true` sur
`POST /v1/critical-operations/rotation-cle-hsm-prod/quorum` en présentant deux assertions de
porteurs valides mais sans lien avec l'opération. Finding `SEC-ADMIN-API-AUTHZ-001`, sévérité
HIGH, OWASP API1:2023, CWE-862.

Le scénario d'attaque réel est étroit mais grave : un attaquant qui obtient deux assertions de
porteurs — rejeu, hameçonnage, ou simple récupération d'assertions émises pour une autre
opération — déclenche n'importe quelle opération critique **sans jamais s'authentifier**. Aucune
trace ne dit qui a déclenché, puisque personne n'a été identifié.

## Options envisagées

### A. Ne rien faire, documenter le risque

Cohérent avec la portée réduite d'ADR-021. Rejetée : la vulnérabilité est démontrée et
exploitable, et un test rouge permanent en CI se serait résolu par neutralisation du test plutôt
que par correction.

### B. Authentifier l'appelant, sans trancher l'habilitation

Exiger une assertion `identity-assertion/v1` valide de niveau AAL3, vérifiée avant toute
évaluation du quorum. Ne dit rien de « quel rôle a le droit d'initier quelle opération ».

### C. Implémenter un système de rôles d'administration

Trancherait l'angle mort complet. Rejetée : c'est précisément ce qu'ADR-021 a refusé de faire
sans instruction, au même titre qu'H2 (pas de mécanisme d'authentification inventé pour OpenBao)
et H3 (pas de distribution de clé inventée). Inventer ici une politique d'autorisation non voulue
serait plus coûteux à défaire qu'à ne pas écrire.

## Décision

**Option B.** L'appelant présente son assertion dans l'en-tête `X-Identity-Assertion`, vérifiée
via `identity.v1.AssertionVerificationService` avant tout appel à `quorum.VerifyQuorum`.

### Refus par défaut sur chaque chemin d'erreur

| Condition | Réponse |
|---|---|
| En-tête absent | `401 assertion_de_lappelant_absente` |
| `identity-provider` injoignable | `502 verification_de_lappelant_indisponible` |
| Assertion non décodable en base64 | `401 assertion_de_lappelant_malformee` |
| Assertion invalide, ou hors du domaine d'autorité configuré | `401 assertion_de_lappelant_invalide` |
| `aal != "AAL3"`, valeur vide incluse | `403 niveau_dauthentification_insuffisant` |
| Domaine proposé par le corps différent du domaine configuré | `400 domaine_dautorite_inattendu` |
| Plus de 64 assertions, ou corps au-delà de 512 Kio | `400` |

Une indisponibilité du vérificateur — panne comme dépassement de délai — est un refus, jamais un
repli permissif (règle absolue #2). Une réponse `nil` sans erreur du client gRPC est traitée de
même : la lire sans garde paniquerait sur le chemin non authentifié.

### Le sujet de l'initiateur est exclu du comptage des porteurs

Rien n'empêche un porteur de se déclarer aussi initiateur : son assertion peut figurer dans
l'en-tête **et** dans le corps. `excludeInitiator` retire donc `caller.subject_id` des porteurs
comptés, puis réévalue l'atteinte du seuil sur les porteurs restants — avant l'audit et avant la
réponse. Sans cette exclusion, un quorum de 2 serait atteint avec un seul approbateur réellement
indépendant de celui qui déclenche : la lettre du plancher `MinimumThreshold = 2` respectée, son
intention vidée.

L'exclusion vit dans la couche HTTP, jamais dans `quorum` : l'initiateur est une notion de cette
couche, et ADR-021 impose que le module ignore l'opération et les rôles.

**L'exclusion est auditée.** Filtrer avant l'audit effaçait du journal le fait que l'initiateur
avait aussi soumis une assertion de porteur : le résultat audité devenait indiscernable d'une
requête où il n'aurait rien soumis, et une campagne d'auto-approbation n'était plus détectable a
posteriori. Le champ `context.justification` de l'événement d'initiateur (champ existant du
contrat, schéma inchangé) porte donc le fait de l'exclusion.

### Le décodage base64 appartient au contrat, pas au handler

Le paramètre est déclaré `format: byte`, comme les assertions de porteurs du corps : le décodage
est fait par le binding généré, jamais par du code écrit à la main. Une première version décodait
l'en-tête manuellement derrière un `type: string` nu — la garantie vivait alors hors de la source
de vérité (règle absolue #8), et un régénérateur ou un autre client n'avait aucun signal.

Un en-tête non décodable n'atteint donc plus le handler. `writeParamError` traduit l'échec de
liaison en `401 assertion_de_lappelant_malformee` et non en `400` : c'est un refus
d'authentification, et le code de statut ne doit pas révéler *où* l'assertion a échoué.

### Le domaine d'autorité vient de la configuration

`expected_authority_domain` est fixé par `ZS_ADMIN_API_EXPECTED_AUTHORITY_DOMAIN` — **obligatoire
au démarrage, sans valeur par défaut** : un ancrage de confiance qui se replie silencieusement sur
une valeur générique n'ancre rien, et un déploiement qui oublie la variable démarrerait en croyant
le contrôle actif. Jamais déduit du corps ; un corps qui en propose un autre est refusé en `400`. Laisser l'appelant choisir le
domaine contre lequel il est vérifié rendrait le contrôle tautologique dès qu'un
`identity-provider` accepte plus d'un domaine : il suffirait de présenter des assertions d'un
domaine A pour agir sur le périmètre B.

### Bornes sur l'entrée non authentifiée

Le corps est nécessairement décodé avant la vérification de l'appelant (le seuil et le domaine
attendu en dépendent), donc les bornes doivent tenir face à un anonyme :
`http.MaxBytesReader` à 512 Kio, et au plus 64 assertions (`maxItems` au contrat, refus `400`
côté application). Chaque assertion déclenchant un appel gRPC sortant, une liste non bornée
amplifierait une requête unique en autant d'appels vers `identity-provider`.

### Budget de temps sur la requête entière

Deux échéances imbriquées : **30 s** posées en tête du handler sur `r.Context()`, et **5 s** pour
la vérification de l'appelant. Le budget global couvre ce que le seul délai de l'appelant laissait
sans échéance : jusqu'à 64 vérifications de porteurs faites en série par le module `quorum`, et
les N+1 envois d'audit. Sans lui, un vérificateur lent — ou tenu par l'attaquant, qui contrôle les
deux bouts — immobilisait un goroutine jusqu'à déconnexion du client, sur le composant même qui
porte le chemin d'une révocation d'urgence.

Le dépassement produit le même `502` qu'une panne : une lenteur indistinguable d'une panne est
traitée comme une panne (règle absolue #2).

### `quorum` reste agnostique

La vérification vit dans la couche HTTP, jamais dans le module `quorum`, qui continue de ne
connaître ni l'opération protégée ni les rôles — conception étroite maintenue par ADR-021, et
seule garantie que le module reste réutilisable quel que soit le futur système de rôles. Même
découpage que `access-broker`, où l'assertion du demandeur est vérifiée dans `httpapi` avant
toute construction de `broker.AccessRequest`.

### L'initiateur est audité, sans changement de schéma

Un `quorum.operation` supplémentaire est émis avec `actor` = initiateur et `outcome` = résultat
global du quorum. Le schéma d'événement (`contracts/events/audit-event.schema.json`) n'a qu'un
champ `actor` ; le modifier casserait la vérifiabilité de l'historique existant. Trois événements
pour un quorum à deux porteurs : deux approbations, une initiation.

`actor.aal` et `actor.auth_method` (optionnels au contrat) sont renseignés **uniquement** sur
l'événement de l'initiateur — le module `quorum` ne renvoie pas le niveau d'authentification des
porteurs. C'est ce qui rend les deux rôles distinguables au journal. Sans ces champs, les N+1
événements d'une même opération seraient identiques en type, cible, issue et forme d'acteur, et un
auditeur — ou `zs-replay` (ADR-034) — compterait un approbateur de trop. L'événement de l'initiateur
est émis même quand aucun porteur n'est vérifié — une tentative de déclenchement par un appelant
identifié est un fait à tracer autant qu'un succès.

Best-effort comme `policy.decided` (ADR-027) : une panne d'`audit-collector` est journalisée,
jamais renvoyée à l'appelant, le quorum ayant déjà été évalué de façon irréversible.

### Le contrat porte la contrainte

`contracts/openapi/admin-api.yaml` déclare l'en-tête `required: true` et les réponses `401`,
`403`, `502`. Le gestionnaire d'erreur de paramètres par défaut d'oapi-codegen est remplacé
(`NewHandler`) : il renvoyait `400 text/plain` avec `err.Error()` brut, ce qui est à la fois le
mauvais statut et une fuite de détail interne.

## Conséquences

**Ce qui est fermé.** Le déclenchement anonyme d'une opération critique. Le journal d'audit dit
désormais qui a demandé, pas seulement qui a approuvé.

**Ce qui reste ouvert.** L'habilitation. Un porteur AAL3 légitime peut toujours initier une
opération critique quelconque, y compris une qui ne le concerne pas. `SEC-ADMIN-API-AUTHZ-001`
reste journalisé, en **MEDIUM non bloquant** au lieu de HIGH bloquant, et reste inscrit au
tableau des risques acceptés de `security/threat-models/admin-api.md`. Cette correction réduit la
vulnérabilité, elle ne la supprime pas.

**Rupture de compatibilité.** Tout appelant existant de cet endpoint doit désormais présenter
l'en-tête. Aucun client de production n'existe à ce stade (`console-web` n'appelle pas encore
cet endpoint), le coût est nul aujourd'hui et croissant ensuite.

**Coût cryptographique.** Aucun. Réutilisation d'`identity-assertion/v1` via H3, exactement comme
ADR-009 et ADR-021 : aucune ligne ajoutée à `zs-crypto`, aucune entrée CBOM nouvelle.

## Critère de réexamen

À rouvrir dès que la granularité des rôles d'administration est tranchée — la vérification
d'habilitation viendra alors s'ajouter après `verifyCaller`, sans modifier le contrat, le
niveau AAL exigé ni le module `quorum`. Réexamen calendaire au **2026-11-29** si la question des
rôles n'a pas avancé d'ici là.

## Questions ouvertes

- Le niveau AAL3 doit-il être exigé pour **toutes** les opérations critiques, ou dépendre de
  l'opération ? Constante non configurable aujourd'hui : un niveau abaissable par configuration
  serait un contournement trivial. Une modulation par opération suppose de savoir quelles
  opérations existent — la même question de rôles, non tranchée.
- Le délai de 5 s et la borne de 64 assertions sont des valeurs par défaut raisonnables, non
  mesurées sous charge réelle. À réévaluer avec les tests de charge de la Phase 2 (`make up`).
- Le refus d'un appelant ne produit aucun événement d'audit : une campagne de sondage de
  l'endpoint reste invisible au journal. Auditer les refus supposerait d'attribuer un événement à
  une identité non établie, ce que le projet refuse ailleurs (ADR-027) — à trancher séparément.
