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
| Assertion invalide, ou hors du `expected_authority_domain` | `401 assertion_de_lappelant_invalide` |
| `aal != "AAL3"`, valeur vide incluse | `403 niveau_dauthentification_insuffisant` |

Une indisponibilité du vérificateur est un refus, jamais un repli permissif (règle absolue #2).
Le domaine d'autorité n'est pas contrôlé séparément : l'assertion de l'appelant est vérifiée
**contre** `expected_authority_domain` du corps, donc un appelant hors domaine échoue à la
vérification elle-même.

### L'initiateur n'est jamais compté dans le quorum

L'assertion de l'en-tête n'entre pas dans la liste des porteurs. Initiateur et porteur sont deux
rôles : un initiateur qui s'auto-compterait ramènerait le quorum réel à un seul porteur
indépendant, ce que le plancher `MinimumThreshold = 2` d'ADR-021 interdit précisément.

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
pour un quorum à deux porteurs : deux approbations, une initiation. L'événement de l'initiateur
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
- Faut-il refuser qu'un initiateur figure aussi parmi les porteurs ? Aujourd'hui autorisé : le
  quorum de 2 exige de toute façon un second porteur distinct. À trancher avec les rôles.
