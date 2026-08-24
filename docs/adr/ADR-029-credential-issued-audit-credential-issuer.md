# ADR-029 — `credential-issuer` câblé sur `audit-collector` : `credential.issued`, extension `EventType::CredentialIssued`

**Statut** : accepté
**Date** : 2026-08-24
**Décideurs** : responsable technique (validation `referent-crypto` fraîche indisponible —
service surchargé au moment du lot, voir « Consultation crypto » ci-dessous)

## Contexte

Dernier des trois producteurs Go à câbler sur `audit-collector` (ADR-026/027/028 : pont,
`policy.decided`, `quorum.operation`). Deux trous de contrat trouvés en implémentant, aucun des
deux anticipé par la portée initiale :

1. `contracts/events/audit-event.schema.json` exige `decision` (dont `request_id`) sur
   `credential.issued`, même forme que `policy.decided` — mais `policyv1.DecisionResponse` (la
   seule chose que `credential-issuer` reçoit) ne porte pas de `request_id` : ce champ n'existe
   que sur `DecisionRequest`, jamais transmis à `credential-issuer`.
2. `actor` (`subject_id`, requis par le contrat sur TOUT événement) n'a également aucune source :
   `DecisionResponse` ne porte pas de `Principal` — `credential-issuer` n'a jamais eu besoin de
   connaître l'identité du demandeur, l'approbateur étant déjà vérifié en amont par
   `access-broker` (H3) et jamais revérifié ici.

## Décision 1 — `request_id`/`subject_id`/`aal`/`auth_method` via `EmissionOrder`, pas via `decision-seal/v1`

**Alternative rejetée** : ajouter `request_id` (et l'identité) aux champs signés de
`decision-seal/v1` (`policyv1.DecisionResponse`), pour que la preuve remonte scellée depuis le
PDP. Rejetée : `decision-seal/v1` est un crate protégé (H4/ADR-019), toute extension de sa
portée signée exige sa propre validation `referent-crypto` — plus lourd que nécessaire pour un
simple identifiant de corrélation qui n'a besoin d'aucune garantie cryptographique propre (il
n'autorise rien, ne prouve rien seul).

**Retenu** : `contracts/proto/credential/v1/emission.proto::EmissionOrder` porte désormais
`request_id`/`subject_id`/`aal`/`auth_method` en clair, non signés — `access-broker` les a déjà
sous la main (même `request_id`/`verifyResp` que pour `policy.decided`, ADR-027) et les transmet
tels quels. Changement Go/proto pur, **aucune crypto touchée** pour cette partie. Documenté
explicitement dans le contrat : « jamais utilisés pour une décision d'autorisation, qui reste
entièrement portée par `decision` » — `credential-issuer` continue de ne revérifier que la
`DecisionResponse` signée (`VerifyDecision`, H4), ces nouveaux champs ne participent à aucun
contrôle d'accès.

**Risque accepté, documenté** : `credential-issuer` fait désormais confiance à `access-broker`
pour l'exactitude de `subject_id`/`aal`/`auth_method`/`request_id` dans l'événement d'audit —
aucune vérification cryptographique de ces champs précis. C'est le même niveau de confiance que
celui déjà accordé à `access-broker` pour tout le reste de l'appel (verbe, ressource) : la
frontière de confiance ne change pas, seule sa surface s'élargit de quelques champs texte.

## Décision 2 — `EventType::CredentialIssued`, mécaniquement identique à `PolicyDecided`

`credential.issued` a exactement la même forme de `decision` que `policy.decided` dans le
contrat. `zs_crypto::audit_seal::EventType::CredentialIssued` ajouté avec la même règle dans
`requires_decision()` (`matches!(self, EventType::PolicyDecided | EventType::CredentialIssued)`),
réutilisant `DecisionInfo` tel quel — **aucun nouveau type, aucun nouveau champ, aucune nouvelle
primitive ou suite**. `outcome` toujours `"success"` : `credential.issued` n'est construit
qu'après un succès OpenBao réel (`internal/issuer.Emit`, règle déjà en place avant ce lot), un
refus n'atteint jamais ce point.

### Consultation crypto

`referent-crypto` indisponible (API surchargée, 4 tentatives échouées) au moment de ce lot.
Décision prise sans consultation fraîche, avec l'accord explicite de l'utilisateur, sur la base
que ce changement est structurellement identique à un pattern déjà validé par `referent-crypto`
pour `PolicyDecided` (ADR-027) : même struct `DecisionInfo`, même mécanisme de couplage
bidirectionnel, aucune primitive/algorithme/suite nouveau. **Ce raisonnement ne s'applique qu'à
cette extension précise** — toute future modification de `crates/zs-crypto` reste soumise à
validation `referent-crypto` fraîche, cette dérogation n'est pas un précédent général.

## Conséquences

**Positives** — les trois producteurs Go (`access-broker`, `admin-api`, `credential-issuer`)
sont désormais câblés sur `audit-collector`. `credential.issued` scellable et
`decision_signature`/`decision_signature_key_id` transportés (même limite que `policy.decided`,
ADR-027 : non vérifiés au scellement).

**Négatives** — `EmissionOrder` porte maintenant des champs texte non authentifiés
indépendamment du reste du message (mais couverts par le même canal gRPC en clair que tout le
reste, même dette de TLS que partout ailleurs). Consultation crypto non fraîche pour l'extension
`EventType` — risque jugé minimal et documenté, pas caché.

**Surface d'attaque** — inchangée pour `audit-sealer`/`audit-collector`. `credential-issuer`
accepte quatre nouveaux champs non vérifiés dans son contrat d'entrée — mêmes conséquences
d'un `access-broker` compromis que celles déjà documentées pour `policy.decided`
(`security/threat-models/audit-sealer.md`, entrée Spoofing ADR-027) : un `access-broker`
compromis peut déjà fabriquer `verb`/`resource_id` arbitraires, `subject_id`/`request_id`
s'ajoutent à cette même liste, pas une nouvelle catégorie de risque.

## Critère de réexamen

Réexaminer si `credential-issuer` acquiert un jour une raison de vérifier l'identité du
demandeur lui-même (au-delà de la décision signée) — rendrait alors `subject_id` non signé
insuffisant. Réexaminer la dérogation de consultation crypto : si `referent-crypto` était
disponible peu après ce lot, une confirmation a posteriori serait bienvenue mais non bloquante
(changement déjà en production à ce moment).
