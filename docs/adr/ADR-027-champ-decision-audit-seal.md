# ADR-027 — Champ `decision` dans `audit-seal/v1` : extension sans changement de suite

**Statut** : accepté
**Date** : 2026-08-24
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

`access-broker` devait être câblé pour appeler `audit-collector.Record` sur `policy.decided`
(ADR-026 avait construit le pont mais laissé ce type hors périmètre). Bloqué immédiatement :
`contracts/events/audit-event.schema.json` exige un objet `decision` (`request_id`,
`decision_hash`, `policy_version`) sur `policy.decided`, mais `zs_crypto::audit_seal::
AuditEventFields` ne portait aucun champ `decision` — module protégé, jamais modifié sans
validation explicite (`crates/zs-crypto/CLAUDE.md`). Consultation `referent-crypto` menée avant
tout code ; deux décisions soumises à validation humaine et approuvées.

## Décision 1 — Extension de `audit-seal/v1` en place, pas de `v2`

Le contrat v1 déclare déjà `decision` — `zs-crypto` n'en implémentait qu'un sous-ensemble
(uniquement les types du parcours WebAuthn + `quorum.operation`, documenté explicitement en
tête de module). Ce n'est donc pas un changement de contrat, mais le rattrapage d'une
implémentation partielle. `audit-seal/v2` reste réservé à l'hybridation post-quantique
(`ECDSA P-256 + ML-DSA-65`, échéance ANSSI 2027, `crates/zs-crypto/CLAUDE.md`) — brûler ce
numéro sur un ajout de champ obligerait plus tard soit à un `v3` pour la PQC, soit à mélanger
deux changements de nature incomparables dans le même relabel de préfixe de domaine.

**Aucun événement déjà scellé ne change d'un octet.** Le nouveau champ n'est inséré que si
`Some` (même convention que `target`/`context`), donc absent des événements existants. Preuve
exigée, pas affirmée : `vecteurs_de_chainage_correspondent_au_fichier_fige`
(`crates/zs-crypto/src/audit_seal.rs`) passe sans régénération du fichier figé
`tests/vectors/audit-seal-v1/chain.json`.

**Coût opérationnel, pas cryptographique** : un vérificateur v1 déjà déployé (aucun n'existe
encore dans ce dépôt) refuserait un événement porteur de `decision`
(`deny_unknown_fields` → `MalformedDocument`) — refus par défaut, conforme à la règle absolue
#2, mais impose un ordre de déploiement (vérificateurs avant émetteur) si un vérificateur
externe venait à exister.

## Décision 2 — Amendement du contrat maintenant : `decision_signature`/`decision_signature_key_id`

`audit-seal/v1` signe ce qu'on lui donne — il ne vérifie pas que `decision_hash` vient
réellement du PDP. Un `access-broker` compromis (ou tout processus atteignant le socket Unix
d'`audit-sealer`) pourrait faire sceller un `decision_hash` fabriqué dans un événement par
ailleurs valide. Le contrat revendique pourtant : « permet le rejeu hors ligne : sans
`decision_hash` et `policy_version`, la décision n'est pas vérifiable par un tiers » — cette
revendication est fausse tant que rien ne rattache le `decision_hash` scellé à une preuve
d'origine PDP.

**Mesure retenue** : `decision.decision_signature`/`decision.decision_signature_key_id`
(optionnels, `pattern: ^[0-9a-f]+$`), recopiés tels quels depuis `policyv1.DecisionResponse`
(`decision-seal/v1`, H4/ADR-019) et couverts par la signature `audit-seal/v1` elle-même. Un
vérificateur hors ligne possédant les deux clés publiques (`zs-audit-seal-v1` et
`zs-decision-seal-v1`) peut alors établir indépendamment « le PDP a décidé ceci » **et** « ce
domaine a journalisé cela ».

**`audit-sealer` ne vérifie PAS `decision_signature` au scellement** — décision délibérée, pas
un oubli. Alternative rejetée : `audit-sealer` appelle `PolicyService.VerifyDecision` avant de
sceller. Rejetée parce qu'un contrôle à l'exécution ne laisse aucune trace : un vérificateur
hors ligne, des années plus tard, voit le même document scellé qu'il y ait eu contrôle ou non,
et doit croire sur parole qu'`audit-sealer` était correctement configuré à l'instant du
scellement — pour un journal dont toute la valeur est la vérifiabilité par un tiers qui n'a
parlé à personne, c'est le mauvais type de contrôle. Elle ajouterait en prime un appel réseau
sortant sur le chemin de scellement (`audit-sealer` reste sans état et sans dépendance réseau,
ADR-026), donc un nouveau mode de panne sur la production de traces.

**Fenêtre qui se ferme.** `decision` a `additionalProperties: false` : ajouter ces deux
propriétés est aujourd'hui gratuit (zéro `policy.decided` scellé en production, aucun
historique à invalider). Le jour où le premier est scellé, ce serait un changement cassant la
vérifiabilité de l'historique — reporté de fait à `audit-seal/v2`, c'est-à-dire à la migration
PQC, deux ou trois ans pendant lesquels le journal revendiquerait une propriété qu'il ne
fournit pas. D'où la décision maintenant plutôt que différée.

**Portée de l'attestation, explicite** : `audit-seal/v1` atteste que le domaine d'autorité a
*détenu* ce `decision_hash` au moment du scellement, pas qu'il vient réellement du PDP.
Établir l'origine PDP exige la vérification indépendante de `decision-seal/v1` par un outil qui
n'existe pas encore dans ce dépôt (aucun vérificateur hors ligne/outil de rejeu construit à ce
jour) — limite documentée ici, dans `security/threat-models/audit-sealer.md` et
`security/threat-models/audit-collector.md`, pas cachée.

## Décisions de conception (crate `zs-crypto`)

- **`EventType::PolicyDecided` seul ajouté** — `credential.issued` (même forme de `decision`)
  reste hors périmètre, aucun producteur ne l'émet encore (pas d'anticipation, même règle que le
  reste du module).
- **Couplage `decision` ↔ `event_type` obligatoire dans les deux sens**
  (`EventType::requires_decision`) : `policy.decided` exige `decision`, tout autre type
  l'interdit. Vérifié en émission (`AuditSealer::seal`, via `validate_decision_coupling`, testable
  sans HSM) **et** en vérification (`verify`) — JSON Schema seul ne peut pas exprimer ce couplage
  conditionnel (`additionalProperties`/`required` ne dépendent pas d'un autre champ du message).
- **`RequestId` distinct d'`EventId`** — même forme UUID (`8-4-4-4-12` hexadécimal) mais sans
  l'exigence de nibble de version 7 qu'`EventId` impose : le contrat de `decision.request_id`
  n'exige que `format: uuid`, l'imposer refuserait de sceller une décision légitime dont le
  `request_id` ne serait pas UUIDv7 — un événement d'audit perdu, contraire à la règle absolue
  #9. Factorisé avec `EventId` via une macro partagée (`uuid_string!` dans `common.rs`) plutôt
  que dupliqué, pour ne pas diverger silencieusement.
- **`decision_hash: [u8; 32]`** (comme `prev_hash`), pas `Vec<u8>` — le contrat impose une
  longueur hex fixe (64 caractères). `policy_version`/`reasons` : nouveaux types bornés
  (`bounded_ascii_string!`). `reasons` plafonné à `MAX_REASONS = 16` — premier champ de
  cardinalité variable du document signé, doit être borné pour ne pas dépasser `MAX_BYTES` à la
  vérification après avoir déjà été chaîné.
- **Correctif d'un défaut préexistant, dans le même lot** : `seal()` ne bornait pas la taille
  du document produit alors que `verify()` refuse déjà au-delà de `MAX_BYTES` — un événement
  pouvait être scellé et chaîné puis irrémédiablement refusé à la vérification (rupture de
  chaîne définitive, pas un refus par défaut sain). Garde ajoutée (`validate_size`, testable sans
  HSM), mesurée et non estimée (`signature_overhead_bytes` sérialise un conteneur de signature
  représentatif et prend la longueur réelle de ses octets canoniques).
- **Correctif d'un second défaut préexistant, trouvé en écrivant `decision_value`** :
  `actor_value`/`context_value` sérialisaient un champ interne optionnel absent en JSON `null`
  (ex. `actor.aal: None` → `"aal": null`) — le contrat refuse `null` pour ces propriétés
  (`type: string`, pas nullable). Masqué jusqu'ici : aucun test existant n'exerçait un
  `Actor`/`Context` avec un champ interne à `None` tout en étant vérifié contre le schéma. Même
  bug côté vérification (`unsigned_document_from_wire` reconstruisait `"aal": null` pour la
  comparaison de canonicité, ce qui aurait fait refuser en `NonCanonical` tout événement légitime
  sans `aal`). Corrigé des deux côtés par insertion conditionnelle, testé
  (`champ_interne_optionnel_absent_nest_jamais_null_meme_objet_present`).

## Décisions de conception (`access-broker`)

- **Condition d'émission** : `policy.decided` audité seulement quand le PDP a réellement été
  consulté (`decision.Signed != nil`), jamais pour un refus local avant tout appel PDP
  (justification trop longue, champ requis absent, approbation vérifiée absente) — ces refus
  n'ont pas de décision à auditer.
- **Couvre ALLOW et DENY.** `broker.Decision.Signed` n'était peuplé que pour ALLOW
  (`if decision.Allowed`) — asymétrie purement locale à `broker.go`, sans lien avec
  `policy-engine` qui scelle *toutes* ses réponses sans distinction d'effet (H4). Corrigé pour
  peupler `Signed` sur ALLOW et DENY : un refus d'accès mérite d'être audité au moins autant
  qu'un octroi.
- **Échec de `audit-collector.Record` : best-effort, ne bloque jamais la réponse HTTP.** Même
  patron que le déclenchement d'émission déjà en place (`credentialClient.Emit`, ADR-025) et
  cohérent avec `docs/architecture.md` (« une saturation de l'audit ne dégrade pas l'accès ») —
  la décision PDP a déjà eu lieu de façon irréversible au moment où l'audit est tenté ; échouer
  toute la requête HTTP à ce stade ne l'annulerait pas, seulement priverait l'appelant légitime
  d'une réponse déjà déterminée. Erreur journalisée (`log.Printf`), jamais silencieuse.

## Conséquences

**Positives** — `policy.decided` est scellable et câblé de bout en bout depuis `access-broker`,
ALLOW et DENY. Deux défauts préexistants de `zs-crypto` corrigés au passage (garde de taille
absente en émission, sérialisation `null` de champs internes optionnels). Le journal peut
désormais prouver l'origine PDP d'une décision auditée, pas seulement sa détention.

**Négatives** — `credential.issued` reste non scellé (même angle mort reconfirmé, pas résolu
ici). `audit-sealer` ne vérifie pas `decision_signature` au scellement : la preuve d'origine
PDP existe dans l'événement mais aucun outil de ce dépôt ne la vérifie encore.

**Surface d'attaque** — inchangée pour `audit-sealer` (toujours sans état, socket Unix
uniquement, ADR-026). Nouvelle entrée Spoofing dans les modèles de menaces d'`audit-sealer`/
`audit-collector` : un `access-broker` compromis peut faire sceller un `decision_hash`
fabriqué — non détecté par `audit-seal/v1` seul.

## Critère de réexamen

Réexaminer dès qu'un vérificateur hors ligne/outil de rejeu (`make replay`, encore non
construit) est instruit — il devra vérifier `decision_signature` via `decision-seal/v1`, pas
seulement `audit-seal/v1`. Réexaminer `credential.issued` non scellé dès que ce type est
produit par un composant (même forme de `decision`, extension triviale de ce lot).
