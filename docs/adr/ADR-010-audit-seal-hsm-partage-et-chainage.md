# ADR-010 — Découpage de L1.4, prérequis HSM partagé et modèle de chaînage

**Statut** : accepté
**Date** : 2026-08-22
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

Le backlog L1.4 (« Audit du parcours ») demande la production d'événements signés et chaînés
pour chaque action du parcours WebAuthn (L1.1/L1.2/L1.3), chacune ayant explicitement différé
cette production en attendant ce lot. Consulté avant toute modification de `zs-crypto`/`zs-hsm`,
`referent-crypto` a établi que `audit-seal` (la suite qui scelle chaque événement) est une suite
d'**émission**, soumise pleinement aux invariants 5 (hybridation stricte) et 7 (clé privée
jamais hors HSM) de `zs-crypto/CLAUDE.md` — **plus contrainte** qu'`identity-assertion/v1`
(ADR-007/008) : compromettre la clé d'audit permet de réécrire l'historique complet du système,
y compris la trace de sa propre compromission, alors que compromettre la clé d'assertion
n'affecte que les authentifications futures et reste détectable par le journal d'audit lui-même.

`crates/zs-hsm` reste un stub vide à ce jour — le même blocage qui a fait différer L1.2c
s'applique donc identiquement à la partie signature de L1.4.

## Décision

### Découpage en quatre contributions

- **L1.4a** (cette contribution) — `crates/zs-audit` : construction du contenu métier
  (`AuditRecord`, non sérialisable — même raison que `AuthenticationClaims` en L1.2b), sérialisation
  canonique (RFC 8785 JCS), vérification de chaîne (`prev_hash`/`sequence`), ports de stockage
  (`AuditSink`, `AuditChainStore` — traits seuls, cohérent scope-cut L1.1/L1.2). **Aucune ligne
  ajoutée à `zs-crypto`/`zs-hsm`.**
- **H1** (prérequis partagé, contribution dédiée, ADR propre requis à son démarrage) —
  intégration PKCS#11/SoftHSM2 réelle dans `crates/zs-hsm`. Conçue avec **deux consommateurs en
  tête** (`identity-assertion` et `audit-seal`, ce dernier étant l'opération HSM la plus
  fréquente du système puisque chaque fonctionnalité produit un événement — règle absolue #9) :
  une API pensée pour un seul appel occasionnel serait inadaptée au débit d'audit.
- **L1.2c** — scellement réel de l'assertion d'identité (ADR-007/008), consomme H1.
- **L1.4b** — scellement réel de l'événement d'audit (`audit-seal/v1`), vecteurs de chaînage
  figés avec une vraie signature, ancrage périodique (`event_type: "audit.chain_verified"`,
  déjà réservé au contrat), consomme H1.

**Justification de sortir H1 maintenant plutôt que de différer encore** : L1.2c et L1.4b sont
désormais tous deux bloqués sur exactement la même intégration. La redemander séparément à deux
reprises produirait deux conceptions d'API HSM incohérentes entre elles. Le poste de calendrier
2027 (échéance ANSSI post-quantique) porte sur l'**approvisionnement HSM** — quels mécanismes
PKCS#11 le matériel visé expose réellement (PKCS#11 v3.2, qui porte ML-DSA/ML-KEM, est un
standard OASIS récent que peu de HSM sous visa ANSSI exposent encore) — pas sur l'écriture Rust ;
plus tôt cette contrainte remonte, mieux le calendrier se pilote.

### Correctif de contrat : `authority_domain` obligatoire

`contracts/events/audit-event.schema.json` définissait `sequence` comme un compteur strictement
croissant **par domaine d'autorité**, mais laissait `authority_domain` optionnel — deux domaines
auraient pu fusionner silencieusement dans une même chaîne, ou un événement sans domaine aurait
cassé l'invariant de la chaîne à laquelle il s'ajoute. Corrigé maintenant (`authority_domain`
ajouté à `required`) : gratuit avant tout événement produit, cassant après.

### Modèle de signature : une signature par événement

Question ouverte posée par `referent-crypto` : signer chaque événement individuellement (conforme
au contrat tel qu'écrit, audit le plus simple, mais débit plafonné par le HSM) ou sceller
périodiquement une racine Merkle (découple le débit, mais modifie le contrat et introduit une
fenêtre de non-répudiation). **Retenu : une signature par événement.** Le débit se traite par
partitionnement par `authority_domain` — déjà permis par le schéma — plutôt qu'en changeant le
modèle probant. Le débit réel (latence d'un aller-retour PKCS#11) reste à mesurer lors de H1
avant de s'engager sur un chiffre de capacité.

### Sémantique de chaînage retenue

`prev_hash` porte sur la **sérialisation canonique complète de l'événement précédent, signature
incluse** (même principe que le *leaf hashing* de Certificate Transparency, RFC 6962) — pas sur
le contenu non signé. Motif : si le hachage ne portait que sur le contenu non signé, un
downgrade de suite (remplacer une signature `audit-seal/v2` hybride par une `v1` sur un
événement passé) ne casserait pas la chaîne, contournant l'invariant 5 par la porte de derrière.
Conséquence pour L1.4a : la vérification de chaîne (`crates/zs-audit/src/chain.rs`) opère sur
des octets **opaques** (la structure interne d'un événement scellé lui est indifférente), testée
avec des octets fabriqués directement dans les tests, jamais via une API publique qui les ferait
passer pour un événement réel.

## Conséquences

**Positives** — L1.2c et L1.4b deviennent indépendants et parallélisables une fois H1 livré. Le
correctif de contrat est gratuit maintenant, impossible sans casser la vérifiabilité de
l'historique après le premier événement réel. La vérification de chaîne est démontrable et
testée dès aujourd'hui, sans dépendre d'aucune primitive de signature.

**Négatives** — le critère d'acceptation du backlog L1.4 (« aucune action ne réussit sans
produire son événement d'audit ») n'est démontré par cette contribution qu'au niveau de la
**complétude de flux** (un puits qui échoue fait échouer l'action, prouvé par test adverse), pas
au niveau du scellement cryptographique réel — celui-ci n'existe pas encore. Coché partiellement
dans `docs/backlog.md`, avec cette note explicite.

**Surface d'attaque** — aucune nouvelle primitive cryptographique dans cette contribution. La
limite structurelle du chaînage (une troncature en queue de chaîne reste indétectable sans
ancrage externe) est documentée et testée explicitement, pas seulement affirmée en commentaire.

## Critère de réexamen

Réexaminer au démarrage effectif de H1 : cet ADR fixe la décision de sortir l'intégration HSM
comme prérequis partagé et le modèle de signature par événement, pas la conception complète de
l'intégration PKCS#11 elle-même (analyse de dépendance `cryptoki`, gestion de session, sémantique
de perte de connexion) — à instruire dans l'ADR dédié à H1.
