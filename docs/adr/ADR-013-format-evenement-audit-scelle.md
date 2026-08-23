# ADR-013 — Format de l'événement d'audit scellé (`audit-seal/v1`)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

ADR-010 a désigné `audit-seal` comme la suite d'émission la plus contrainte du projet :
compromettre sa clé permet de réécrire l'historique complet du système, y compris la trace de
sa propre compromission — plus grave que compromettre la clé `identity-assertion` (ADR-012),
dont la compromission n'affecte que les authentifications futures et reste détectable par le
journal d'audit lui-même. H1 (ADR-011) a levé le prérequis HSM partagé ; L1.2c (ADR-012) a livré
le premier scellement réel et découvert plusieurs pièges génériques (double-hachage aws-lc-rs,
canonicité par re-sérialisation). L1.4b implémente le scellement réel d'`audit-seal/v1`.

`crates/zs-audit` (L1.4a) livre déjà la construction du contenu métier (`AuditRecord`) et la
vérification de chaîne (`chain::verify_chain`, opérant sur des octets scellés opaques). Restait
à trancher : qui possède la canonicalisation de l'événement **complet** (contenu métier +
`event_id`/`sequence`/`prev_hash`/`signature`), sachant que `zs-crypto` ne dépend d'aucun crate
applicatif du workspace (frontière posée en L1.2c, `tools/lib/check-zs-crypto-deps.sh`).

## Décisions

### `zs_crypto::audit_seal` possède la canonicalisation complète

Comme `identity_assertion` l'a fait pour son propre document. Raison décisive : `verify()` doit
**reconstruire** le document canonique à partir de champs typés et le comparer octet à octet à
l'entrée (contrôle de canonicité déjà validé en L1.2c). Si une partie du document arrivait sous
forme de `serde_json::Value` opaque produit par `zs-audit`, `verify()` devrait re-sérialiser un
sous-arbre non typé — `deny_unknown_fields` sauterait sur cette portion, rouvrant l'injection de
champs arbitraires dans une zone signée mais non validée. Le document signé doit être
intégralement typé côté vérificateur.

**Conséquence** : `crates/zs-audit/src/canonical.rs` (L1.4a) est **supprimé** dans ce lot — deux
implémentations JCS dans le dépôt auraient divergé sans que rien ne le détecte. Ses deux tests de
non-régression (tri des clés, absence d'espace superflu) sont repris dans
`crates/zs-crypto/src/common.rs`, qui porte désormais la canonicalisation partagée.

**Correctif hérité** : l'ancien `canonical.rs` émettait `"target": null` / `"context": null`
quand ces champs étaient absents — le contrat les déclare non requis avec
`additionalProperties: false`, et `null` échoue la validation de schéma. `audit_seal` omet les
champs absents, ne les sérialise jamais en `null` — vérifié par test
(`champ_optionnel_absent_nest_jamais_null`) et par la conformité au contrat elle-même
(`octets_scelles_valident_le_contrat`, voir plus bas).

### Forme différente d'`identity_assertion`, imposée par le contrat existant

`contracts/events/audit-event.schema.json::signature` est un objet singulier
`{ suite, components: [...] }` (corrigé en même temps qu'`identity_assertion` — ADR-012 — pour
porter un tableau de composantes plutôt qu'une seule signature), **pas** un tableau
`signatures: [...]` au premier niveau comme `identity_assertion`. `contracts/` fait foi (règle
absolue #8) : la forme du contrat existant l'emporte sur la cohérence esthétique entre suites.

Conséquence de sécurité à traiter explicitement : puisque `suite` vit **à l'intérieur** de
l'objet `signature` — exclu du message signé — ce n'est pas un champ signé de premier niveau qui
lie cryptographiquement le document à sa version. C'est le **préfixe de séparation de domaine**,
dérivé de `signature.suite` **après confrontation à `accepted_suites`**, qui joue ce rôle : un
relabel `v1`↔`v2` change le message signé et invalide la signature. Verrouillé par test
(`suite_inconnue_est_refusee` et l'arité de composantes imposée par la suite résolue).

**Divergence assumée et datée** pour résorption au passage `v2` hybride (les deux formats
changent de toute façon à ce moment), pas un oubli.

### Séparation de domaine et encodage

`m = "zero-secret/audit-seal/v1" || 0x00 || jcs(document sans "signature")` — même schéma
qu'`identity_assertion`, préfixe distinct. Signatures en hexadécimal minuscule, raw `r‖s`
(même raisonnement qu'ADR-012 : canonicité triviale, cohérent avec `prev_hash`).

### `sequence` bornée à 2^53−1

`serde_json` sérialise un `u64` exactement, mais RFC 8785 canonicalise les nombres selon la
règle ECMAScript : au-delà de 2^53−1, un vérificateur tiers réimplémenté en JS ou en Go perd la
précision et calcule un `prev_hash` différent. Le journal doit rester vérifiable par un tiers
avec ses propres outils — c'est l'objet même de ce lot, pas un détail. `Sequence::new` refuse
au-delà (`sequence_au_dela_de_2_puissance_53_est_refusee`).

### Deux types partagés extraits vers `common.rs`, en commit isolé

`Timestamp` et `EventId` (validateur RFC 3339 / UUIDv7) sont désormais dans
`crates/zs-crypto/src/common.rs`, réutilisés tels quels par `audit_seal` (`event_id`,
`occurred_at`) et `identity_assertion` (`issued_at`, `expires_at`, `audit_event_id`) — un second
validateur dupliqué aurait divergé du premier sans que rien ne le détecte. Refactor livré en
commit séparé, sans changement de comportement (25/25 tests d'`identity_assertion` inchangés).
`SubjectId`/`AuthMethod`/`AssuranceLevel` restent définis dans `identity_assertion` et sont
réutilisés directement par `audit_seal::Actor` (mêmes concepts, pas de raison de dupliquer).

### Périmètre : `decision` non supporté dans ce lot

Le champ `decision` du contrat (présent sur `policy.decided`, `credential.issued` — backlog L2+)
n'est pas implémenté : aucun `EventType` de ce lot (parcours WebAuthn L1.1-L1.3) ne le requiert.
À ajouter avec le lot qui produit ces événements, pas par anticipation — cohérent avec le
principe déjà appliqué à L1.1 (pas de câblage DB avant qu'un serveur en ait besoin).

### `audit.chain_verified` : type scellable, pas de sémantique de charge utile

Ajouté aux deux énumérations `EventType` (`zs_crypto::audit_seal`, `zs_audit::record`) comme un
type d'événement ordinaire, scellable comme les autres. **Aucune logique d'ancrage** (plage de
séquences couverte, empreinte de tête, point de publication externe) n'est livrée ici : ces
champs n'existent dans aucune partie du contrat actuel, et les improviser sous forme de
`target.id` composite figerait un format probant jamais instruit. À traiter par un ADR dédié à
l'ouverture d'`audit-collector` (Go, hors périmètre Rust), pas anticipé ici.

### Clé HSM et vecteurs de chaînage figés

**Label `zs-audit-seal-v1`** (convention posée ici, symétrique à `zs-identity-assertion-v1` —
ADR-011 documentait la séparation sans fixer les noms). La version est dans le label : `v2` sera
une clé neuve, jamais la même clé réutilisée sous deux suites.

**Vecteurs figés** en deux temps, pour respecter la frontière de dépendance :
- **Production** — `crates/zs-crypto/src/audit_seal.rs`, `#[cfg(test)]` (seul endroit avec accès
  aux fonctions privées de scellement). Signeur `p256` déterministe (RFC 6979, ADR-012), 3
  événements chaînés, sérialisés en hexadécimal dans `tests/vectors/audit-seal-v1/chain.json`.
  Un test ignoré (`regenerer_les_vecteurs_de_chainage`) régénère le fichier — à relancer
  seulement si le format change délibérément (nouvel ADR), sinon le fichier cesse de détecter une
  dérive de canonicalisation. Un test non ignoré compare la sortie fraîche au fichier figé.
- **Consommation** — `crates/zs-audit/tests/chain_vectors.rs`, direction de dépendance normale
  (`zs-audit → zs-crypto`), aucune primitive importée : appelle `audit_seal::verify` sur chaque
  vecteur puis `chain::verify_chain` sur les entrées reconstruites — preuve d'intégration bout en
  bout entre les deux crates.

### Conformité au contrat, testée directement

`crates/zs-crypto` gagne une dev-dependency `jsonschema` (0.50, `default-features = false` — le
contrat n'a aucune référence distante, pas besoin de `reqwest`/TLS pour un validateur local) :
`octets_scelles_valident_le_contrat` valide un événement fraîchement scellé contre
`contracts/events/audit-event.schema.json` directement, plutôt que de faire confiance à la
lecture du contrat par ce module — c'est ce test qui a confirmé le correctif `null`/omission.

### Erreur opaque, type dédié

`audit_seal::SealError`/`VerifyError`, mêmes noms qu'`identity_assertion` mais modules distincts
— pas de type d'erreur partagé entre suites : un enum d'erreur partagé deviendrait l'union de
tous les cas et imposerait à chaque appelant des variantes structurellement inatteignables dans
son contexte, la forme exacte de `match` qui finit traitée en `_ => continue`. Seul
`common::FieldError` est partagé (validateurs de champ, pas la sémantique de scellement).

## Conséquences

**Positives** — le format `v1` porte déjà le conteneur à N composantes qui rendra `v2` hybride
non cassant. L'intégration `zs-audit`/`zs-crypto` est prouvée bout en bout par des vecteurs
figés, pas seulement par des tests isolés de chaque côté. La conformité au contrat est testée
directement (`jsonschema`), pas supposée. Le piège du double-hachage aws-lc-rs (découvert en
L1.2c) ne s'est pas reproduit ici — la mise en garde a fonctionné.

**Négatives** — divergence de forme assumée entre `identity_assertion` (`signatures: [...]`) et
`audit_seal` (`signature: {suite, components: [...]}`), résorbée seulement au passage `v2`. Le
champ `decision` reste non supporté, limitant ce lot au parcours déjà livré (L1.1-L1.3). La
mesure de latence `sign_digest` réelle reste impossible sur ce poste de développement Windows
(pas de SoftHSM2, même limite qu'H1 et L1.2c) — reportée à CI/Jenkins Linux.

**Surface d'attaque** — `audit_seal::verify` est un analyseur exposé à des entrées non fiables,
borné en taille (8192 octets), refus par défaut à chaque étape, fuzzé
(`crates/zs-crypto/fuzz/fuzz_targets/audit_seal_verify.rs`, compile via `cargo +nightly check`,
non exécuté ici — même limite que L1.1/L1.2c, à lancer en CI/Jenkins Linux).

## Critère de réexamen

Réexaminer au démarrage de `v2` hybride (résorption visée de la divergence de forme avec
`identity_assertion`) et à l'ouverture effective d'`audit-collector`, qui devra spécifier la
charge utile probante de l'ancrage périodique (`audit.chain_verified`) par son propre ADR.
