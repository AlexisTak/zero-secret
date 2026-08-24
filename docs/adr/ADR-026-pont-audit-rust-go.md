# ADR-026 — Pont d'audit Rust↔Go : `audit-sealer` (Rust) + `audit-collector` (Go)

**Statut** : accepté
**Date** : 2026-08-24
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

Trois composants Go (`access-broker`, `admin-api`, `credential-issuer`) construisent des
événements d'audit (`policy.decided`, `credential.issued`, `quorum.operation`) mais ne peuvent
pas les sceller eux-mêmes — règle absolue #4 (« toute crypto passe par `zs-crypto` ») et ADR-001
(frontière Rust/Go uniquement réseau, jamais FFI) l'interdisent. Seul `identity-provider` (Rust,
H5) scelle et persiste réellement des événements aujourd'hui, strictement en interne à son
propre process — jamais partagé. `apps/audit-collector` était un stub vide depuis le lot
d'échafaudage initial (L0.1) ; ADR-025 avait déjà repéré ce composant comme candidat pour un
futur pont d'audit partagé, sans l'instruire.

**Portée de ce lot** (validée avec l'utilisateur) : construire le pont — un nouveau binaire Rust
(`audit-sealer`) exposant le scellement, et `audit-collector` (Go) recevant des événements bruts
et les persistant. **Le câblage des trois producteurs Go est différé** à des lots séparés (même
discipline que H5 avant L2.6) — ce lot livre le pont et sa réception réseau, testés de bout en
bout avec des événements construits pour le test, pas encore les appels réels depuis les trois
composants.

## Décision critique : socket Unix, jamais un port réseau

**`audit-sealer` n'est pas un service réseau ouvert.** Exposer la clé `zs-audit-seal-v1` comme
un oracle de signature accessible à quiconque atteint son port détruirait la non-répudiation de
tout le journal — n'importe quel appelant réseau ferait fabriquer des événements arbitraires
signés valides. C'est exactement le scénario que redoute ADR-010 : « compromettre la clé d'audit
permet de réécrire l'historique, y compris la trace de sa propre compromission ».

Le précédent « pas de mTLS, dette assumée » (`policy-engine`, `identity-provider`,
`access-broker`, `admin-api`, `credential-issuer`) **ne s'étend pas ici**. Chacun de ces
précédents garde sa clé de signature strictement intra-process — aucun autre appelant ne peut
l'invoquer. `audit-sealer` serait le premier service dont la fonction même est d'exposer une
opération de signature à un appelant distinct sur le réseau ; la dette de TLS déjà acceptée
ailleurs ne compense pas cette différence qualitative.

**Mesure retenue** (validée `referent-crypto` + utilisateur) : `audit-sealer` et
`audit-collector` colocalisés sur le même hôte, communiquant par un socket Unix
(`tokio::net::UnixListener`, chemin fourni par `ZS_AUDIT_SEALER_SOCKET`/`ZS_AC_AUDIT_SEALER_SOCKET`)
— jamais un port TCP. C'est une contrainte de déploiement, pas un mécanisme d'authentification
inventé (conforme à la discipline du projet : ne jamais improviser d'auth non instruite).
`access-broker`/`admin-api`/`credential-issuer` continuent de parler uniquement à
`audit-collector` (réseau normal, même dette de TLS déjà acceptée partout ailleurs) — jamais
directement à `audit-sealer`.

L'alternative rejetée — différer tout le pont jusqu'à ce que SPIFFE/SPIRE existe dans ce dépôt —
aurait bloqué indéfiniment la fermeture de l'angle mort `policy.decided`/`credential.issued` non
scellés, sans bénéfice : le socket Unix ferme le trou de l'oracle de signature dès maintenant,
sans attendre une dépendance non instruite.

## Décisions

### `audit-sealer` sans état, sans Postgres, une seule responsabilité

`AuditSealingService` expose deux RPC : `Seal` (reçoit des champs déjà calculés par l'appelant —
`event_id`, `sequence`, `prev_hash`, `occurred_at`, `authority_domain`, `event_type`, `actor`,
`target?`, `outcome`, `context?` — et retourne les octets scellés) et `HashPrevious` (voir
ci-dessous). Aucune logique de chaînage, aucune validation métier au-delà du typage déjà imposé
par `AuditEventFields` (`bounded_ascii_string!`, `Sequence`, enums fermés).

### `HashPrevious` — ajouté en cours d'implémentation, pas anticipé au plan initial

La conception initiale prévoyait qu'`audit-collector` hache localement les `sealed_bytes` de
l'événement précédent pour calculer `prev_hash` — un `sha256Of()` en Go via `crypto/sha256`.
Écrit puis retiré avant tout commit : `tools/lib/check-no-direct-crypto.sh` interdit **tout**
import `crypto/*` côté Go, pas seulement les opérations de signature — le hachage en fait
strictement partie. Plutôt que d'assouplir le hook (interdit sans validation explicite, voir
`CLAUDE.md` racine, section « ce que tu ne fais jamais sans validation »), une seconde RPC
`HashPrevious` a été ajoutée au même contrat : `audit-collector` transmet les `sealed_bytes` bruts
de la tête de chaîne, `audit-sealer` les hache via `zs_audit::hash_sealed_event` (déjà existant,
lui-même un appel à `zs_crypto::authenticator_proof::sha256`) et retourne le digest. `audit-sealer`
reste ainsi le seul point où une opération cryptographique — signature ou hachage — a lieu pour
le compte du côté Go.

### `audit-collector` porte tout le chaînage et la persistance

Lecture de la tête de chaîne par `authority_domain` (`audit.events`, rôle `audit_writer`, même
requête que `apps/identity-provider/src/store.rs::AuditStore::chain_head`), calcul de
`sequence`/`prev_hash` (racine 32 octets nuls pour le premier événement, même convention que
`zs_audit::CHAIN_ROOT`), appel à `audit-sealer` pour la signature, `INSERT` protégé par la
contrainte `UNIQUE (authority_domain, sequence)` déjà en place (migration 002).

**Jamais de ré-essai automatique sur conflit ou timeout.** `seal()` n'est pas idempotent — la
signature ECDSA est randomisée — donc un ré-essai après un timeout ou un conflit produirait une
seconde signature valide sur le même `(sequence, prev_hash)`, un risque de fourche du journal
(ADR-011, réaffirmé par `referent-crypto` pour ce lot). Un événement scellé mais non persisté est
un événement perdu, signalé comme une erreur de transport, jamais re-signé silencieusement.
Testé (`TestConflitDeSequenceNestJamaisReessaye` : un seul appel à `Seal` même quand `Append`
échoue).

### Écrivain unique par `authority_domain`, pour l'instant

`audit-collector` est le seul appelant d'`audit-sealer` dans ce lot — les producteurs Go ne
l'appellent pas encore, donc pas de concurrence multi-process sur la tête de chaîne à ce stade.
**Point à revoir explicitement** quand le câblage réel des producteurs introduira des appelants
concurrents à `audit-collector` : la lecture de tête de chaîne puis l'`INSERT` ne sont pas
protégées par une transaction verrouillante aujourd'hui, seule la contrainte `UNIQUE` empêche une
double écriture — suffisant tant qu'un seul processus écrit, pas garanti au-delà.

### `event_id`/`occurred_at` générés par `audit-collector`, jamais fournis par l'appelant

C'est la réception qui fait exister l'événement — rôle déjà assigné à ce composant par
`docs/architecture.md` (« horodatage »), cohérent avec R7 sans dupliquer la génération côté
producteur.

### Portée non couverte, reconfirmée

**`policy.decided`/`credential.issued` ne peuvent toujours pas être scellés via ce pont.**
`AuditEventFields` (`zs-crypto`) ne porte pas le champ `decision` qu'exige
`contracts/events/audit-event.schema.json` pour ces deux types — seuls les types déjà couverts
par `zs_crypto::audit_seal::EventType` (parcours WebAuthn + `quorum.operation`) peuvent être
scellés aujourd'hui. C'est une correction par rapport à l'attente initiale de ce lot (« débloque
policy.decided/credential.issued/quorum.operation ») : seul `quorum.operation` l'est réellement.
Étendre `AuditEventFields` avec un champ `decision` est une décision crypto séparée, non
instruite ici — elle exigerait sa propre consultation `referent-crypto`.

Le câblage des trois producteurs Go (`access-broker`/`admin-api`/`credential-issuer` appelant
réellement `audit-collector.Record`) est différé, hors périmètre de ce lot.

### Visibilité privée des fonctions de mapping `zs-crypto`

`EventType::from_contract_str`/`ActorKind::from_contract_str`/`Outcome::from_contract_str` ne
sont pas `pub` dans `zs-crypto` — inaccessibles depuis `audit-sealer`. Plutôt que d'assouplir la
visibilité de `zs-crypto` (changement structurant nécessitant une validation `referent-crypto`
séparée), les petites tables de correspondance chaîne→enum sont dupliquées localement dans
`apps/audit-sealer/src/lib.rs` — même précédent déjà établi pour `civil_from_days`, dupliqué
entre `policy-engine` et `identity-provider`.

### Pas de TLS/mTLS sur le lien `audit-collector` → producteurs

Même dette que partout ailleurs (L2.2/H3/H4/H5/ADR-022/ADR-023/ADR-025) — ce lot ne câble pas
encore ce lien de toute façon.

## Conséquences

**Positives** — le pont existe et fonctionne de bout en bout (testé) pour les types d'événements
déjà couverts par `AuditEventFields`. L'oracle de signature n'est jamais exposé en réseau ouvert
— fermé par construction, pas par une politique d'accès qu'un déploiement pourrait mal
configurer. `zs-hsm` reste le seul point d'accès au HSM, cohérent avec l'architecture existante.

**Négatives** — `policy.decided`/`credential.issued` restent non scellés ; le pont ne les
débloque pas malgré l'intention initiale. Aucun producteur Go n'appelle encore ce pont —
c'est une infrastructure prête, pas encore utilisée. `apps/audit-sealer/src/main.rs` est non
vérifié sur un poste de développement Windows (voir ci-dessous).

**Surface d'attaque** — nouvelle : un service Rust supplémentaire avec accès HSM, mais sa surface
réseau exposée est nulle (socket Unix local uniquement) — c'est une réduction nette du risque
comparé à l'alternative rejetée (port TCP en clair). Nouveau modèle de menaces dédié
(`security/threat-models/audit-sealer.md`), premier composant du dépôt dont la surface réseau
volontaire est un socket Unix, pas un port.

**Limite d'environnement** — `tokio::net::UnixListener`/`tokio_stream::wrappers::UnixListenerStream`
n'existent que sous `cfg(unix)`, une limitation de plateforme réelle, pas une limitation de
fonctionnalité Cargo. La logique réelle de `main.rs` est isolée dans un module `#[cfg(unix)]` ;
un module `#[cfg(not(unix))]` distinct affiche une erreur et sort en échec sur toute autre
plateforme — ce choix garde `cargo build --workspace` utilisable sur un poste Windows (le reste
du workspace compile normalement) sans faire croire que ce binaire précis fonctionne hors
Linux/macOS. Non vérifié en exécution réelle sur ce poste (aucune cible Rust Linux installée) —
à confirmer en CI Linux avant tout déploiement.

## Critère de réexamen

Réexaminer l'écrivain unique par `authority_domain` dès que le câblage des trois producteurs Go
introduit des appelants concurrents à `audit-collector`. Réexaminer la portée
`policy.decided`/`credential.issued` non scellés dès qu'une extension de `AuditEventFields` avec
un champ `decision` est instruite séparément (`referent-crypto`). Réexaminer le socket Unix dès
que SPIFFE/SPIRE est câblé dans ce dépôt — pourrait alors migrer vers mTLS sur un port dédié
sans perdre la garantie d'authentification de l'appelant.
