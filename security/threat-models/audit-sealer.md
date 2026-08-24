# Modèle de menaces — audit-sealer

**Dernière révision** : 2026-08-24 — **Déclencheur** : pont d'audit Rust↔Go, ADR-026

## Périmètre

Scellement d'un événement d'audit déjà construit — `AuditSealingService.Seal` (signature ECDSA
P-256 via HSM, `zs_crypto::audit_seal::AuditSealer`) et `AuditSealingService.HashPrevious`
(hachage SHA-256 des octets scellés d'un événement précédent, pour le calcul de `prev_hash` côté
Go). Sans état, sans Postgres, aucune logique de chaînage — reçoit des champs déjà calculés par
l'appelant (`sequence`, `prev_hash`, `event_id`, `occurred_at`).

**Premier composant du dépôt dont la surface réseau est délibérément un socket Unix, pas un
port TCP** — décision de conception documentée en ADR-026, pas une omission de TLS. Servi
uniquement sur `tokio::net::UnixListener`, joignable seulement par un processus colocalisé sur le
même hôte que le fichier de socket (permissions du système de fichiers comme contrôle d'accès
implicite, pas un mécanisme applicatif).

Frontières de confiance traversées : `audit-collector` (Go, seul appelant légitime, colocalisé)
→ socket Unix → `audit-sealer` (Rust) → `crates/zs-crypto`/`crates/zs-hsm` (HSM, PKCS#11).

## Actifs

- **La clé de signature `zs-audit-seal-v1`** (HSM, composante du CBOM). C'est l'actif le plus
  critique de tout le pont : sa compromission permettrait de fabriquer des événements d'audit
  arbitraires validement signés, invalidant la garantie de non-répudiation de tout le journal
  (scénario déjà identifié par ADR-010).
- **La capacité même d'invoquer `Seal`** — c'est exactement pourquoi ce composant n'est pas un
  service réseau ouvert : la capacité d'appel EST l'actif à protéger, indépendamment de la clé
  elle-même. Un appelant illégitime qui atteint le socket peut faire signer n'importe quel champ
  syntaxiquement valide, sans avoir besoin d'extraire la clé.
- Disponibilité du service : une indisponibilité d'`audit-sealer` bloque toute nouvelle écriture
  d'audit côté `audit-collector` — refus par défaut (règle absolue #2), jamais un événement non
  scellé persisté silencieusement.

## Entrées non fiables

| Entrée | Origine | Analyseur | Couverte par fuzzing ? |
|---|---|---|---|
| `SealRequest` (champs de l'événement) | `audit-collector`, seul appelant légitime (colocalisé) | Typage `AuditEventFields` (`bounded_ascii_string!`, `Sequence`, enums fermés) + tables de correspondance locales (`event_type_from_str`/`actor_kind_from_str`/`outcome_from_str`, dupliquées depuis `zs-crypto` — privées à ce crate) | Non prioritaire — appelant unique, colocalisé, pas une surface exposée à un tiers non authentifié |
| `HashPreviousRequest.sealed_bytes` | `audit-collector` | Aucune validation de structure — hachage opaque, `zs_audit::hash_sealed_event` ne décode pas le contenu | Sans objet — pas un parseur |
| Accès au socket lui-même | Tout processus local avec permission sur le fichier de socket | Permissions du système de fichiers (déploiement), pas de contrôle applicatif supplémentaire | Sans objet |

L'entrée la plus critique n'est pas le contenu du `SealRequest` (déjà typé et borné) mais **le
fait même d'atteindre le socket** — un processus local malveillant avec les bonnes permissions
sur le fichier de socket obtient un accès équivalent à `audit-collector` lui-même. C'est un
risque résiduel structurel de la mesure retenue (voir STRIDE, Spoofing).

## STRIDE

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | Un processus local autre qu'`audit-collector` atteint le socket Unix et se fait passer pour l'appelant légitime | Faible (nécessite un accès local au même hôte, avec permission sur le fichier de socket) | Critique (signature d'événements arbitraires) | Permissions du système de fichiers sur le socket (déploiement — non instruit dans ce lot, à documenter en `deploy/`), colocalisation qui réduit la surface d'accès à un seul hôte plutôt qu'un réseau entier | Aucune authentification applicative de l'appelant au-delà des permissions du système de fichiers — un accès root local, ou une permission de socket mal configurée, contourne la mesure. Réexaminer dès que SPIFFE/SPIRE permet une authentification mTLS forte (ADR-026, critère de réexamen) |
| **T**ampering | Modification du `SealRequest` en transit | Très faible (socket Unix local, pas de segment réseau traversé) | Élevé si réussi | Aucun chiffrement en transit — jugé acceptable car le trajet ne quitte jamais le noyau de l'hôte (contrairement à un port TCP) | Un accès mémoire noyau privilégié (root) pourrait intercepter — hors modèle de menace de ce composant, cohérent avec le reste du dépôt (aucune protection contre un attaquant root local) |
| **R**epudiation | `audit-sealer` nie avoir scellé un événement qu'il a bien scellé | Sans objet | Sans objet | La signature elle-même est la preuve — pas de journal séparé côté `audit-sealer` | Sans objet |
| **I**nformation Disclosure | Fuite du contenu d'un événement en transit sur le socket | Faible (local, pas de segment réseau) | Moyen (mêmes données que celles déjà persistées côté `audit-collector`) | Aucune mesure dédiée — même surface que la persistance elle-même | Cohérent avec le modèle de menaces `audit-collector` : pas une exposition nouvelle |
| **D**enial of Service | Flot de requêtes `Seal` sature le pool HSM (`pool_size`, `acquire_timeout`) | Moyenne si `audit-collector` reçoit un pic de volume | Élevé pour l'ingestion d'audit (mais jamais pour le plan de données, découplé par construction) | `PoolExhausted` → erreur explicite (`Status::unavailable`), jamais un scellement dégradé ou une attente indéfinie | Un pic prolongé au-delà de la capacité du pool reste un déni de service pour l'audit — à borner par un objectif de service explicite, même limite que le modèle de menaces `audit-collector` |
| **E**levation of Privilege | Un appelant obtient, via le socket, une capacité au-delà du scellement (ex. lecture de la clé elle-même) | Très faible (l'API ne retourne jamais la clé, seulement des octets signés) | Critique si réussi | `zs-hsm`/`zs-crypto` n'exposent jamais la clé privée hors du HSM — même garantie que partout ailleurs dans le dépôt | Aucun connu au-delà des limites déjà documentées de `zs-hsm` |

## Scénarios d'attaque testés

| Menace | Test | Statut |
|---|---|---|
| `event_type`/`outcome`/`kind` inconnu du contrat | `apps/audit-sealer/src/lib.rs::tests::event_type_inconnu_est_refuse` | Écrit |
| `prev_hash` de mauvaise longueur | `apps/audit-sealer/src/lib.rs::tests::fields_from_request_refuse_un_prev_hash_de_mauvaise_longueur` | Écrit |
| Scellement réel via HSM (SoftHSM2), vecteurs de bout en bout | À écrire — `#[ignore]` par défaut, même discipline que `crates/zs-hsm/tests/pkcs11_integration.rs` (H1) | Non écrit — HSM non disponible sur ce poste |
| Épuisement du pool HSM sous charge | À écrire | Non écrit |

## Hypothèses de sécurité

- Le socket Unix n'est joignable que par des processus colocalisés sur le même hôte que
  `audit-collector`, avec des permissions de système de fichiers correctement restreintes au
  déploiement — non instruit dans ce lot (`deploy/`), traité comme hypothèse jusqu'à
  l'instruction du déploiement réel.
- Le HSM protège la clé `zs-audit-seal-v1` ; ce composant ne vérifie pas l'intégrité du HSM
  lui-même (même hypothèse que `policy-engine`/`identity-provider`).
- L'hôte lui-même n'est pas compromis — aucune protection contre un attaquant avec un accès
  root local, cohérent avec le reste du dépôt.
- `audit-collector` reste le seul appelant applicatif de ce service dans ce lot ; le critère de
  réexamen d'ADR-026 s'applique dès que ce n'est plus le cas.
