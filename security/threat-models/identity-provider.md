# Modèle de menaces — identity-provider

**Dernière révision** : 2026-08-22 — **Déclencheur** : lot L0.5, avant tout code L1

## Périmètre

WebAuthn/FIDO2 : enregistrement d'authentificateur, vérification d'assertion, cycle de vie
(révocation, récupération à quorum), émission d'assertions d'identité signées. **Ne décide
d'aucune autorisation** — l'assertion signée est un fait d'authentification, pas une décision
d'accès ; celle-ci reste au `policy-engine`.

Frontières de confiance traversées : navigateur/authentificateur (non fiable, protocole WebAuthn)
→ `identity-provider` (Rust, réseau public ou périmétré selon déploiement) → `crates/zs-crypto`
(vérification de signature) → schéma `identity` PostgreSQL → `audit-collector` (gRPC interne,
mTLS SPIFFE).

## Actifs

- Clés publiques et compteurs de signature des authentificateurs enregistrés (intégrité —
  leur falsification ouvrirait un rejeu ou masquerait un clonage).
- Challenges d'enregistrement/authentification en cours (confidentialité et unicité — un
  challenge prévisible ou réutilisable casse la garantie anti-rejeu du protocole).
- La capacité même d'émettre une assertion signée (c'est la primitive de confiance de tout le
  système ; sa compromission est le scénario 6 de `docs/architecture.md`).
- Disponibilité du service : un IdP indisponible bloque tout nouvel accès JIT.

## Entrées non fiables

| Entrée | Origine | Analyseur | Couverte par fuzzing ? |
|---|---|---|---|
| Structure d'attestation (CBOR) | Authentificateur, via navigateur | `zs-webauthn` (parseur d'attestation) | Écrit — `crates/zs-webauthn/fuzz/fuzz_targets/attestation_parser.rs`, non exécuté sur ce poste (libFuzzer/ASan indisponible sous Windows), à lancer en CI/GitHub Actions |
| Assertion signée (authentification) | Authentificateur, via navigateur | `zs-webauthn` (vérification de signature via `zs-crypto`) | Non — mêmes structures binaires que l'attestation, pas d'analyseur distinct ; couverte par les tests unitaires d'`authentication.rs` (L1.2a) |
| `origin` / `rpId` déclarés par le client | Navigateur (client_data_json) | `zs-webauthn` | Non — validation par comparaison stricte, pas de parseur complexe à fuzzer, revu en priorité 5.1 si un format enrichi est introduit |
| Challenge retourné par le client | Navigateur | Comparaison en mémoire côté serveur (émis puis vérifié par l'IdP lui-même) | Sans objet — pas un analyseur de format |
| Requête de révocation / récupération | `admin-api` (interne, mTLS) | `crates/zs-webauthn::recovery::verify_quorum` (L1.3, ADR-009) — comptage de porteurs distincts, aucune structure binaire complexe à fuzzer | Sans objet — pas un analyseur de format |

Toute entrée non fiable sans analyseur identifié est un angle mort : ici, le parseur
d'attestation CBOR est le point le plus exposé (format binaire, source externe non fiable) et
n'a pas encore de code — c'est une dette explicite avant tout déploiement, pas une case vide.

## STRIDE

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | Attaquant hameçonne l'utilisateur vers un domaine visuellement proche pour capturer une assertion | Faible (WebAuthn lie l'assertion à l'origine par construction — scénario 1) | Élevé si contourné | Vérification stricte de `origin`/`rpId` dans `zs-webauthn`, refus par défaut si absent ou non concordant | Un navigateur ou un client compromis en amont (extension malveillante interceptant l'API WebAuthn) reste hors du périmètre protégé par le protocole lui-même |
| **T**ampering | Modification du compteur de signature stocké pour masquer un clonage d'authentificateur | Faible (accès direct à `identity` requis) | Élevé (clonage non détecté = usurpation durable) | Compteur vérifié strictement croissant à chaque assertion, refus si `signCount ≤ stored` (`crates/zs-webauthn/src/authentication.rs`, L1.2). `counter_supported` figé une fois à l'enregistrement (migration 004), jamais réévalué par assertion — sans ça, un authentificateur cloné qui force `signCount=0` désactiverait rétroactivement la détection pour un authentificateur qui la supportait (mise en garde `referent-crypto`) ; rôle applicatif au principe du moindre privilège sur le schéma `identity` | Une compromission du rôle applicatif PostgreSQL avec droits d'écriture pourrait falsifier le compteur avant sa lecture — mesure compensatoire : événement d'audit signé indépendamment à chaque vérification, permettant la détection a posteriori par rejeu (`make replay`). Le contrat d'atomicité de l'avance (`SignCounterStore::advance`, `store.rs`) est posé mais son implémentation réelle reste à brancher (hors périmètre bibliothèque, L1.2a) |
| **R**epudiation | Un enregistrement ou une révocation est contesté a posteriori | Faible | Moyen (perte de confiance dans l'historique) | Chaque action du parcours produit un événement d'audit chaîné (`crates/zs-audit`, L1.4a — construction, sérialisation canonique RFC 8785, `verify_chain`), horodaté par `audit-collector`. **Scellement cryptographique réel non fait** (`audit-seal/v1`, ADR-010) : bloqué sur l'intégration HSM (prérequis H1, partagé avec `identity-assertion`/L1.2c), différé à L1.4b | La fenêtre entre l'action et son inscription dans le journal (latence réseau `identity-provider` → `audit-collector`) reste un intervalle non couvert si l'IdP est compromis avant l'envoi — voir hypothèse de sécurité ci-dessous. Tant que L1.4b n'est pas fait, un événement chaîné mais non scellé n'a **aucune valeur probante contre un attaquant qui contrôle le stockage** : seule la signature HSM rend la falsification détectable, le chaînage seul ne protège que contre une réorganisation accidentelle |
| **I**nformation Disclosure | Fuite de challenges en cours ou de métadonnées d'authentificateur via un journal ou une erreur verbeuse | Moyenne (erreur de développement classique) | Faible à moyen (pas de secret durable ici — seules des clés publiques et compteurs) | Aucune clé privée ne transite jamais par ce composant ; règle absolue #1 du `CLAUDE.md` (aucun secret en journal), revue de code systématique sur les messages d'erreur | Une fuite de métadonnées (quels authentificateurs, quand) reste possible et facilite un ciblage social ultérieur — non éliminée, seulement réduite |
| **D**enial of Service | Flot de demandes d'enregistrement ou d'authentification, ou challenges expirés non nettoyés | Moyenne | Moyen (bloque l'accès JIT le temps de l'incident) | Challenges à expiration courte et usage unique (backlog L1.1), limitation de débit au niveau du plan de données (à spécifier en L2+) | La disponibilité de l'IdP reste un point de défaillance unique structurel pour tout nouvel accès — assumé, voir « Limites assumées » de `docs/architecture.md` |
| **E**levation of Privilege | Un authentificateur enregistré pour un principal accède avec un niveau AAL supérieur à celui réellement atteint | Faible | Élevé (contournerait le contrôle AAL3 pour les accès privilégiés) | Le niveau AAL est déterminé par la méthode d'authentification effectivement vérifiée, jamais déclaré par le client ; porté dans l'assertion signée, pas recalculé en aval | Si `zs-webauthn` mappe incorrectement une méthode faible vers un AAL élevé (bug de classification), aucune couche suivante ne le détecterait — mesure compensatoire à ajouter : test de conformité explicite mappant chaque méthode WebAuthn à son AAL attendu (backlog L1.2) |

## LINDDUN — volet vie privée

Traite des identifiants de compte (subject_id) et des métadonnées d'authentificateur (méthode,
horodatage de dernière authentification). Non applicable pour la donnée biométrique : le
gabarit biométrique reste dans l'authentificateur matériel, jamais transmis ni stocké
côté serveur (contrainte RGPD du `CLAUDE.md` racine). Linkability : le `subject_id` stable
permet de corréler l'activité d'un même principal à travers le journal d'audit — c'est
l'objectif recherché (traçabilité), pas une fuite ; le risque résiduel est la conservation de
cette corrélation au-delà de la durée nécessaire, à traiter dans la politique de rétention de
`audit-collector`, pas ici.

## Scénarios d'attaque testés

| Menace | Test | Statut |
|---|---|---|
| Hameçonnage (scénario 1) | `crates/zs-webauthn/src/client_data.rs::origin_incorrecte_est_refusee` | Écrit — L1.1 |
| Rejeu de challenge | `crates/zs-webauthn/src/client_data.rs::challenge_rejoue_est_refuse`, `registration.rs::challenge_rejoue_est_refuse` | Écrit — L1.1 |
| Attestation absente alors qu'exigée | `crates/zs-webauthn/src/registration.rs::attestation_absente_alors_quexigee_est_refusee` | Écrit — L1.1 |
| Format d'attestation non supporté | `crates/zs-webauthn/src/registration.rs::format_attestation_non_supporte_est_refuse_explicitement` | Écrit — L1.1 |
| `rpId` incorrect | `crates/zs-webauthn/src/registration.rs::rp_id_incorrect_est_refuse` | Écrit — L1.1 |
| Signature d'attestation invalide | `crates/zs-webauthn/src/registration.rs::signature_attestation_packed_invalide_est_refusee` | Écrit — L1.1 |
| Attestation binaire malformée (CBOR non canonique, taille excessive) | `crates/zs-webauthn/fuzz/fuzz_targets/attestation_parser.rs` | Écrit — non exécuté ici (libFuzzer/ASan indisponible sur ce poste Windows), à lancer en CI/GitHub Actions (Linux) |
| Clonage d'authentificateur (compteur régressif) | `crates/zs-webauthn/src/authentication.rs::{compteur_regressif_est_refuse,compteur_identique_est_refuse}` | Écrit — L1.2a |
| Rejeu d'assertion d'authentification (challenge) | `crates/zs-webauthn/src/authentication.rs::challenge_rejoue_est_refuse` | Écrit — L1.2a |
| Confusion de cérémonie (`webauthn.create` rejoué comme `webauthn.get`) | `crates/zs-webauthn/src/authentication.rs::confusion_de_ceremonie_est_refusee` | Écrit — L1.2a |
| Authentificateur révoqué toujours accepté | `crates/zs-webauthn/src/authentication.rs::authentificateur_revoque_est_refuse_immediatement` | Écrit — L1.3 |
| Récupération déclenchée par un seul porteur | `crates/zs-webauthn/src/recovery.rs::un_seul_porteur_ne_peut_jamais_declencher_une_recuperation` | Écrit — L1.3 |
| Un même porteur compté plusieurs fois pour atteindre le quorum | `crates/zs-webauthn/src/recovery.rs::meme_porteur_repete_ne_compte_quune_fois` | Écrit — L1.3 |

Onze menaces ont désormais un test réel (33 tests unitaires dans `zs-webauthn`,
vérifiés avec des signatures ECDSA P-256 réelles, pas des doublures) : le clonage
d'authentificateur (compteur de signature), la révocation et le quorum de récupération sont
couverts par L1.2a/L1.3. Reste théorique/différé : l'émission de l'assertion d'identité
**signée** elle-même (ADR-007/ADR-008, L1.2c — intégration HSM non encore faite), la liaison
cryptographique entre approbations et une demande de récupération précise (ADR-009,
responsabilité de l'appelant), le scellement réel de l'événement de récupération (L1.4) et le
branchement réel des ports de stockage (`ChallengeStore`,
`SignCounterStore` — traits posés, implémentation hors périmètre bibliothèque).

## Limite structurelle assumée (scénario 6)

**Compromission de l'IdP** : `docs/architecture.md` la nomme explicitement comme **limite
structurelle assumée du modèle**, pas comme un risque résiduel ordinaire. Si `identity-provider`
lui-même est compromis (code exécuté par un attaquant avec les privilèges du processus), il peut
en principe émettre des assertions signées pour n'importe quel principal — aucune couche en aval
(`policy-engine`, `access-broker`, `credential-issuer`) ne peut distinguer une assertion
légitime d'une assertion forgée par un IdP compromis, puisque la vérification en aval consiste
précisément à vérifier que l'assertion est bien signée par l'IdP.

Mesures compensatoires existantes, aucune n'étant une élimination du risque :
- Le HSM protège la clé de signature elle-même (compromettre le processus ne donne pas
  automatiquement la clé si elle ne quitte jamais le HSM).
- Distribution de l'autorité (à spécifier — plusieurs instances, quorum de signature) et
  détection dédiée (SIEM sur l'activité anormale de l'IdP) sont mentionnées comme axes de
  traitement par `docs/architecture.md`, non encore implémentées.

**Ce risque n'est jamais présenté comme résolu.** Toute contribution qui laisserait entendre le
contraire (ex. un commentaire minimisant ce risque) doit être corrigée.

## Hypothèses de sécurité

- Le HSM (via `crates/zs-hsm`, appelé exclusivement par `crates/zs-crypto` — ADR-010/011, corrige
  une mention antérieure de `credential-issuer`) protège les clés utilisées pour signer les
  assertions d'identité et les événements d'audit ; `identity-provider` ne vérifie pas lui-même
  l'intégrité du HSM. Depuis H1 (ADR-011), l'indisponibilité du HSM (jeton absent, session
  perdue, pool saturé) est un **mode de panne par conception** : refus complet de l'action
  métier, jamais un repli logiciel ni une action qui réussirait sans signature — l'indisponibilité
  HSM devient donc une indisponibilité du système, décision assumée explicitement, pas découverte
  en incident.
- L'horloge système est synchronisée (NTP) — la validité temporelle des challenges et des
  assertions en dépend directement.
- Le canal navigateur ↔ `identity-provider` est en TLS ; ce composant ne compense pas
  l'absence de TLS en amont.
- `audit-collector` est disponible et accepte les événements dans un délai borné ; en cas
  d'indisponibilité prolongée, le comportement (bloquer l'action ou l'autoriser sans preuve
  d'audit immédiate) n'est pas encore spécifié — tranché pour la partie HSM (refus, voir
  ci-dessus, ADR-011) ; reste ouvert pour la partie transport vers `audit-collector` lui-même,
  à trancher avant L1.4b.

## Addendum (H5, ADR-023) — émission réelle, entrée HTTP

`identity-provider` cesse d'être un composant purement vérificateur : `apps/identity-provider/
src/httpapi.rs` scelle réellement des assertions `identity-assertion/v1` (`AssertionSealer::seal`)
et des événements `audit-seal/v1` (`AuditSealer::seal`) via `zs-hsm` — la « capacité même d'émettre
une assertion signée », déjà listée en actif ci-dessus, est désormais un chemin de code réel, pas
seulement une primitive de bibliothèque.

- **Nouvelle entrée non fiable** : 4 endpoints HTTP (`/v1/webauthn/{registration,authentication}/
  {challenge,verify}`), non authentifiés au niveau transport (pas de TLS dans ce lot, dette déjà
  assumée ailleurs — ADR-022). `Content-Length`/JSON malformé/champs `format: byte` mal encodés
  sont refusés par construction (parse strict, bornes de taille héritées de `zs-webauthn`).
- **Angle mort non résolu, signalé** : `RegistrationChallengeRequest.subject_id` est accepté tel
  quel, sans authentification préalable — le bootstrap du tout premier facteur d'un sujet n'est
  pas instruit dans ce lot (aucun mécanisme d'invitation/admin n'existe). Un attaquant qui connaît
  ou devine un `subject_id` peut initier un enregistrement à son nom ; seule la possession réelle
  d'un authentificateur limite l'impact (l'attaquant n'obtient qu'un credential *supplémentaire*
  sous ce `subject_id`, pas un accès à un credential existant). À trancher avant un déploiement
  réel — voir critère de réexamen de l'ADR-023.
- **Double scellement HSM par requête réussie** (assertion + événement d'audit) : la
  disponibilité HSM devient un mode de panne encore plus central pour ce composant qu'avant H5 —
  cohérent avec l'hypothèse déjà actée ci-dessus (refus complet, jamais de repli), mais la
  fréquence d'exposition à ce mode de panne augmente avec le trafic d'authentification réel.
- **Persistance nouvelle** : `identity.challenges`/`identity.authenticators` (déjà prévues,
  migration 003/004) sont désormais réellement écrites ; `audit.events.sealed_bytes` (migration
  005, H5) stocke les octets canoniques scellés pour permettre la dérivation du `prev_hash`
  suivant sans réimplémenter la canonicalisation JCS hors de `zs-crypto`.
