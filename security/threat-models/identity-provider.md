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
| Structure d'attestation (CBOR) | Authentificateur, via navigateur | `zs-webauthn` (parseur d'attestation) | Prévu backlog L1.1 — pas encore écrit |
| Assertion signée (authentification) | Authentificateur, via navigateur | `zs-webauthn` (vérification de signature via `zs-crypto`) | Prévu backlog L1.2 |
| `origin` / `rpId` déclarés par le client | Navigateur (client_data_json) | `zs-webauthn` | Non — validation par comparaison stricte, pas de parseur complexe à fuzzer, revu en priorité 5.1 si un format enrichi est introduit |
| Challenge retourné par le client | Navigateur | Comparaison en mémoire côté serveur (émis puis vérifié par l'IdP lui-même) | Sans objet — pas un analyseur de format |
| Requête de révocation / récupération | `admin-api` (interne, mTLS) | Vérification de quorum (backlog L1.3) | Prévu, corrélé à l'analyseur de quorum quand il existera |

Toute entrée non fiable sans analyseur identifié est un angle mort : ici, le parseur
d'attestation CBOR est le point le plus exposé (format binaire, source externe non fiable) et
n'a pas encore de code — c'est une dette explicite avant tout déploiement, pas une case vide.

## STRIDE

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | Attaquant hameçonne l'utilisateur vers un domaine visuellement proche pour capturer une assertion | Faible (WebAuthn lie l'assertion à l'origine par construction — scénario 1) | Élevé si contourné | Vérification stricte de `origin`/`rpId` dans `zs-webauthn`, refus par défaut si absent ou non concordant | Un navigateur ou un client compromis en amont (extension malveillante interceptant l'API WebAuthn) reste hors du périmètre protégé par le protocole lui-même |
| **T**ampering | Modification du compteur de signature stocké pour masquer un clonage d'authentificateur | Faible (accès direct à `identity` requis) | Élevé (clonage non détecté = usurpation durable) | Compteur vérifié strictement croissant à chaque assertion (backlog L1.2), rôle applicatif au principe du moindre privilège sur le schéma `identity` | Une compromission du rôle applicatif PostgreSQL avec droits d'écriture pourrait falsifier le compteur avant sa lecture — mesure compensatoire : événement d'audit signé indépendamment à chaque vérification, permettant la détection a posteriori par rejeu (`make replay`) |
| **R**epudiation | Un enregistrement ou une révocation est contesté a posteriori | Faible | Moyen (perte de confiance dans l'historique) | Chaque action du parcours produit un événement d'audit signé et chaîné (backlog L1.4), horodaté par `audit-collector` | La fenêtre entre l'action et son inscription dans le journal (latence réseau `identity-provider` → `audit-collector`) reste un intervalle non couvert si l'IdP est compromis avant l'envoi — voir hypothèse de sécurité ci-dessous |
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
| Hameçonnage (scénario 1) | `tests/adversarial/` — assertion avec `origin` falsifié | Non écrit — backlog L1.1 |
| Rejeu de challenge | `tests/adversarial/` — challenge réutilisé après consommation | Non écrit — backlog L1.1 |
| Clonage d'authentificateur | `tests/adversarial/` — compteur de signature régressif | Non écrit — backlog L1.2 |
| Attestation absente alors qu'exigée | `tests/adversarial/` — politique d'attestation stricte, requête sans attestation | Non écrit — backlog L1.1 |

Quatre menaces identifiées, zéro test écrit à ce jour : ce composant reste **théorique** tant
que L1.1/L1.2 ne sont pas livrés. Ne pas déployer avant.

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

- Le HSM (via `zs-hsm`/`credential-issuer`) protège les clés utilisées pour signer les
  assertions d'identité ; `identity-provider` ne vérifie pas lui-même l'intégrité du HSM.
- L'horloge système est synchronisée (NTP) — la validité temporelle des challenges et des
  assertions en dépend directement.
- Le canal navigateur ↔ `identity-provider` est en TLS ; ce composant ne compense pas
  l'absence de TLS en amont.
- `audit-collector` est disponible et accepte les événements dans un délai borné ; en cas
  d'indisponibilité prolongée, le comportement (bloquer l'action ou l'autoriser sans preuve
  d'audit immédiate) n'est pas encore spécifié — à trancher avant L1.4.
