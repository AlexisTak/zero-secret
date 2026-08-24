# ADR-031 — Ancrage périodique du journal d'audit (`audit.chain_verified`)

**Statut** : proposé — Q1-Q10 toutes tranchées (2026-08-24). Une action de suivi reste ouverte
hors du périmètre de ce document : choix du prestataire d'horodatage RFC 3161 et de son budget
(Q2, différé au porteur du projet, même pattern que la Q2 d'ADR-030 pour les fournisseurs HSM).
**Date** : 2026-08-24
**Auteurs** : instruction `referent-crypto`, à relire par le porteur du projet.
**Lève** : la réserve posée par ADR-013 §« `audit.chain_verified` : type scellable, pas de
sémantique de charge utile », et la Q6 d'ADR-030.

## Contexte

### La limite prouvée

`zs_audit::chain::verify_chain` vérifie, domaine d'autorité par domaine d'autorité : racine à 64
zéros, séquence strictement croissante depuis 0, `prev_hash` égal au SHA-256 des octets scellés
du prédécesseur. Toute **modification**, **suppression interne** ou **insertion** dans la chaîne
est détectée (`BrokenLink`, `SequenceGap`).

Une seule attaque passe : **supprimer les k derniers événements d'un domaine**. La chaîne
restante est parfaitement valide à ses propres yeux. Ce n'est pas une hypothèse, c'est un test
qui échouerait si le comportement changeait :
`chain.rs::troncature_en_queue_de_chaine_nest_pas_detectee` (L1.4a, `docs/backlog.md`).

Le modèle de menaces d'`audit-collector` décrit précisément l'adversaire concerné : un accès
superutilisateur PostgreSQL contourne la révocation d'`UPDATE`/`DELETE` du rôle `audit_writer` ;
« seul le chaînage cryptographique resterait comme détection, pas comme prévention ». Or contre
une troncature en queue, **le chaînage ne détecte rien non plus**. C'est aujourd'hui le trou de
couverture le plus large du plan d'observation.

### Pourquoi un ancrage interne ne sert à rien

Un adversaire capable de supprimer les k derniers événements d'`audit.events` est, par
construction, capable de supprimer l'événement d'ancrage qui s'y trouve. Un ancrage stocké dans
la même base que ce qu'il ancre ne protège de rien. **La propriété utile n'est pas
cryptographique, elle est topologique : l'empreinte doit exister à un endroit que l'adversaire
du journal ne contrôle pas.** Tout le reste de cet ADR découle de ce constat.

### Ce qui existe déjà et qu'il ne faut pas refaire

- `event_type: "audit.chain_verified"` est déjà dans l'enum du contrat et dans les deux
  `EventType` (`zs_crypto::audit_seal`, `zs_audit::record`) — scellable, sans sémantique.
  ADR-013 a explicitement refusé d'improviser sa charge utile sous forme de `target.id`
  composite.
- Le motif « champ conditionnel couplé au type d'événement » est déjà implémenté et éprouvé :
  `decision` / `requires_decision()` / `validate_decision_coupling()`, vérifié en émission et en
  vérification, avec insertion conditionnelle (jamais de `null`) et borne de cardinalité
  explicite (`MAX_REASONS`). ADR-027/029.
- La contrainte `UNIQUE (authority_domain, sequence)` (migration 002) et `Store.ChainHead`
  donnent déjà la sérialisation nécessaire à l'insertion d'un ancrage dans la chaîne.

### Une incohérence de documentation à corriger au passage

`docs/architecture.md` (« chaînage Merkle ») et `security/threat-models/audit-collector.md`
(« chaînage Merkle rend toute modification détectable ») décrivent un mécanisme qui n'existe
pas : le code fait du chaînage séquentiel par `prev_hash`. Le modèle de menaces le signale
d'ailleurs lui-même plus haut (« pas encore de Merkle réel »). Cet ADR tranche que le Merkle
n'est pas la réponse au problème posé (voir Alternatives rejetées n°1) et impose la correction
du vocabulaire dans ces deux documents.

## Décision proposée

### 1. Charge utile probante : le minimum non dérivable, et rien de plus

L'ancrage est un événement ordinaire de la chaîne du domaine qu'il ancre, émis à la séquence `N`
du domaine `D`, scellé par la même clé HSM et la même suite que tous les autres.

Conséquence directe, et c'est le point de conception central : son `prev_hash` est déjà
l'empreinte de la tête de chaîne au moment de l'ancrage — SHA-256 des octets scellés complets de
l'événement `N−1`, signature incluse, lequel couvre récursivement tout le préfixe `[0, N−1]`.

**Il ne faut donc pas ajouter de champ `head_hash`.** Trois raisons, dans l'ordre d'importance :

1. Deux champs qui expriment la même chose peuvent diverger. Un vérificateur devrait alors
   décider lequel fait foi — exactement la classe de bug qu'ADR-012/013 a fermée en refusant que
   le message choisisse son vérificateur.
2. L'ancreur ne connaît pas la tête réelle. Entre sa lecture de `ChainHead` et l'insertion
   effective, d'autres événements peuvent s'intercaler (les trois producteurs Go écrivent en
   continu). Un `head_hash` calculé par l'ancreur serait périmé ; le `prev_hash` calculé par
   `audit-collector` au moment de l'`INSERT` est, lui, exact par construction.
3. Un champ redondant est un champ à valider, donc une branche de refus de plus, donc de la
   couverture à écrire pour rien.

Même raisonnement pour la borne haute de la plage : elle vaut toujours `sequence − 1`, invariant
à énoncer et à vérifier, pas un champ à transporter.

Restent deux informations réellement non dérivables du document lui-même :

| Champ | Pourquoi il est indispensable |
|---|---|
| `anchor.previous_anchor` = `{sequence, hash}` de l'ancrage précédent **du même domaine** | Crée une seconde chaîne, creuse, sur les seuls ancrages. Un tiers qui ne détient que le registre externe (pas la base) peut la vérifier entièrement. C'est elle qui rend détectable la disparition d'un ancrage entier. Elle définit aussi la borne basse de la plage couverte : `]previous_anchor.sequence, sequence[`. |
| `anchor.publications[]` = `{kind, locator, evidence_hash}` **de l'ancrage précédent** | Fait entrer la preuve de publication externe dans la chaîne scellée. Registre externe et chaîne interne s'accusent mutuellement. |
| `anchor.reason` (enum fermée) | Distingue un ancrage périodique d'un ancrage de bascule de suite (§5) ou demandé par un opérateur. Sans lui, ADR-030 aurait besoin d'un mécanisme distinct. |

Le décalage d'un cran sur `publications` est structurel, pas un oubli : un ancrage ne peut pas
attester de sa propre publication, qui lui est postérieure. Le formuler explicitement dans le
contrat évite qu'un relecteur le prenne pour un bug.

**Un ancrage par domaine d'autorité, jamais global.** Les chaînes sont indépendantes
(`verify_chain` les traite séparément, la contrainte d'unicité est `(authority_domain,
sequence)`), l'attaque est per-domaine, et un ancrage global devrait référencer N têtes
hétérogènes dans un champ que le contrat n'a pas — on retomberait dans l'improvisation
qu'ADR-013 a refusée. Quatre chaînes actives aujourd'hui : `identity-provider`,
`access-broker`, `admin-api`, `credential-issuer`.

**`outcome` porte le résultat de la vérification préalable** : `success` si `verify_chain` a
passé sur la plage couverte, `error` sinon. Un ancrage sur chaîne cassée doit quand même être
émis et publié, accompagné d'une alarme. La règle « refus par défaut » du projet porte sur
l'octroi d'un accès, pas sur la production d'une preuve : ici, refuser d'émettre produirait un
silence, c'est-à-dire précisément le signal que l'adversaire cherche à obtenir.

### 2. Publication externe : dépôt Git indépendant et horodatage RFC 3161

Avis argumenté, pas une liste neutre.

**(a) Dépôt Git séparé, hébergé hors de l'infrastructure du système — retenu comme socle.** On y
publie les octets scellés canoniques de l'événement d'ancrage, verbatim, un fichier par ancrage,
chemin `<authority_domain>/<sequence>.json`.

Le point décisif : ce dépôt n'a pas besoin d'être signé. L'authenticité de l'artefact vient
d'`audit-seal` (HSM), pas de Git. On évite ainsi d'introduire une clé de signature Git — qui
serait une clé cryptographique hors `zs-crypto` et hors HSM, en violation frontale de la règle
absolue n°4. Git n'est ici ni une autorité ni une racine de confiance : c'est un transport
répliqué et un témoin daté, dont le DAG de hachages fournit gratuitement un historique
inaltérable sans réécriture visible. Vérifiable par n'importe quel tiers avec `git`, `jq` et une
clé publique. Coût : nul. Réplication : `git clone` chez le RSSI, chez un CESTI, chez
l'association.

Limite honnête : la garantie repose entièrement sur l'indépendance administrative de
l'hébergement. Si la même personne administre la base Postgres et la forge, la protection
s'évanouit. Et Git ne prouve pas l'antériorité : une date de commit est déclarative.

**(b) Horodatage RFC 3161 auprès d'une autorité d'horodatage qualifiée eIDAS — retenu en
complément, c'est lui qui apporte ce que Git ne peut pas.** On horodate le SHA-256 des octets
scellés de l'ancrage ; on conserve le jeton ; son empreinte entre dans `publications[]` de
l'ancrage suivant. RFC 3161 + ETSI TS 319 421/422 sont des standards ouverts, et l'horodatage
qualifié bénéficie d'une présomption d'exactitude au titre d'eIDAS — c'est-à-dire une valeur
opposable devant un tiers, exactement l'usage visé (RSSI, CESTI, contentieux).

Trois réserves à assumer par écrit :
- C'est un appel réseau sortant vers un service externe payant : règle absolue n°10 et « ce que
  tu ne fais jamais sans validation explicite ». Il ne peut avoir lieu ni dans `policy-engine`
  (interdit), ni sur le chemin d'ingestion d'`audit-collector` (voir §3).
- Le jeton TSA est signé RSA ou ECDSA, non post-quantique, et son renouvellement n'est pas sous
  notre contrôle. La réponse normalisée à long terme est le re-horodatage périodique
  (RFC 4998, Evidence Record Syntax) — hors périmètre ici, mais à inscrire au registre de veille.
- Indisponibilité de l'AH : l'ancrage est quand même émis et publié dans (a), avec `publications`
  privé de l'entrée `rfc3161-timestamp` et une alarme. Jamais de blocage de l'ingestion, jamais
  de silence.

**(c) Notarisation blockchain publique — rejetée.** Ni infondée ni sans standard (OpenTimestamps
existe), mais : aucune reconnaissance ANSSI ou eIDAS, gouvernance et disponibilité non
maîtrisées, coût opérationnel et de conformité disproportionné pour une association loi 1901, et
un standard de fait n'est pas une norme au sens de la règle absolue n°6. La propriété
recherchée — un témoin indépendant et daté — est intégralement fournie par (a)+(b), avec un
dossier de qualification plus simple à défendre.

**(d) Export périodique signé remis hors bande à un tiers (RSSI, CESTI) — retenu comme procédure
organisationnelle, pas comme mécanisme.** Aucun mécanisme technique n'a de valeur si personne ne
conserve ni ne compare. Cadence proposée : mensuelle, contenu = le dépôt (a) à une révision
donnée, contre accusé de réception. C'est le volet qui transforme la publication en détention par
un tiers.

**(e) Journal de transparence type SCITT / reçus COSE — en veille, pas retenu.** C'est la
trajectoire normative naturelle de ce mécanisme, mais l'architecture est en Internet-Draft
(v22, oct. 2025, expiration déc. 2026). Figer un format probant sur un draft, c'est le refaire
dans deux ans. `publications[].kind` est une enum extensible : accueillir un `scitt-receipt`
plus tard ne cassera pas les ancrages existants.

**Recommandation ferme : (a) + (b) dès le premier lot, (d) en procédure, (c) rejeté, (e) en
veille.**

### 3. Cadence et déclencheur

Les deux critères, en disjonction : ancrer dès que `événements_depuis_dernier_ancrage ≥ N` OU
`maintenant − dernier_ancrage ≥ T`.

- Volume seul : une chaîne peu active (`admin-api`, quelques `quorum.operation` par mois) ne
  serait jamais ancrée, et sa troncature resterait indétectable indéfiniment.
- Temps seul : à l'hypothèse de charge retenue par ADR-030 (Q5, ~50 000 événements/jour), un
  ancrage horaire laisse ~2 000 événements tronçonnables.

**Valeurs proposées : `N = 1000`, `T = 1 h`, par domaine, configurables, plancher de sécurité
documenté.**

L'ancrage ne rend pas la troncature impossible, il la borne. La fenêtre résiduelle est
`min(N, activité pendant T)` événements. C'est un objectif de service mesurable : « au plus
1 000 événements ou 1 heure d'historique peuvent disparaître d'un domaine sans détection ». Toute
autre formulation serait une surpromesse.

**Qui déclenche : un composant séparé, pas `audit-collector`.** Deux raisons indépendantes,
chacune suffisante :

1. L'ancreur surveille l'écrivain. Faire porter l'ancrage par le processus qui écrit la chaîne,
   c'est lui demander de témoigner contre lui-même : un `audit-collector` compromis tronque et
   n'ancre pas.
2. La publication externe est un appel réseau sortant lent, faillible et hors du plan de données.
   Il n'a rien à faire sur le chemin d'ingestion, dont l'architecture à trois plans exige
   justement le découplage.

**Proposition : un binaire `apps/audit-anchor` (Go)**, qui (i) lit la chaîne avec un rôle
PostgreSQL `audit_reader` en lecture seule — il n'a jamais besoin d'`INSERT` —, (ii) la vérifie
via `verify_chain`, (iii) construit l'événement d'ancrage, (iv) le soumet à `audit-collector` par
le chemin gRPC `Record` ordinaire (donc `sequence`/`prev_hash` calculés par le collecteur,
scellement par `audit-sealer` sur socket Unix, aucune écriture directe en base), (v) publie à
l'extérieur, (vi) alarme sur tout échec.

Coût assumé : un artefact de plus dans `apps/`, avec la règle n°7 (aucune dépendance croisée
entre `apps/`) — le partage passe par `pkg/`. Un repli acceptable si ce coût est jugé trop élevé
à court terme : une goroutine d'`audit-collector` avec un pool Postgres distinct en lecture
seule — mais elle perd la propriété (1), qui est la principale. À trancher (Q3).

**Procédure de vérification par un tiers** — c'est elle qui donne sa valeur à tout le reste, donc
elle est normative, pas indicative :

1. Pour chaque ancrage publié dans le registre externe : recalculer SHA-256 de ses octets,
   vérifier la signature `audit-seal` avec la clé publique du domaine.
2. Vérifier que la chaîne creuse des ancrages est continue : `anchor.previous_anchor.hash` =
   SHA-256 des octets de l'ancrage publié précédent, `previous_anchor.sequence` strictement
   croissante.
3. Confronter au journal : pour chaque ancrage publié à la séquence `S` du domaine `D`,
   l'événement `(D, S)` doit exister en base avec exactement les mêmes octets.
4. Le contrôle qui détecte la troncature : la tête de chaîne actuelle de `D` doit avoir une
   séquence ≥ à celle du dernier ancrage publié pour `D`. Sinon : troncature avérée.
5. `verify_chain` sur l'intervalle `]previous_anchor.sequence, sequence[` de chaque ancrage.

### 4. Format exact — contrat `contracts/events/audit-event.schema.json`

Extension additive : `event_type` est inchangé (`audit.chain_verified` y est déjà),
`schema_version` reste `1`, aucun événement existant ne devient invalide. Même style que
`decision` : `additionalProperties: false`, bornes explicites, jamais de `null`.

```json
"anchor": {
  "type": "object",
  "description": "Présent si et seulement si event_type = audit.chain_verified. Couplage bidirectionnel non exprimable en JSON Schema (additionalProperties ne dépend pas d'un autre champ) : vérifié dans zs-crypto en émission ET en vérification, comme decision (ADR-027/029). Couvre l'intervalle ]previous_anchor.sequence, sequence[ du même authority_domain. L'empreinte de tête de cet intervalle est le prev_hash de CET événement — jamais dupliquée ici : deux champs redondants peuvent diverger, et l'ancreur ne connaît pas la tête réelle au moment où il construit l'événement (ADR-031).",
  "additionalProperties": false,
  "required": ["reason"],
  "properties": {
    "reason": {
      "type": "string",
      "enum": ["periodic", "suite_transition", "operator_requested"]
    },
    "previous_anchor": {
      "type": "object",
      "description": "Ancrage précédent du MÊME domaine — chaîne creuse vérifiable à partir du seul registre externe. Absent (jamais null) pour le premier ancrage d'un domaine : l'omission fait partie des octets signés, donc n'est pas falsifiable.",
      "additionalProperties": false,
      "required": ["sequence", "hash"],
      "properties": {
        "sequence": { "type": "integer", "minimum": 0 },
        "hash": {
          "type": "string",
          "pattern": "^[0-9a-f]{64}$",
          "description": "SHA-256 des octets canoniques scellés de l'ancrage précédent, signature incluse — même construction que prev_hash."
        }
      }
    },
    "publications": {
      "type": "array",
      "maxItems": 4,
      "description": "Publications externes constatées de l'ancrage PRÉCÉDENT. Le décalage d'un cran est structurel : un ancrage ne peut pas attester de sa propre publication, qui lui est postérieure. Tableau borné dès v1 pour accueillir un registre supplémentaire (ex. reçu SCITT) sans modifier le contrat — même pari que le conteneur signature à N composantes d'ADR-012/013.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "locator", "evidence_hash"],
        "properties": {
          "kind": {
            "type": "string",
            "enum": ["git-repository", "rfc3161-timestamp", "out-of-band-export"]
          },
          "locator": {
            "type": "string",
            "maxLength": 256,
            "description": "Référence opaque et stable dans le registre : identifiant de commit Git, référence de jeton d'horodatage, référence d'accusé de réception. Jamais une URL portant un secret ni une donnée personnelle."
          },
          "evidence_hash": {
            "type": "string",
            "pattern": "^[0-9a-f]{64}$",
            "description": "SHA-256 de la preuve elle-même (objet Git publié, jeton RFC 3161 DER, export signé)."
          }
        }
      }
    }
  }
}
```

Côté `crates/zs-crypto/src/audit_seal.rs`, strictement calqué sur `decision` :

- `pub struct AnchorInfo { reason: AnchorReason, previous_anchor: Option<PreviousAnchor>,
  publications: Vec<Publication> }` ; `PreviousAnchor { sequence: Sequence, hash: [u8; 32] }` ;
  `Publication { kind: PublicationKind, locator: PublicationLocator, evidence_hash: [u8; 32] }`.
- `bounded_ascii_string!(PublicationLocator, 256, "anchor.publications.locator")`.
- `const MAX_PUBLICATIONS: usize = 4;` — même rôle que `MAX_REASONS` : sans borne, un événement
  peut être scellé, chaîné, persisté, puis refusé en vérification, ce qui est une rupture de
  chaîne définitive et non un refus sain.
- `EventType::requires_anchor()` → `matches!(self, EventType::AuditChainVerified)`, et le champ
  `anchor` est interdit sur tout autre type.
- `validate_anchor_coupling()` appelé dans `seal()`, contrôle miroir dans `verify()` —
  exactement la construction de `validate_decision_coupling`, avec la même justification : un
  vérificateur hors ligne ne doit jamais obtenir un `audit.chain_verified` dépourvu de charge
  utile, quelle que soit la configuration de l'émetteur.
- `anchor_value()` par insertion conditionnelle (jamais de `null`) et son miroir dans
  `unsigned_document_from_wire()` — le bug corrigé lors d'ADR-027 (`actor_value`/`context_value`)
  se reproduirait à l'identique ici s'il était oublié d'un seul côté.
- Contrôles supplémentaires en vérification, sans court-circuit :
  `previous_anchor.sequence < sequence`, longueurs de hash = 32 octets,
  `publications.len() ≤ MAX_PUBLICATIONS`.
- `Sequence` reste borné à 2^53−1 : inchangé.

**Plan de test** (couverture ≥ 95 % sur `zs-crypto`, cas nominal et cas adverse pour chacun) :

| Cas | Attendu |
|---|---|
| Ancrage nominal scellé puis vérifié, validé contre le JSON Schema | accepté (miroir de `policy_decided_valide_le_contrat`) |
| Premier ancrage d'un domaine, `previous_anchor` absent | accepté, et les octets ne contiennent aucun `null` |
| `anchor` absent sur `audit.chain_verified` | refusé au scellement et à la vérification |
| `anchor` présent sur tout autre `event_type` | refusé au scellement et à la vérification |
| `publications` à 5 entrées | refusé des deux côtés |
| `previous_anchor.hash` falsifié dans les octets | `InvalidSignature` (miroir de `decision_hash_falsifie_...`) |
| `previous_anchor.sequence ≥ sequence` | `MalformedDocument` |
| Vecteurs figés : chaîne de 3 événements + 1 ancrage, dans `tests/vectors/audit-seal-v1/` | comparaison bit à bit |
| Chaîne tronquée après un ancrage publié | détectée par la procédure §3, à écrire dans `tests/adversarial/` — c'est le test qui justifie cet ADR, pendant explicite de `troncature_en_queue_de_chaine_nest_pas_detectee` |
| Ancrage publié absent du journal | détecté |
| Ancrage retiré du registre externe | détecté par la chaîne creuse (`previous_anchor` de l'ancrage suivant) |
| AH RFC 3161 indisponible | ancrage émis sans l'entrée, alarme, jamais de blocage ni de silence |
| Fuzzing : `anchor` ajouté à la cible existante de `audit_seal::verify` | aucun panic |

### 5. Articulation avec `audit-seal/v2` (ADR-030 §6(b), Q6)

La bascule v1→v2 devient un cas d'usage de ce mécanisme, sans une ligne de code spécifique :

**L'événement charnière d'ADR-030 est un ancrage `reason: "suite_transition"`, scellé sous
`audit-seal/v2`, dont le `prev_hash` couvre le dernier événement v1 du domaine.**

- La propriété recherchée par ADR-030 est obtenue telle quelle : un adversaire disposant d'un
  CRQC peut forger une signature ECDSA sur un événement v1 isolé, mais ne peut pas le réinsérer
  dans la chaîne sans casser le `prev_hash` scellé en ML-DSA de l'ancrage charnière.
- La date de bascule `T` d'ADR-030 (Q9/O4) se définit sans ambiguïté : `T` = la séquence de
  l'ancrage `suite_transition` de chaque domaine. Un vérificateur applique la règle « tout
  événement de séquence ≥ `T` doit être en v2 » en lisant la chaîne seule, hors ligne, sans
  horloge — ce qu'une date calendaire ne permet pas. **Cela clôt Q9 en faveur de la séquence.**
- Bénéfice non prévu par ADR-030 : la charnière est publiée à l'extérieur comme tout autre
  ancrage. Un tiers peut donc constater la date et le contenu de la bascule sans faire confiance
  à l'exploitant.
- Un domaine ayant `previous_anchor` renseigné dans sa charnière rattache la bascule à
  l'historique v1 ancré ; un domaine encore jamais ancré l'omet.

**Ordre d'implémentation imposé** : ADR-031 avant ADR-030. Ce dernier ne peut pas passer à
« accepté » tant que le mécanisme dont dépend son point 7 n'existe pas. Sa Q6 est levée par le
présent document.

**Point de vigilance dimensionnel** : sous `audit-seal/v2`, un ancrage nominal pèsera ~7,7 Kio
comme tout autre événement (+6 683 octets de signature hybride, ADR-030 §4). À `N = 1000`,
l'ancrage représente ~0,1 % du volume du journal : négligeable. Le mécanisme ne pèse pas sur la
volumétrie, il pèse sur l'exploitation.

### 6. Impact mesuré

**Taille — mesurée par comptage exact des octets JCS** (les clés étant triées et les longueurs
de chaînes connues, la sérialisation canonique est déterministe ; ce n'est pas une estimation) :

| Configuration du bloc `anchor` | Octets ajoutés au document |
|---|---|
| `previous_anchor` + 1 publication `rfc3161-timestamp`, locator 64 car. | 349 |
| idem + 2ᵉ publication `git-repository`, locator 64 car. | 538 |
| pire cas contractuel : 4 publications, locators à 256 car. | 1 688 |

Événement d'ancrage complet, sous `audit-seal/v1` : environ 400 octets de document de base
(`actor` système, pas de `target`, pas de `context`) + 349 + 247 de signature ≈ 1,0 Kio ; pire
cas ≈ 2,3 Kio. `MAX_BYTES_V1 = 8192` reste inchangé — aucune modification de borne n'est
nécessaire, contrairement à ce qu'exigeait `audit-seal/v2`. Sous v2 : ≈ 7,7 Kio nominal,
largement sous le `MAX_BYTES_V2 = 32768` proposé par ADR-030.

**Latence — à mesurer, non estimée** (`crates/zs-crypto/CLAUDE.md` l'exige) :
1. Coût HSM : +1 signature `audit-seal` par tranche de `N` événements. À `N = 1000`, +0,1 %
   d'opérations HSM. À confirmer, sans attente d'effet.
2. Coût de `verify_chain` sur un intervalle de `N` événements, en incluant la bascule TOAST de
   `sealed_bytes` en v2 (ADR-030 §4) — c'est le coût dominant du mécanisme, pas la signature. À
   mesurer à `N` = 1 000 / 10 000 / 100 000.
3. Latence de l'appel RFC 3161 (p50/p95/p99) et comportement au délai d'expiration — hors chemin
   d'ingestion, donc sans effet sur le plan de données, mais dimensionnant pour la fenêtre `T`.
4. Croissance du dépôt Git : ~1 Kio (v1) à ~7,7 Kio (v2) par ancrage et par domaine ; à
   `N = 1000` sur l'hypothèse de charge d'ADR-030 (Q5), l'ordre de grandeur reste inférieur à
   1 Go sur 5 ans. À recaler sur charge réelle.

### 7. Entrée CBOM

`security/crypto-inventory/cbom.json` — aucune suite nouvelle, mais deux composants à déclarer,
dont un pour ce qu'il n'est pas :

```json
{
  "bom-ref": "operation/audit-anchor/v1",
  "type": "cryptographic-asset",
  "name": "audit-anchor/v1",
  "cryptoProperties": { "assetType": "protocol", "protocolProperties": {} },
  "properties": [
    { "name": "zs:suite", "value": "audit-seal/v1" },
    { "name": "zs:role", "value": "emission" },
    { "name": "zs:execution-environment", "value": "hardware" },
    { "name": "zs:anssi-2027-compliant", "value": "false" },
    { "name": "zs:note", "value": "Ancrage periodique (ADR-031) : aucune primitive propre, reutilise integralement audit-seal. Devient conforme 2027 avec audit-seal/v2 (ADR-030), sans changement de mecanisme." }
  ]
},
{
  "bom-ref": "external/rfc3161-timestamp-authority",
  "type": "cryptographic-asset",
  "name": "rfc3161-timestamp-authority",
  "cryptoProperties": { "assetType": "protocol", "protocolProperties": {} },
  "properties": [
    { "name": "zs:role", "value": "external-witness" },
    { "name": "zs:execution-environment", "value": "external" },
    { "name": "zs:anssi-2027-compliant", "value": "false" },
    { "name": "zs:note", "value": "Jeton signe par un tiers (RSA ou ECDSA, non PQC, hors de notre controle). Conserve et reference par empreinte, JAMAIS verifie par du code de ce depot : le verifier exigerait un analyseur CMS dans zs-crypto, donc une suite dediee et un ADR. Re-horodatage long terme (RFC 4998 ERS) : hors perimetre, en veille." }
  ]
}
```

Le second est essentiel pour un auditeur : il déclare une dépendance cryptographique externe non
post-quantique que nous n'avons pas la capacité de faire évoluer, et il documente le refus
délibéré d'importer un analyseur CMS.

## Conséquences

**Positives**
- La seule attaque non couverte par `verify_chain` devient détectable, avec une fenêtre
  résiduelle bornée et énonçable comme objectif de service.
- Zéro nouvelle primitive, zéro nouvelle suite, zéro nouvelle clé, zéro nouvelle dépendance
  Rust. La règle « on compose, on n'écrit pas » est respectée sans effort — l'ancrage n'était
  jamais un problème de cryptographie.
- Zéro rupture de contrat : extension additive, `schema_version` reste `1`, l'historique déjà
  scellé reste valide.
- ADR-030 §6(b) et Q6/Q9 sont résolus sans mécanisme dédié ; `T` devient vérifiable hors ligne.
- Un tiers (RSSI, CESTI, red team) peut vérifier l'intégrité du journal sans accès à
  l'infrastructure, avec `git`, `sha256sum` et une clé publique. C'est un argument de
  qualification, pas seulement une propriété technique.
- Le registre externe est un artefact d'audit réutilisable directement dans un dossier CSPN/CC.

**Négatives — assumées**
- La garantie est organisationnelle autant que technique. Si l'exploitant contrôle la base et la
  forge et la relation avec l'AH, l'ancrage ne prouve plus grand-chose. Aucune construction
  cryptographique ne corrige cela ; seule la séparation des administrations le fait. À écrire
  noir sur blanc dans le modèle de menaces plutôt qu'à laisser croire à une preuve absolue.
- Un artefact de plus dans `apps/` (`audit-anchor`), son quadlet, son runbook, son alarme, sa
  supervision.
- Un appel réseau sortant nouveau vers un service tiers payant — validation humaine explicite
  requise (règles absolues n°10 et « ce que tu ne fais jamais sans validation »).
- Une exigence d'exploitation continue : un mécanisme d'ancrage en panne silencieuse est pire
  qu'aucun ancrage, parce qu'il inspire une confiance non fondée. La supervision de l'ancreur
  devient elle-même critique.
- Les événements antérieurs au premier ancrage restent définitivement tronçonnables sans
  détection. Non rattrapable : plus tôt le mécanisme existe, plus petite est cette fenêtre.
- La chaîne creuse des ancrages est un second invariant à maintenir et à tester.
- `publications` référence l'ancrage précédent : lecture contre-intuitive, source d'erreur
  d'interprétation en revue. D'où la description explicite dans le contrat.

## Alternatives rejetées

1. **Arbre de Merkle sur la chaîne, avec `merkle_root` dans l'ancrage.** Rejeté pour ce problème.
   Le chaînage `prev_hash` engage déjà l'intégralité du préfixe : une racine de Merkle n'ajoute
   strictement rien à la détection de troncature. Ce qu'elle apporterait est une autre
   propriété — des preuves d'inclusion permettant à un tiers de vérifier un événement isolé sans
   rejouer la chaîne entière (RFC 9162, SCITT). Propriété réelle et souhaitable, à instruire par
   un ADR dédié le jour où un consommateur en a besoin ; l'introduire ici serait de la
   complexité contractuelle sans bénéfice sur le problème posé. Corollaire imposé : corriger
   `docs/architecture.md` et `security/threat-models/audit-collector.md`, qui décrivent
   aujourd'hui un chaînage Merkle inexistant.
2. **`head_hash` explicite dans la charge utile.** Rejeté : duplique `prev_hash`, crée une
   possibilité de divergence, et serait calculé par l'ancreur sur une tête potentiellement
   périmée (§1).
3. **Ancrage global multi-domaines.** Rejeté : les chaînes sont indépendantes par construction
   (contrainte d'unicité, `verify_chain`, modèle d'autorité) ; un ancrage global exigerait un
   champ de N têtes hétérogènes — exactement l'improvisation qu'ADR-013 a refusée.
4. **Ancrage écrit dans une seconde table ou une seconde base, sans publication externe.**
   Rejeté : un adversaire capable de tronquer la chaîne est capable de supprimer l'ancrage.
   C'est le raisonnement fondateur de cet ADR.
5. **Ancrage déclenché par `audit-collector` lui-même.** Rejeté comme cible : l'ancreur est le
   témoin de l'écrivain ; les confondre supprime la propriété. Retenu au plus comme repli
   transitoire, avec pool Postgres distinct en lecture seule, si le coût d'un binaire
   supplémentaire est jugé prohibitif (Q3).
6. **Notarisation blockchain publique.** Rejeté : disproportionné, gouvernance non maîtrisée,
   aucune reconnaissance ANSSI/eIDAS, standard de fait et non norme (règle n°6). (a)+(b)
   fournissent la même propriété avec un dossier défendable.
7. **Vérifier les jetons RFC 3161 dans le code du dépôt.** Rejeté à ce stade : impose un
   analyseur CMS/ASN.1 dans `zs-crypto` — une surface d'attaque majeure pour une propriété que
   l'auditeur peut vérifier hors ligne avec `openssl ts`. Réexaminable par un ADR dédié créant
   une suite `timestamp-token/vN`.
8. **Signer le dépôt Git de publication.** Rejeté : introduirait une clé de signature hors HSM
   et hors `zs-crypto` (règle absolue n°4). Les octets publiés sont déjà scellés par le HSM ;
   Git est un témoin, pas une racine de confiance.
9. **Attendre la stabilisation de SCITT pour tout faire d'un coup.** Rejeté :
   `draft-ietf-scitt-architecture-22` expire en décembre 2026, contre une échéance ANSSI 2027 et
   une exposition actuelle. Chaque jour sans ancrage est un jour d'historique définitivement
   tronçonnable sans détection.
10. **Attendre `audit-seal/v2` pour ancrer.** Rejeté : l'ancrage est utile immédiatement sous v1,
    et l'existence du mécanisme est un prérequis d'ADR-030, pas une conséquence.

## Hors périmètre

- Job de vérification périodique automatique de la chaîne complète et de sa confrontation au
  registre externe (procédure §3-4-5). La procédure est normative ici ; son automatisation est
  de l'implémentation, à rattacher à `make replay` et à l'alarme d'interruption d'audit (déjà
  signalée non implémentée dans le modèle de menaces).
- Alarme et export SIEM — déjà hors périmètre d'`audit-collector`, inchangé.
- Preuves d'inclusion / Merkle (alternative 1) et reçus SCITT (option e).
- Vérification en code des jetons RFC 3161 (alternative 7) et re-horodatage long terme RFC 4998
  ERS.
- Ouverture d'`audit-collector` en lecture (API d'interrogation du journal) : distincte, bien que
  citée par ADR-013 comme le moment naturel de cet ADR.
- Rétention et purge du journal : une purge légitime après expiration de rétention ressemble à
  une troncature. L'interaction ancrage / purge n'est pas traitée ici et devra l'être avant toute
  politique de purge.

## Critère de réexamen

- Toute purge ou rétention décidée sur `audit.events` : réexamen obligatoire avant mise en œuvre
  (voir hors périmètre).
- Publication de SCITT en RFC, ou d'un profil ETSI/ANSSI de journal de transparence : réévaluer
  l'option (e) et l'ajout d'un `kind` correspondant.
- Ajout d'un cinquième domaine d'autorité, ou changement du modèle de domaines : la cadence est
  par domaine.
- Première mesure de charge réelle : recaler `N` et `T` sur l'activité observée, pas sur
  l'hypothèse d'ADR-030 Q5.
- Bascule `audit-seal/v2` : vérifier que l'ancrage `suite_transition` produit bien la propriété
  attendue, par un test de rejeu croisant les deux suites.
- Toute évolution de la doctrine ANSSI sur l'horodatage qualifié ou la PQC appliquée aux
  services de confiance.
- Changement d'hébergement du registre externe ou d'AH : c'est un changement de racine de
  confiance, il exige un ADR, pas une modification de configuration.
- Au plus tard fin 2026, en cohérence avec ADR-030.

---

## Questions ouvertes — arbitrage humain requis avant « Statut : accepté »

**Q1 — Hébergement du registre externe. TRANCHÉE (2026-08-24) : un tiers externe à
l'association (RSSI ou CESTI partenaire).** Le dépôt Git de publication est administré par une
organisation ou une personne extérieure à Biscuits IA, sans accès à l'infrastructure du système
(PostgreSQL compris). C'est la séparation la plus forte disponible pour la propriété recherchée :
même un accès administrateur système complet chez Biscuits IA ne donne aucun contrôle sur le
registre externe. Reste à instruire avant l'implémentation, hors périmètre de cet ADR : le nom du
partenaire retenu, les modalités contractuelles (droit d'accès en écriture, disponibilité,
pérennité de l'engagement au-delà d'une mission ponctuelle), et un mécanisme de repli si le
partenaire cesse d'assurer ce rôle (le registre existant ne doit pas devenir orphelin).

**Q2 — Autorité d'horodatage RFC 3161. TRANCHÉE (2026-08-24) sur le principe : oui.**
L'indisponibilité de l'AH dégrade l'ancrage en Git-seul avec alarme, jamais en blocage —
confirmé, cohérent avec la règle « refus par défaut » qui porte sur l'octroi d'accès, pas sur la
production de preuve (voir Q5). Choix du prestataire et budget **différés**, même pattern que
la Q2 d'ADR-030 pour les fournisseurs HSM : le porteur du projet les instruira séparément, hors
du périmètre de cet ADR. Cet ADR ne peut passer à « accepté » que sur les points qu'il tranche
lui-même ; le choix du prestataire reste une action de suivi distincte, à consigner ici une fois
faite (règle absolue n°10 : licence/gouvernance du prestataire à documenter à ce moment-là).

**Q3 — Composant séparé `apps/audit-anchor` ou goroutine d'`audit-collector` ? TRANCHÉE
(2026-08-24) : composant séparé.** `apps/audit-anchor` (Go, nouveau binaire), rôle PostgreSQL
`audit_reader` strictement en lecture seule, jamais d'`INSERT`. Retenu explicitement pour
préserver la propriété « l'ancreur n'est pas l'écrivain » — un `audit-collector` compromis
tronque et n'ancre pas si les deux processus sont confondus. Pas de repli goroutine : implémenté
directement comme composant séparé dès la première livraison, pas de dette transitoire à dater.

**Q4 — Valeurs de `N` et `T`. TRANCHÉE (2026-08-24) : `N = 1000`, `T = 1 h`.** Objectif de
service retenu : « au plus 1 000 événements ou 1 heure d'historique peuvent disparaître d'un
domaine sans détection », le premier des deux critères atteint déclenchant l'ancrage. Cohérent
avec l'hypothèse de charge d'ADR-030 Q5 (~50 000 événements/jour) — laisse ~2 000 événements
tronçonnables dans la fenêtre horaire au pire cas, sans multiplier le coût HSM/volumétrie/appels
AH qu'imposerait un seuil plus strict (ex. N=100/T=15min, ~14× plus d'ancrages sur les domaines
peu actifs comme `admin-api`). Par domaine, configurable, plancher de sécurité documenté — à
recaler sur charge réelle observée (critère de réexamen déjà posé).

**Q5 — Ancrage sur chaîne cassée. TRANCHÉE (2026-08-24) : émis et publié, jamais refusé.** Un
ancrage `outcome: "error"` est produit et publié dans le registre externe même quand
`verify_chain` échoue, plutôt qu'un refus d'émettre. Validé consciemment comme **exception
explicite** au « refus par défaut » du projet : cette règle absolue porte sur l'octroi d'accès,
pas sur la production de preuve — refuser d'émettre un ancrage produirait un silence, exactement
le résultat que rechercherait un adversaire ayant tronqué la chaîne. L'échec de `verify_chain`
déclenche une alarme en plus de l'ancrage `outcome: "error"`, jamais un blocage silencieux de
l'ancrage lui-même.

**Q6 — Forme de `publications`. TRANCHÉE (2026-08-24) : tableau borné à 4, comme déjà proposé en
§4.** Confirme le format du contrat déjà rédigé (`"maxItems": 4`) — reproduit le pari gagnant du
conteneur `signature` à N composantes d'ADR-012/013, où anticiper la cardinalité a évité une
rupture de contrat ultérieure. Accueille un registre supplémentaire (ex. reçu SCITT, option (e)
en veille) sans jamais modifier `contracts/events/audit-event.schema.json` de nouveau.

**Q7 — Antériorité vis-à-vis d'ADR-030. TRANCHÉE (2026-08-24) : confirmée.** Ordre
ADR-031 → ADR-030. ADR-030 (§Q6/Q9, déjà mis à jour dans ce sens) renvoie à
`anchor.reason = "suite_transition"` pour son événement charnière, et `T` s'y définit comme la
séquence de cet ancrage plutôt qu'une date calendaire — cohérent avec la décision déjà actée
côté ADR-030 dans cette même session.

**Q8 — Correction documentaire. TRANCHÉE (2026-08-24) : corrigée.** `docs/architecture.md` et
`security/threat-models/audit-collector.md` ne décrivent plus un « chaînage Merkle » inexistant
— remplacé par « chaînage séquentiel (`prev_hash`) », avec renvoi explicite à ADR-031 pour la
propriété que le chaînage seul ne couvre pas (troncature en queue de chaîne).

**Q9 — Rétention et purge. TRANCHÉE (2026-08-24) : aucune purge prévue à ce jour.** Rétention
indéfinie du journal tant qu'aucune politique de purge n'est instruite. L'interaction
ancrage/purge reste explicitement hors périmètre de ce document (voir « Hors périmètre ») — dès
qu'une politique de purge est envisagée, elle doit être instruite par un ADR dédié qui traite
spécifiquement cette interaction avant toute implémentation, pas après : une purge légitime
resterait sinon indiscernable d'une troncature pour la procédure de vérification §3.

**Q10 — Premier ancrage. TRANCHÉE (2026-08-24) : ancrage rétroactif immédiat.** Un premier
ancrage par domaine d'autorité, `previous_anchor` omis, couvrant tout l'historique déjà écrit à
la mise en service. Borne définitivement la fenêtre non protégée à ce qui existe aujourd'hui —
tout report aurait continué à agrandir la portion d'historique définitivement tronçonnable sans
détection.

Sources normatives citées : [ANSSI — FAQ cryptographie post-quantique](https://cyber.gouv.fr/cryptographie-post-quantique-faq),
[ANSSI — services de confiance eIDAS](https://cyber.gouv.fr/reglementation/reglementation-identite-confiance-numerique/securite-echanges-voie-electronique/reglement-eidas/services-de-confiance/),
[RFC 3161 — horodatage et preuve numérique](https://evidency.io/rfc-3161-horodatage/),
[caractéristiques de l'horodatage qualifié eIDAS](https://www.datasure.net/services/horodatage-electronique-qualifie-eidas/caracteristiques-horodatage-qualifie-eidas/),
[draft-ietf-scitt-architecture (IETF Datatracker)](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/),
[ANSSI : fin des certifications sans PQC dès 2027](https://itsocial.fr/cybersecurite/cybersecurite-actualites/a-partir-de-2027-lanssi-ne-certifiera-plus-les-produits-de-securite-sans-cryptographie-post-quantique/).
