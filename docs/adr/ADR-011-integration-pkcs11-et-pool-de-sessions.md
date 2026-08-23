# ADR-011 — Intégration PKCS#11 (H1), pool de sessions et CBOM

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique, `referent-crypto`

## Contexte

L1.2c (`identity-assertion/v1`, ADR-007/008) et L1.4b (`audit-seal/v1`, ADR-010) sont tous deux
bloqués sur la même intégration réelle de `crates/zs-hsm`, aujourd'hui un stub vide. ADR-010 a
tranché de sortir cette intégration comme prérequis partagé (« H1 ») plutôt que de la redemander
séparément pour les deux lots, et a désigné `audit-seal` comme l'opération HSM la plus fréquente
du système (une signature par action métier — règle absolue #9 du `CLAUDE.md` racine), donc la
contrainte de conception dimensionnante.

Consulté avant toute modification de `zs-hsm` (crate FFI `unsafe`, ADR-001), `referent-crypto` a
produit une analyse complète : choix de bibliothèque, modèle de session, surface d'API, sémantique
de refus, frontière avec `zs-crypto`, plan de test, structure CBOM. Les points structurants ont
été soumis à validation humaine.

## Décisions

### Bibliothèque : `cryptoki` 0.12 (+ `cryptoki-sys`)

Apache-2.0 (OSI, pas de copyleft fort), gouvernance CNCF/Parsec, cadence de publication régulière,
aucune advisory RustSec propre au crate, couvre PKCS#11 v3.2 (`Mechanism::MlDsa`, `MlKem`,
`SlhDsa*`) — nécessaire pour la cible hybride `v2`. Alternatives écartées : `pkcs11` (mheese,
non maintenu depuis 2020), `native-pkcs11` (fournisseur de module, pas consommateur — hors sujet).

**Contrainte de build** : bindings `cryptoki-sys` **pré-générés, vendorisés en amont** — la
génération à la compilation via `bindgen` est désactivée, pour ne pas faire entrer `libclang`
dans la chaîne CI ni rendre le SBOM non reproductible.

**Trou de contrôle comblé dans ce lot** : `tools/lib/check-no-direct-crypto.sh` ne connaissait ni
`cryptoki` ni `cryptoki-sys` — étendu pour que ces crates ne soient importables que depuis
`crates/zs-hsm`, comme les autres bibliothèques crypto.

### Modèle de session : pool borné, jamais `thread_local`

Un seul contexte PKCS#11 par processus (`Arc<Pkcs11>`, `CInitializeFlags::OS_LOCKING_OK`). Les
sessions vivent dans un **pool borné**, capacité plafonnée à `ulMaxSessionCount` lue au démarrage
(refus de démarrer si la configuration la dépasse). Acquisition avec timeout explicite ; timeout
épuisé = refus (voir « Politique de saturation » ci-dessous), jamais d'attente non bornée.

Le pattern `thread_local!` de l'exemple amont `cryptoki` est explicitement écarté : sous un
runtime async à vol de travail, le nombre de threads worker n'a aucun rapport avec le nombre de
sessions qu'un token accepte — un HSM matériel impose une borne dure (`ulMaxSessionCount`) que ce
pattern ignore.

**API bloquante, aucune dépendance à un runtime async dans `zs-hsm`.** L'appelant (`zs-crypto`)
est responsable d'un `spawn_blocking` ou équivalent s'il tourne sous un exécuteur async.

**Piège identifié — `logout()` a une portée application/token, pas session.** Déloguer une
session du pool peut déloguer silencieusement toutes les autres sessions ouvertes, transformant
un simple retour de session au pool en panne globale intermittente, sous charge uniquement.
**Règle : ne jamais appeler `logout()` explicitement sur une session du pool.** Les sessions ne
meurent que sur erreur (`SessionLost`), jamais par recyclage de routine. Premier test
d'intégration à écrire : deux sessions ouvertes, une droppée, la seconde doit rester `RwUser`.

### Surface d'API : `HsmSigner`, générique, sans vocabulaire métier

```
pub struct KeyRef { label: String }
#[non_exhaustive]
pub enum SigningMechanism { EcdsaP256Sha256 }   // v2 : + MlDsa65

pub trait HsmSigner: Send + Sync {
    fn sign_digest(&self, key: &KeyRef, mechanism: SigningMechanism, digest: &[u8])
        -> Result<Signature, HsmError>;
    fn public_key(&self, key: &KeyRef) -> Result<PublicKeyDer, HsmError>;
}
```

- **`sign_digest`, pas `sign_message`** (`Mechanism::Ecdsa`, digest pré-calculé) : la
  canonicalisation et le hachage restent un seul point de vérité côté `zs-crypto`/`zs-audit`, pas
  dupliqués dans le lien PKCS#11.
- **`SigningMechanism` énuméré**, jamais un `cryptoki::Mechanism` réexporté — sinon `zs-crypto`
  choisirait un algorithme via ce type, contournant l'invariant 2 (« l'API expose des
  intentions, pas des algorithmes »).
- Le trait n'existe que pour l'injection dans les tests de `zs-crypto` ; aucune implémentation de
  `HsmSigner` hors `zs-hsm` (et hors `#[cfg(test)]`) — vérifié par test d'architecture (voir
  « Tests »), pour qu'un « repli logiciel de test » ne devienne jamais un repli de production.

### Sémantique de refus — non négociable

```
pub enum HsmError {
    NotInitialized, TokenAbsent, SessionLost, NotLoggedIn,
    KeyNotFound(String), MechanismUnsupported(SigningMechanism),
    PoolExhausted, DeviceError,
}
```

1. **Aucune variante n'est rattrapable en « autoriser quand même ».** Toute erreur remonte et
   fait échouer l'action métier (règles absolues #2 et #9 : pas d'événement scellé signifie que
   l'action n'a pas eu lieu).
2. **Aucun repli logiciel, y compris en dev** — pas de feature de signature en mémoire, pas de
   variable d'environnement de contournement. Contrôlé par test d'architecture, pas seulement
   par convention.
3. **Reconnexion à l'acquisition suivante uniquement, jamais en cours d'opération.**
   `sign_digest` ne réessaie jamais tout seul. Motif précis : ECDSA P-256 est un algorithme de
   signature **randomisé** ; une reprise interne sur une réponse HSM perdue produirait deux
   signatures valides distinctes sur le même contenu. Comme `prev_hash` (ADR-010) porte sur la
   sérialisation complète **signature incluse**, deux scellements du même événement seraient deux
   successeurs également valides de la chaîne — un risque de fourche que la façon sûre d'éviter
   est de ne jamais produire la seconde signature. Corollaire pour L1.4b : l'allocation de
   `sequence` et la persistance doivent être atomiques avec la signature obtenue, jamais avant.
4. **Pas de sonde de disponibilité qui autorise par anticipation** — le refus se décide sur
   l'échec de l'appel réel, jamais sur l'état d'un cache de santé.
5. **Démarrage en échec dur** : au boot, vérifier que le mécanisme requis est réellement offert
   par le token (`get_mechanism_list`) et que chaque clé existe et est unique. Absence = refus de
   démarrer, pas une découverte à la première authentification.
6. **PIN** : lu à l'exécution (`SOFTHSM2_PIN`, déjà produit par `deploy/softhsm/init-token.sh`),
   zeroizé après usage, jamais journalisé ni dérivable d'un `Debug`.

### Politique de saturation du pool

Un timeout d'acquisition épuisé (`PoolExhausted`) fait échouer l'action métier en entier —
**refus complet, pas de dégradation partielle.** Conséquence assumée : une surcharge HSM devient
une indisponibilité du système, jamais une action qui réussirait sans événement scellé. C'est la
conséquence directe de « pas d'action sans événement d'audit » (règle absolue #9), tranchée
explicitement plutôt que découverte en incident.

### Frontière `zs-crypto` / `zs-hsm`

`zs_crypto::identity_assertion::seal` et `zs_crypto::audit_seal::seal` appellent `zs-hsm` en
interne ; aucun consommateur (`identity-provider`, `zs-audit`) ne dépend de `zs-hsm` directement
— déjà vérifié par test d'architecture (`check-webauthn-no-hsm.sh`, étendu en L1.4a).

**`zs-hsm` reste une dépendance privée de `zs-crypto` : aucun type `zs-hsm` n'apparaît dans la
surface publique de `zs-crypto`.** `HsmError` est traduit en une variante unique et opaque côté
façade (`SealError::SealingUnavailable`) — le détail part en télémétrie, jamais dans le type de
retour qu'un appelant pourrait être tenté de faire correspondre à un cas « on continue quand
même ».

Composition hybride `v2` (ECDSA P-256 + ML-DSA-65) : faite **dans `zs-crypto`**, qui appelle
`zs-hsm` deux fois (deux `KeyRef`, deux `SigningMechanism`). `zs-hsm` reste mono-mécanisme par
appel — l'invariant 5 (hybridation stricte) reste vérifiable en un seul endroit (`zs-crypto`),
jamais dans `zs-hsm`.

**Correction de documentation** : `crates/zs-hsm/src/lib.rs` indiquait « utilisé exclusivement
par `apps/credential-issuer` » — obsolète depuis ADR-010 (`zs-crypto` est l'unique appelant),
corrigé dans ce lot pour ne pas induire un futur contributeur en erreur sur la frontière.

### Deux clés HSM séparées

Une clé pour `identity-assertion/v1`, une clé distincte pour `audit-seal/v1` — labels distincts
dès ce lot. Cohérent avec ADR-010 : compromettre la clé `audit-seal` (réécriture de l'historique
complet) est strictement plus grave que compromettre la clé d'assertion (usurpation détectable
par le journal). Séparer les clés après coup exigerait de rejouer tout l'historique signé ; les
séparer maintenant coûte deux clés à provisionner, pas une reprise ultérieure.

### Encodage de signature : raw `r‖s`, 64 octets

Retenu plutôt que DER : taille fixe, aucun analyseur DER requis sur le chemin de vérification —
surface minimale. Ce choix entre dans `prev_hash` (ADR-010, hash de la sérialisation complète
signature incluse) et devient donc **irréversible dès le premier événement réellement scellé** —
tranché maintenant, pas en L1.4b.

### CBOM : `suites.toml` source, `cbom.json` dérivé

`security/crypto-inventory/` est initialisé dans ce lot, format CycloneDX 1.6
(`cryptographic-asset`) :

```
security/crypto-inventory/
  README.md      # comment lire, qui met à jour, lien vers l'échéance ANSSI 2027
  suites.toml    # source, édité à la main, revue humaine
  cbom.json       # généré par tools/generate-cbom.sh depuis suites.toml — jamais édité à la main
```

Trois suites déclarées dès ce lot — pas seulement `audit-seal`/`identity-assertion` : l'invariant
9 de `zs-crypto/CLAUDE.md` est **déjà en défaut** depuis `authenticator-proof/v1` (L1.1), sans
entrée CBOM à ce jour. Comblé maintenant plutôt que reporté un lot de plus :

| Suite | Rôle | `executionEnvironment` | Conformité ANSSI 2027 |
|---|---|---|---|
| `authenticator-proof/v1` | vérification | software | exception documentée (ADR-006, algorithme imposé par un tiers) |
| `identity-assertion/v1` | émission | hardware (HSM) | `false` — `v2` hybride visé |
| `audit-seal/v1` | émission | hardware (HSM) | `false` — `v2` hybride visé |

**Contrôle bloquant inclus dans ce lot** (pas différé) : `tools/generate-cbom.sh` échoue si une
constante de suite (`pattern */vN` détecté dans `crates/zs-crypto/src/**/*.rs`) n'a pas d'entrée
correspondante dans `suites.toml` — rend l'invariant 9 mécaniquement vrai plutôt qu'une promesse
non outillée. Testé par fixture (violation/clean), même style que les autres détecteurs
d'architecture (L0.2).

## Plan de test

`zs-hsm` n'a que des tests d'intégration contre un **vrai** SoftHSM2 — un mock de `HsmSigner` est
légitime pour tester `zs-crypto`, jamais pour tester `zs-hsm` lui-même (ce serait précisément le
repli logiciel interdit, déguisé en test).

- `crates/zs-hsm/tests/pkcs11_integration.rs`, `#[ignore]` par défaut, activé par `make
  test-crypto`. Variable `ZS_HSM_MODULE` **requise** — absence = échec du test, jamais un skip
  silencieux (un test d'intégration HSM qui se dérobe silencieusement en CI est pire qu'absent).
- Token éphémère par exécution (`tempdir`, PIN généré à l'exécution), pas le token partagé de
  `deploy/compose.dev.yml` — non reproductible sinon.
- Cas couverts, adverses en priorité : nominal signé/vérifié ; deux sessions + drop de l'une
  (reste `RwUser`) ; PIN erroné ; clé absente/dupliquée ; mécanisme non offert (refus au
  démarrage) ; perte de session en cours d'opération (aucune signature produite) ; token absent ;
  pool saturé (timeout, refus) ; tentative d'extraction de la clé privée (refusée par le
  token — preuve de l'invariant 7, pas une affirmation) ; N threads concurrents.
- `make test-crypto` étendu pour inclure `zs-hsm` (n'incluait avant que `zs-crypto` et
  `zs-webauthn`).

## Conséquences

**Positives** — L1.2c et L1.4b deviennent indépendants et parallélisables. L'invariant 7 (« aucune
clé privée ne quitte le HSM ») devient démontrable par test (tentative d'extraction refusée),
pas seulement affirmé en commentaire. Le CBOM existe et son contrôle devient bloquant, comblant
une dette ouverte depuis L1.1.

**Négatives** — de l'`unsafe` transitif entre dans le graphe de dépendances via `cryptoki-sys`
(borné à `zs-hsm`, déjà couvert par ADR-001). SoftHSM2 ne prédit pas la performance d'un HSM
matériel — les mesures de latence de ce lot sont un plancher, pas une capacité de production.
Le contrôle CBOM bloquant élargit la portée de H1 (assumé, voir arbitrage ci-dessus).

**Surface d'attaque** — un nouveau composant (le module PKCS#11 et son pilote) entre sur le
chemin de confiance de toute émission. L'indisponibilité HSM devient un mode de panne **par
conception** (refus), pas un cas limite — à refléter dans `security/threat-models/
identity-provider.md` et le modèle de menaces d'`audit-collector` lors de L1.2c/L1.4b.

## Critère de réexamen

Réexaminer à l'approvisionnement d'un HSM matériel cible (mécanismes PKCS#11 v3.2 réellement
exposés, visa ANSSI, `ulMaxSessionCount` réel, latence réelle) et au démarrage effectif de la
cible `v2` hybride. Aucun HSM matériel cible n'est identifié à la date de cet ADR — SoftHSM2
reste la seule cible testée ; `SigningMechanism` peut nécessiter une révision selon les
mécanismes réellement exposés par le matériel choisi.
