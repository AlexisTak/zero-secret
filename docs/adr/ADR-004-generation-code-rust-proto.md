# ADR-004 — Génération du code Rust depuis les contrats proto : build.rs, pas buf generate

**Statut** : accepté
**Date** : 2026-08-22
**Décideurs** : responsable technique

## Contexte

`contracts/proto/policy/v1/decision.proto` est le contrat le plus sensible du dépôt (voir son
en-tête). La règle absolue #8 du `CLAUDE.md` racine impose : `contracts/` est la source de
vérité, les types sont générés, jamais écrits à la main.

Côté Go, `buf generate` (via `protoc-gen-go` / `protoc-gen-go-grpc`) produit `pkg/gen/`,
committé, sans incident.

Côté Rust, la même approche — `buf generate` avec `protoc-gen-prost` et `protoc-gen-tonic`
(derniers binaires publiés, installés via `cargo install`), sortie en deux fichiers
(`policy.v1.rs` + `policy.v1.tonic.rs`) reliés dans `crates/zs-policy` par `include!` ou par des
modules `#[path]` — produit une erreur de compilation reproductible et déterministe :
`error[E0428]: the name "policy_decision_service_client" is defined multiple times`, alors
qu'aucune définition textuelle en double n'existe dans les fichiers générés. L'erreur a été
reproduite dans un crate isolé minimal (donc indépendante du reste du workspace), disparaît avec
un contenu simplifié (structs vides sans dérive), et persiste que la liaison se fasse par
`include!` ou par `#[path]`. La cause exacte n'a pas été identifiée après investigation ciblée ;
aucun rapport correspondant trouvé côté `protoc-gen-prost`/`protoc-gen-tonic` au moment de la
recherche.

## Options envisagées

1. **`buf generate` + `protoc-gen-prost`/`protoc-gen-tonic` séparés, sortie committée** — option
   initialement retenue pour l'auditabilité (un tiers lit le code généré sans avoir à faire
   confiance à la reproductibilité du pipeline). Écartée : bloquée par le bug ci-dessus,
   reproduit de façon isolée et déterministe, sans piste de correction trouvée dans un budget de
   temps raisonnable.
2. **`build.rs` avec `tonic-prost-build`** — invoque `protoc` une seule fois, combine messages et
   service dans un seul fichier généré à la compilation (`OUT_DIR`). Testé sur le même contrat :
   compile sans erreur, à l'identique du flux Go. C'est l'approche par défaut de l'écosystème
   Rust pour prost/tonic.
3. **Abandonner tonic et exposer seulement les messages** — écarté : `policy-engine` a besoin du
   contrat de service (`PolicyDecisionService`), pas seulement des messages.

## Décision

**Option 2.** `crates/zs-policy/build.rs` appelle `tonic_prost_build::compile_protos` sur
`contracts/proto/policy/v1/decision.proto` à chaque compilation. Le fichier généré n'est **pas**
committé — c'est un écart volontaire à la pratique Go du même dépôt (`pkg/gen/`, committé),
accepté pour les raisons suivantes :

- **Reproductibilité** : garantie par le contrat figé (`contracts/proto/`, versionné,
  `buf breaking` en CI) et par `Cargo.lock` (versions de `prost`/`tonic`/`tonic-prost-build`
  verrouillées), pas par une inspection statique d'un fichier committé.
- **Dérive détectée** : `make check`/CI font tourner `cargo build`, qui régénère systématiquement
  depuis le contrat courant — impossible de compiler avec un générateur périmé sans que la CI
  échoue au premier changement de contrat non répercuté (contrairement à un fichier committé
  oublié, qui compile silencieusement jusqu'à la prochaine régénération manuelle).
- `contracts/buf.yaml`/`buf.gen.yaml` ne déclarent plus de plugin Rust ; seul le Go y reste.

## Conséquences

**Positives** — flux Rust standard, aligné sur l'écosystème (moins de surface de maintenance
propre à ce dépôt) ; aucun risque de fichier généré committé périmé côté Rust, par construction.

**Négatives** — un auditeur qui veut lire le code Rust généré sans compiler doit lancer
`cargo build -p zs-policy` et lire `target/.../build/zs-policy-*/out/policy.v1.rs` — un pas
supplémentaire par rapport à `pkg/gen/` (lecture directe). Asymétrie Go/Rust dans ce dépôt sur ce
point précis, à documenter pour ne pas surprendre un contributeur qui découvre l'un après l'autre.

**Surface d'attaque** — aucune : le contrat lui-même (source de vérité) est inchangé, seule la
mécanique de génération diffère. `contracts/proto/` reste sous revue et sous `buf breaking`.

## Critère de réexamen

Réexaminer si une version future de `protoc-gen-prost`/`protoc-gen-tonic` corrige le défaut
observé (à revalider avant de rouvrir), ou si l'écosystème Rust converge vers une pratique de
génération committée standardisée que ce dépôt voudrait suivre pour l'homogénéité avec `pkg/gen/`.
