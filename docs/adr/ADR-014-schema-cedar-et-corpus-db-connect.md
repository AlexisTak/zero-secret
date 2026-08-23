# ADR-014 — Schéma d'entités Cedar et premier corpus de politiques (`db.connect`)

**Statut** : accepté
**Date** : 2026-08-23
**Décideurs** : responsable technique, `auteur-politiques`

## Contexte

L2.1 pose le socle du lot L2 (autorisation dynamique) : le schéma d'entités Cedar
(`contracts/cedar/schema.cedarschema.json`) et le premier corpus de `policies/access/`, dont
dépendent L2.2 (`policy-engine`) et toute la suite. ADR-003 a choisi Cedar précisément pour son
typage statique contre la confusion de requête ; deux choix de cette contribution engagent
directement cette propriété et ne doivent pas être laissés à l'implicite.

## Décisions

### Un type d'entité Cedar dédié par type de ressource métier, jamais un `map` générique

`Resource.attributes` du contrat de transport (`decision.proto`) est un `map<string, string>`
ouvert. Le traduire tel quel en Cedar (un type `Resource` générique portant ce map) aurait
réintroduit exactement la confusion de requête qu'ADR-003 invoque pour justifier Cedar : un
attribut non typé statiquement n'est pas distinguable d'un attribut d'un autre type de ressource
portant le même nom mais une sémantique différente.

**Décision** : chaque type de ressource métier a son propre type d'entité Cedar, aux attributs
typés et complets (`required: true` sur tout le corpus actuel). Premier type livré : `Database`
(`authority_domain`, `environment`), le plus proche de l'exemple `db.connect` déjà présent dans
`decision.proto`. Les types suivants (`SshHost`, `Secret`, …) s'ajoutent au fil des politiques
réelles qui les motivent, jamais par anticipation.

**Conséquence** : le schéma grossit avec le nombre de types de ressources plutôt que de rester à
taille fixe. Assumé — c'est le prix du typage statique, et il grossit au même rythme que les
politiques elles-mêmes, jamais en avance sur elles.

### Le sixième cas d'attaque obligatoire (« dépassement de la durée de vie maximale ») réinterprété en fraîcheur de posture

`policies/CLAUDE.md` impose six catégories de cas de refus par politique, dont « le dépassement de
la durée de vie maximale ». Cedar n'évalue pas de TTL de credential : `max_ttl` est une valeur que
`policy-engine` impose depuis les métadonnées de la politique correspondante (`DecisionResponse`,
jamais fournie par l'appelant) — calcul de L2.2, pas une condition Cedar évaluable dans ce lot.

**Décision** : ce sixième cas est instancié concrètement comme la fraîcheur de
`context.posture.evaluated_at` par rapport à `context.requested_at` (fenêtre de 3600 s, borne
basse incluse contre une posture datée dans le futur). Ce n'est pas une substitution arbitraire :
le commentaire déjà présent sur `DevicePosture` dans `decision.proto` énonce l'invariant
directement (« une posture périmée n'est pas une posture valide »). La politique
`db_connect.cedar` exprime cet invariant plutôt que d'inventer une sémantique de TTL non instruite.

**Conséquence** : quand L2.2 introduira une notion de TTL réellement évaluée par politique
(annotation de métadonnées, pas une condition `when`/`unless`), le sixième cas d'attaque de
`policies/CLAUDE.md` devra être réexaminé pour vérifier qu'il couvre aussi ce nouveau mécanisme —
la fraîcheur de posture reste valide en soi, mais ne suffira plus à épuiser la catégorie.

### Garde-fous `forbid` volontairement redondants avec le `permit`

`policies/access/db_connect_guardrails.cedar` réaffirme en trois `forbid` distincts les mêmes
conditions déjà portées par les clauses `when` du `permit` de `db_connect.cedar` (AAL3, ticket et
approbation combinés, cloisonnement de domaine d'autorité). En Cedar, un `forbid` l'emporte
toujours sur tout `permit`, quel qu'il soit — y compris un `permit` futur mal écrit.

**Décision** : la redondance est délibérée, pas une dette à factoriser. C'est le mécanisme concret
qui donne un sens à la catégorie « escalade par combinaison de deux règles légitimes prises
isolément » (`policies/CLAUDE.md`) : sans garde-fou séparé, une seconde politique `permit` future,
correcte en elle-même, pourrait recombiner des conditions déjà couvertes et élargir l'accès par
effet de bord. Le garde-fou borne ce pire cas indépendamment du nombre de `permit` qui s'accumulent
avec le temps.

## Conséquences

**Positives** — le schéma reste vérifiable statiquement (`cedar validate --validation-mode strict
--deny-warnings`, exécuté réellement via `cargo install cedar-policy-cli`, pas seulement supposé) ;
le corpus démontre par test de mutation que chacune des cinq conditions du `permit` est réellement
nécessaire (suppression individuelle testée, détectée dans les cinq cas).

**Négatives** — deux fichiers de politique à maintenir en cohérence pour une seule règle métier
(`db_connect.cedar` + `db_connect_guardrails.cedar`) ; le sixième cas d'attaque devra être
retravaillé à l'arrivée du TTL réel en L2.2, pas figé définitivement par cette décision.

**Surface d'attaque non couverte, signalée** : rejeu d'un ticket ou d'une approbation déjà
consommés (pas de notion de consommation dans le contexte de cette tâche) ; approbateur identique
au demandeur (`Approval.approver_id` n'est comparé à rien) ; collusion de deux approbateurs ;
`source_network` déclaré au schéma mais non exploité par aucune politique ; `posture.managed`/
`disk_encrypted` déclarés, non exigés. À traiter par les politiques suivantes de L2.1+, pas un
oubli de cette contribution mais une portée volontairement limitée à `db.connect`.

## Critère de réexamen

Réexaminer le sixième cas d'attaque à l'introduction du TTL réel en L2.2. Réexaminer la
redondance `permit`/`forbid` si le nombre de `permit` du corpus grossit au point que la
duplication devient elle-même une source d'incohérence (auquel cas un mécanisme de garde-fou
factorisé, mais toujours à priorité `forbid`, sera proposé par ADR séparé).
