// Exigence couverte : un porteur d'identité prouvée au niveau AAL3 peut ouvrir une session de
//   base de données (`db.connect`) sur une `Database` de production de SON PROPRE domaine
//   d'autorité, uniquement s'il présente une référence de ticket ITSM non vide, au moins une
//   approbation, et une posture de poste évaluée depuis moins d'une heure au moment de la
//   requête.
// ADR : ADR-003 (Cedar pour les décisions d'accès — typage statique contre la confusion de
//   requête). Contrat de transport : contracts/proto/policy/v1/decision.proto.
//   Schéma d'entités : contracts/cedar/schema.cedarschema.json.
// Détection associée : policies/detection/db_connect.yml.
// Tests : policies/tests/db_connect/ (1 cas nominal, 7 cas de refus attendus).
// Date de réexamen : 2027-02-23.
//
// Notes de portée (refus par défaut — P2) :
// - Le plafond de durée de vie du credential n'est PAS exprimé par une condition Cedar : il est
//   porté par les métadonnées de la politique et appliqué par `policy-engine` (`max_ttl` de
//   DecisionResponse, jamais fourni par l'appelant). Cf. L2.2.
// - `Approval.signature` n'apparaît pas dans le contexte : la signature d'approbation est
//   vérifiée via `zs-crypto` AVANT l'appel au PDP et n'est jamais réévaluée ici. Le PDP ne
//   constate que la présence d'approbations déjà validées.
// - Aucune condition ne dépend d'un état externe : tout le contexte arrive en entrée, la
//   décision est rejouable hors ligne (invariant de decision.proto).
@id("db-connect-production")
permit (
  principal is ZeroSecret::Principal,
  action == ZeroSecret::Action::"db.connect",
  resource is ZeroSecret::Database
)
when {
  // Périmètre : uniquement la production. Les autres environnements ne sont pas couverts par
  // cette politique et relèvent donc du refus par défaut.
  resource.environment == "production"
}
when {
  // Cloisonnement multi-zone : un principal d'un domaine d'autorité voisin ne bénéficie jamais
  // de cette règle, même en AAL3 avec ticket et approbation.
  principal.authority_domain == resource.authority_domain
}
when {
  // NIST SP 800-63-4 : seul AAL3 (authentificateur matériel résistant au hameçonnage) ouvre la
  // production. Comparaison de chaîne exacte — AAL1/AAL2/valeur vide/valeur inconnue refusent.
  principal.aal == "AAL3"
}
when {
  // Traçabilité ITSM : une chaîne vide est traitée comme une absence de ticket.
  context.ticket_ref != ""
}
when {
  // Au moins une approbation (double contrôle). La signature associée a déjà été vérifiée
  // en amont ; le PDP ne juge que la présence.
  !context.approvals.isEmpty()
}
when {
  // Fraîcheur de posture : « une posture périmée n'est pas une posture valide »
  // (DevicePosture, decision.proto). Fenêtre de 3600 s, en secondes epoch.
  // La borne basse refuse aussi une posture datée dans le futur (horloge incohérente ou
  // valeur forgée) : un écart négatif n'est pas une posture fraîche, c'est une anomalie.
  context.posture.evaluated_at <= context.requested_at &&
  context.requested_at - context.posture.evaluated_at <= 3600
};
