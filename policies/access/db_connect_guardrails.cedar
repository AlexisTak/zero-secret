// Exigence couverte : aucune politique `permit` présente ou future ne peut accorder
//   `db.connect` sur une base de production sans AAL3, sans correspondance de domaine
//   d'autorité, sans ticket ou sans approbation. Garde-fou anti-élargissement par effet de
//   bord : en Cedar, un `forbid` l'emporte toujours sur tout `permit`.
// ADR : ADR-003. Schéma : contracts/cedar/schema.cedarschema.json.
// Détection associée : policies/detection/db_connect.yml.
// Tests : policies/tests/db_connect/ — cas `escalade_*`.
// Date de réexamen : 2027-02-23.
//
// Ces règles sont volontairement redondantes avec les conditions de `db_connect.cedar`. La
// redondance est le mécanisme : elle borne le pire cas d'une future politique mal écrite ou
// d'une combinaison de deux règles légitimes prises isolément. Ne pas « factoriser ».

// Aucun accès de production sans AAL3.
@id("guardrail-production-requires-aal3")
forbid (
  principal is ZeroSecret::Principal,
  action == ZeroSecret::Action::"db.connect",
  resource is ZeroSecret::Database
)
when { resource.environment == "production" }
unless { principal.aal == "AAL3" };

// Aucun franchissement de domaine d'autorité, quel que soit l'environnement.
@id("guardrail-authority-domain-isolation")
forbid (
  principal is ZeroSecret::Principal,
  action == ZeroSecret::Action::"db.connect",
  resource is ZeroSecret::Database
)
unless { principal.authority_domain == resource.authority_domain };

// Aucun accès de production sans ticket ITSM ET sans approbation : les deux, jamais l'un OU
// l'autre. C'est le point exact où une escalade par combinaison serait tentée.
@id("guardrail-production-requires-ticket-and-approval")
forbid (
  principal is ZeroSecret::Principal,
  action == ZeroSecret::Action::"db.connect",
  resource is ZeroSecret::Database
)
when { resource.environment == "production" }
unless { context.ticket_ref != "" && !context.approvals.isEmpty() };
