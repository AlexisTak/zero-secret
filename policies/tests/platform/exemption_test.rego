# Cas de test du mécanisme d'exemption de policies/platform/exemption.rego.
#
# Le mécanisme d'exemption est la seule voie par laquelle une non-conformité peut être levée :
# c'est donc la surface la plus attaquante du corpus. Ces cas s'attachent à prouver qu'une
# exemption ne déborde JAMAIS de ce qu'elle nomme — ni sur une autre règle, ni sur un autre
# service, ni au-delà de sa date, ni hors de l'environnement de développement, ni sur une règle
# déclarée non exemptable.
#
# Cas nominal : une seule ligne de ce fichier produit une exemption valide
# (`test_exemption_valide_leve_la_violation`). Tous les autres cas en sont des variantes d'un
# seul paramètre — c'est la forme d'attaque la plus réaliste : on ne forge pas une exemption de
# zéro, on part d'une exemption légitime et on la déforme.
package zerosecret.platform.exemption_test

import data.zerosecret.platform.compose
import rego.v1

# --------------------------------------------------------------------------------------------
# Fabriques
# --------------------------------------------------------------------------------------------

label_key := "io.zero-secret.exemption.PLT-001"

# Justification de référence : référence ADR + date de réexamen à 182 jours de la date
# d'évaluation utilisée par ces cas (2026-08-25), donc sous le plafond de 366 jours.
valid_justification := "ADR-014 IPC_LOCK requis par OpenBao pour le verrouillage memoire reexamen=2027-02-23"

# Service qui viole PLT-001 (capacité Linux ajoutée) et rien d'autre.
openbao_with(labels) := {"openbao": {
	"image": "docker.io/openbao/openbao:2",
	"cap_add": ["IPC_LOCK"],
	"labels": labels,
}}

input_at(env, date, labels) := {
	"context": {"evaluated_at": date, "environment": env},
	"compose": {"services": openbao_with(labels)},
}

input_with(labels) := inp if {
	inp := input_at("dev", "2026-08-25", labels)
}

input_justified(justification) := inp if {
	inp := input_with({label_key: justification})
}

rule_ids(vs) := {v.rule | some v in vs}

pairs(vs) := {[v.rule, v.service] | some v in vs}

# --------------------------------------------------------------------------------------------
# Cas nominal et cas de référence sans exemption
# --------------------------------------------------------------------------------------------

test_exemption_valide_leve_la_violation if {
	inp := input_justified(valid_justification)
	vs := compose.violation with input as inp
	count(vs) == 0
	compose.allow with input as inp
	compose.exempted("PLT-001", "openbao") with input as inp
}

test_sans_exemption_la_violation_demeure if {
	inp := input_with({})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
	not compose.allow with input as inp
}

# --------------------------------------------------------------------------------------------
# Qualité de la justification
# --------------------------------------------------------------------------------------------

test_justification_vide_refusee if {
	inp := input_justified("")
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

test_justification_trop_courte_refusee if {
	inp := input_justified("ADR-014 reexamen=2027-02-23")
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

test_justification_sans_reference_adr_refusee if {
	inp := input_justified("IPC_LOCK requis par OpenBao pour le verrouillage memoire reexamen=2027-02-23")
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

test_justification_sans_date_de_reexamen_refusee if {
	inp := input_justified("ADR-014 IPC_LOCK requis par OpenBao pour le verrouillage memoire")
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

# Catégorie 4 : ambiguïté. Deux dates de réexamen ne se départagent pas — on ne choisit pas la
# plus favorable, on refuse.
test_justification_a_deux_dates_refusee if {
	inp := input_justified("ADR-014 verrouillage memoire OpenBao reexamen=2027-02-23 reexamen=2027-08-01")
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

test_justification_a_date_impossible_refusee if {
	inp := input_justified("ADR-014 IPC_LOCK requis par OpenBao verrouillage memoire reexamen=2027-13-45")
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

# --------------------------------------------------------------------------------------------
# Durée de vie de l'exemption (catégories 1 et 6)
# --------------------------------------------------------------------------------------------

test_exemption_echue_refusee if {
	inp := input_justified("ADR-014 IPC_LOCK requis par OpenBao verrouillage memoire reexamen=2026-08-24")
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

# Une exemption dont le réexamen tombe le jour même de l'évaluation ne protège plus : la borne
# est stricte, pour qu'il n'y ait pas de journée d'indétermination.
test_exemption_expirant_le_jour_meme_refusee if {
	inp := input_justified("ADR-014 IPC_LOCK requis par OpenBao verrouillage memoire reexamen=2026-08-25")
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

# Borne haute exacte : 366 jours après 2026-08-25 (2027 n'est pas bissextile).
test_exemption_a_la_borne_de_366_jours_acceptee if {
	inp := input_justified("ADR-014 IPC_LOCK requis par OpenBao verrouillage memoire reexamen=2027-08-26")
	vs := compose.violation with input as inp
	count(vs) == 0
}

test_exemption_au_dela_de_la_borne_refusee if {
	inp := input_justified("ADR-014 IPC_LOCK requis par OpenBao verrouillage memoire reexamen=2027-08-27")
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

# Le plafond est ce qui distingue une exemption d'une dérogation permanente.
test_exemption_perpetuelle_refusee if {
	inp := input_justified("ADR-014 IPC_LOCK requis par OpenBao verrouillage memoire reexamen=2035-01-01")
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

# --------------------------------------------------------------------------------------------
# Portée de l'exemption (catégories 2, 3 et 5)
# --------------------------------------------------------------------------------------------

# Catégorie 2 : règle voisine. Une exemption PLT-002 parfaitement rédigée ne lève pas PLT-001.
test_exemption_d_une_autre_regle_ne_couvre_pas if {
	inp := input_with({"io.zero-secret.exemption.PLT-002": valid_justification})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

# Catégorie 5 : ressource proche. Un préfixe de clé voisin ne doit pas être reconnu.
test_cle_de_label_voisine_ne_couvre_pas if {
	inp := input_with({"io.zero-secret.exemption.PLT-0011": valid_justification})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

test_cle_de_label_sans_prefixe_ne_couvre_pas if {
	inp := input_with({"exemption.PLT-001": valid_justification})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

# Catégorie 3 : escalade par combinaison. Le service exempté et le service fautif sont voisins
# dans le même fichier ; l'exemption ne franchit pas la frontière du service qui la porte.
test_exemption_d_un_autre_service_ne_couvre_pas if {
	inp := {
		"context": {"evaluated_at": "2026-08-25", "environment": "dev"},
		"compose": {"services": {
			"openbao": {
				"image": "docker.io/openbao/openbao:2",
				"cap_add": ["IPC_LOCK"],
				"labels": {label_key: valid_justification},
			},
			"agent": {
				"image": "docker.io/library/debian:bookworm-slim",
				"cap_add": ["IPC_LOCK"],
			},
		}},
	}

	vs := compose.violation with input as inp
	pairs(vs) == {["PLT-001", "agent"]}
	not compose.allow with input as inp
}

# Catégorie 3 : contournement par la forme. La forme liste des labels est valide en Compose ;
# ce lot ne la reconnaît pas, et le refuse explicitement au lieu de l'ignorer — sinon une
# exemption illisible aurait la même conséquence pratique qu'une exemption valide.
test_exemption_en_forme_liste_non_reconnue if {
	inp := input_with([sprintf("%s=%s", [label_key, valid_justification])])
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000", "PLT-001"}
	not compose.allow with input as inp
}

# --------------------------------------------------------------------------------------------
# Conditions d'environnement et de contexte (catégorie 1)
# --------------------------------------------------------------------------------------------

# Exemption irréprochable, mais évaluée hors du développement local : ce lot ne statue que sur
# l'environnement de développement, donc il refuse partout ailleurs.
test_exemption_hors_developpement_refusee if {
	inp := input_at("production", "2026-08-25", {label_key: valid_justification})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
	not compose.allow with input as inp
}

test_exemption_en_staging_refusee if {
	inp := input_at("staging", "2026-08-25", {label_key: valid_justification})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

# Sans date d'évaluation, aucune date de réexamen n'est comparable : l'exemption ne peut pas
# être valide, et l'entrée elle-même est signalée.
test_exemption_sans_date_d_evaluation_refusee if {
	inp := {
		"context": {"environment": "dev"},
		"compose": {"services": openbao_with({label_key: valid_justification})},
	}

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000", "PLT-001"}
}

# --------------------------------------------------------------------------------------------
# Règles non exemptables
# --------------------------------------------------------------------------------------------

# Escalade la plus directe : utiliser le mécanisme légitime d'exemption pour lever la règle
# absolue #1 (aucun secret durable). Doit échouer quelle que soit la qualité de l'exemption.
test_exemption_ne_leve_jamais_un_secret_en_dur if {
	inp := {
		"context": {"evaluated_at": "2026-08-25", "environment": "dev"},
		"compose": {"services": {"postgres": {
			"image": "docker.io/library/postgres:17",
			"environment": {"POSTGRES_PASSWORD": "valeur-en-dur"},
			"labels": {"io.zero-secret.exemption.PLT-003": valid_justification},
		}}},
	}

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-003"}
	not compose.allow with input as inp
}

# Une entrée qu'on ne sait pas analyser ne s'exempte pas : sinon il suffirait de rendre sa
# configuration illisible et de s'auto-exempter de l'illisibilité.
test_exemption_ne_leve_jamais_une_entree_inanalysable if {
	inp := {
		"context": {"evaluated_at": "2026-08-25", "environment": "dev"},
		"compose": {"services": {"postgres": {
			"image": "docker.io/library/postgres:17",
			"ports": [5432],
			"labels": {"io.zero-secret.exemption.PLT-000": valid_justification},
		}}},
	}

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
	not compose.allow with input as inp
}

# Vérification directe de la garde `non_exemptable`, indépendamment des règles qui l'utilisent :
# la même justification, valide pour PLT-001, ne l'est jamais pour PLT-000 ni PLT-003.
test_garde_non_exemptable_sur_la_fonction_exempted if {
	inp := input_with({
		"io.zero-secret.exemption.PLT-000": valid_justification,
		"io.zero-secret.exemption.PLT-001": valid_justification,
		"io.zero-secret.exemption.PLT-003": valid_justification,
	})

	compose.exempted("PLT-001", "openbao") with input as inp
	not compose.exempted("PLT-000", "openbao") with input as inp
	not compose.exempted("PLT-003", "openbao") with input as inp
}

# Un service inexistant n'est jamais exempté : pas de nom, pas de labels, pas d'exemption.
test_exemption_sur_un_service_inexistant_refusee if {
	inp := input_justified(valid_justification)
	not compose.exempted("PLT-001", "openbao-staging") with input as inp
}
