# Cas de test des règles PLT-000 à PLT-006 de policies/platform/compose.rego.
#
# Chaque règle a au moins un cas nominal ET un cas de refus. Les cas de refus couvrent les six
# catégories imposées par policies/CLAUDE.md, transposées d'un principal vers une configuration :
#
#   1. configuration légitime hors conditions .. exemption valide mais environnement ≠ dev,
#                                                exemption échue (voir exemption_test.rego)
#   2. voisin qui ne doit pas bénéficier ....... `[::1]` accepté / `0.0.0.0` refusé,
#                                                registre:port confondu avec une étiquette,
#                                                empreinte sha256 tronquée
#   3. escalade par combinaison ................ exemption PLT-001 valide + secret littéral,
#                                                socket du moteur monté sans `privileged`,
#                                                secret déplacé vers la ligne de commande
#   4. requête ambiguë ou partielle ............ port numérique, image non chaîne, contexte
#                                                absent, forme longue de volume
#   5. ressource proche hors périmètre ......... `--api-key=/chemin` (chemin, pas un secret),
#                                                `POSTGRES_HOST_AUTH_METHOD` ≠ nom sensible
#   6. dépassement de durée de vie ............. borné dans exemption_test.rego (durée de vie
#                                                d'une exemption)
#
# Les assertions portent sur l'ENSEMBLE EXACT des identifiants de règle déclenchés, pas sur une
# simple appartenance : un test qui vérifierait `"PLT-001" in ids` passerait aussi si la
# politique déclenchait cinq autres règles au passage. On veut prouver ce qui est refusé et,
# tout autant, ce qui ne l'est pas.
package zerosecret.platform.compose_test

import data.zerosecret.platform.compose
import rego.v1

# --------------------------------------------------------------------------------------------
# Fabriques et aides
# --------------------------------------------------------------------------------------------

dev_context := {
	"evaluated_at": "2026-08-25",
	"environment": "dev",
	"source": "deploy/compose.dev.yml",
}

input_for(svcs) := {"context": dev_context, "compose": {"services": svcs}}

# Service conforme minimal, utilisé comme base : tout ce qu'un cas ajoute est donc la seule
# cause possible d'une violation.
conformant := {
	"image": "docker.io/library/postgres:17",
	"ports": ["127.0.0.1:5432:5432"],
}

rule_ids(vs) := {v.rule | some v in vs}

pairs(vs) := {[v.rule, v.service] | some v in vs}

services_of(vs) := {v.service | some v in vs}

# --------------------------------------------------------------------------------------------
# Cas nominal
# --------------------------------------------------------------------------------------------

test_nominal_service_conforme_est_autorise if {
	inp := input_for({"postgres": object.union(conformant, {
		"environment": {"POSTGRES_DB": "zero_secret"},
		"volumes": ["zero-secret-postgres-data:/var/lib/postgresql/data"],
	})})

	vs := compose.violation with input as inp
	count(vs) == 0
	compose.allow with input as inp
}

# --------------------------------------------------------------------------------------------
# PLT-000 — entrée inanalysable, ambiguë ou hors périmètre
# --------------------------------------------------------------------------------------------

test_plt000_entree_vide_refusee if {
	inp := {"context": dev_context, "compose": {"services": {}}}
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
	not compose.allow with input as inp
}

test_plt000_compose_absent_refuse if {
	inp := {"context": dev_context}
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
	not compose.allow with input as inp
}

# Variante voisine : l'objet `compose` existe mais ne décrit aucun service. Les deux cas sont
# testés séparément parce qu'ils empruntent deux gardes différentes, et que la seconde ne se
# déclenche que si la première a été franchie.
test_plt000_services_absent_refuse if {
	inp := {"context": dev_context, "compose": {"volumes": {"zero-secret-postgres-data": null}}}
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
	not compose.allow with input as inp
}

test_plt000_services_de_type_inattendu_refuse if {
	inp := {"context": dev_context, "compose": {"services": ["postgres"]}}
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
	not compose.allow with input as inp
}

# Catégorie 4 : requête partiellement remplie. Le service est irréprochable, le contexte manque.
test_plt000_contexte_absent_refuse_un_service_conforme if {
	inp := {"compose": {"services": {"postgres": conformant}}}
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
	not compose.allow with input as inp
}

test_plt000_date_evaluation_illisible_refusee if {
	inp := {
		"context": {"evaluated_at": "25/08/2026", "environment": "dev"},
		"compose": {"services": {"postgres": conformant}},
	}
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
}

test_plt000_environnement_inconnu_refuse if {
	inp := {
		"context": {"evaluated_at": "2026-08-25", "environment": "prod"},
		"compose": {"services": {"postgres": conformant}},
	}
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
}

test_plt000_service_sans_image_refuse if {
	inp := input_for({"builder": {"build": {"context": "."}}})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
}

test_plt000_definition_de_service_illisible_refusee if {
	inp := input_for({"postgres": "docker.io/library/postgres:17"})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
}

# Catégorie 4 : donner à l'analyseur une forme qu'il ne sait pas lire ne doit jamais produire
# « conforme ». Un port numérique est valide en Compose et publie sur toutes les interfaces.
test_plt000_port_numerique_refuse if {
	inp := input_for({"postgres": {"image": "docker.io/library/postgres:17", "ports": [5432]}})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
	not compose.allow with input as inp
}

test_plt000_champ_de_type_inattendu_refuse if {
	inp := input_for({"postgres": object.union(conformant, {"cap_add": "IPC_LOCK"})})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
}

test_plt000_volume_forme_longue_refuse if {
	inp := input_for({"postgres": object.union(conformant, {"volumes": [{
		"type": "bind",
		"source": "./softhsm",
		"target": "/init",
	}]})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
}

# --------------------------------------------------------------------------------------------
# PLT-001 — élévation de privilège
# --------------------------------------------------------------------------------------------

test_plt001_conteneur_privilegie_refuse if {
	inp := input_for({"postgres": object.union(conformant, {"privileged": true})})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
	not compose.allow with input as inp
}

test_plt001_privileged_false_est_conforme if {
	inp := input_for({"postgres": object.union(conformant, {"privileged": false})})
	vs := compose.violation with input as inp
	count(vs) == 0
}

# Liste blanche vide : IPC_LOCK, pourtant légitime pour OpenBao, n'échappe pas à la règle sans
# exemption nominative.
test_plt001_capacite_linux_refusee_sans_exemption if {
	inp := input_for({"openbao": object.union(conformant, {"cap_add": ["IPC_LOCK"]})})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

test_plt001_confinement_desactive_refuse if {
	inp := input_for({"postgres": object.union(conformant, {"security_opt": ["seccomp:unconfined"]})})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

test_plt001_profil_seccomp_explicite_est_conforme if {
	inp := input_for({"postgres": object.union(conformant, {"security_opt": ["seccomp:/etc/seccomp/pg.json"]})})
	vs := compose.violation with input as inp
	count(vs) == 0
}

test_plt001_espace_de_noms_hote_refuse if {
	inp := input_for({"postgres": object.union(conformant, {"pid": "host"})})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

test_plt001_espace_de_noms_service_est_conforme if {
	inp := input_for({"postgres": object.union(conformant, {"pid": "service:openbao"})})
	vs := compose.violation with input as inp
	count(vs) == 0
}

# Catégorie 3 : escalade par combinaison. Rien n'est « privilégié » ici — le montage du socket
# du moteur de conteneurs suffit à obtenir root sur l'hôte. Deux règles distinctes doivent
# tomber : l'élévation de privilège et le montage en écriture.
test_plt001_socket_moteur_conteneurs_refuse if {
	inp := input_for({"agent": object.union(conformant, {"volumes": ["/run/podman/podman.sock:/run/podman/podman.sock"]})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001", "PLT-006"}
	not compose.allow with input as inp
}

# Le même socket monté en lecture seule reste une élévation de privilège : le confinement en
# lecture ne protège pas d'une API qui crée des conteneurs.
test_plt001_socket_moteur_conteneurs_en_lecture_seule_refuse_aussi if {
	inp := input_for({"agent": object.union(conformant, {"volumes": ["/run/podman/podman.sock:/run/podman/podman.sock:ro"]})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-001"}
}

# --------------------------------------------------------------------------------------------
# PLT-002 — exposition réseau
# --------------------------------------------------------------------------------------------

test_plt002_publication_toutes_interfaces_refusee if {
	inp := input_for({"postgres": {"image": "docker.io/library/postgres:17", "ports": ["5432:5432"]}})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-002"}
	not compose.allow with input as inp
}

test_plt002_publication_0000_refusee if {
	inp := input_for({"postgres": {"image": "docker.io/library/postgres:17", "ports": ["0.0.0.0:5432:5432"]}})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-002"}
}

# Catégorie 2 : voisin. `[::1]` est la boucle locale IPv6 et doit passer ; toute autre adresse
# littérale, non.
test_plt002_boucle_locale_ipv6_conforme if {
	inp := input_for({"openbao": {"image": "docker.io/openbao/openbao:2", "ports": ["[::1]:8200:8200"]}})
	vs := compose.violation with input as inp
	count(vs) == 0
}

test_plt002_adresse_locale_voisine_refusee if {
	inp := input_for({"postgres": {"image": "docker.io/library/postgres:17", "ports": ["127.0.0.2:5432:5432"]}})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-002"}
}

test_plt002_forme_longue_sans_host_ip_refusee if {
	inp := input_for({"postgres": {
		"image": "docker.io/library/postgres:17",
		"ports": [{"target": 5432, "published": 5432}],
	}})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-002"}
}

test_plt002_forme_longue_avec_host_ip_loopback_conforme if {
	inp := input_for({"postgres": {
		"image": "docker.io/library/postgres:17",
		"ports": [{"target": 5432, "published": 5432, "host_ip": "127.0.0.1"}],
	}})

	vs := compose.violation with input as inp
	count(vs) == 0
}

# Restriction documentée : les plages de ports ne sont pas analysées, donc refusées.
test_plt002_plage_de_ports_refusee if {
	inp := input_for({"postgres": {
		"image": "docker.io/library/postgres:17",
		"ports": ["127.0.0.1:5432-5442:5432-5442"],
	}})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-002"}
}

# --------------------------------------------------------------------------------------------
# PLT-003 — secret durable (règle absolue #1)
# --------------------------------------------------------------------------------------------

test_plt003_secret_litteral_en_variable_refuse if {
	inp := input_for({"postgres": object.union(conformant, {"environment": {"POSTGRES_PASSWORD": "valeur-en-dur"}})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-003"}
	not compose.allow with input as inp
}

# La forme liste d'`environment` est équivalente à la forme map en Compose : l'ignorer aurait
# créé un contournement d'une ligne.
test_plt003_secret_litteral_en_forme_liste_refuse if {
	inp := input_for({"postgres": object.union(conformant, {"environment": ["POSTGRES_PASSWORD=valeur-en-dur"]})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-003"}
}

test_plt003_reference_a_une_variable_de_l_hote_conforme if {
	inp := input_for({"postgres": object.union(conformant, {"environment": {"POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}"}})})

	vs := compose.violation with input as inp
	count(vs) == 0
}

# Catégorie 2 : voisin immédiat du cas conforme. La valeur par défaut d'une interpolation est
# un littéral, utilisé dès que la variable est absente de l'environnement.
test_plt003_valeur_par_defaut_d_interpolation_refusee if {
	inp := input_for({"postgres": object.union(conformant, {"environment": {"POSTGRES_PASSWORD": "${POSTGRES_PASSWORD:-valeur-par-defaut}"}})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-003"}
}

test_plt003_env_file_refuse if {
	inp := input_for({"postgres": object.union(conformant, {"env_file": [".env"]})})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-003"}
}

# Catégorie 3 : escalade par déplacement. Interdire les secrets dans `environment` sans regarder
# `command` déplace le problème d'une ligne.
test_plt003_secret_deplace_en_ligne_de_commande_refuse if {
	inp := input_for({"openbao": object.union(conformant, {"command": ["server", "-dev-root-token-id=valeur-en-dur"]})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-003"}
}

# Catégorie 5 : ressource proche mais hors périmètre. Un CHEMIN vers un fichier de clé n'est
# pas un secret ; le refuser rendrait la règle inapplicable et pousserait à la contourner.
test_plt003_chemin_de_fichier_en_argument_conforme if {
	inp := input_for({"collector": object.union(conformant, {"command": ["--api-key=/etc/otel/api.key"]})})

	vs := compose.violation with input as inp
	count(vs) == 0
}

test_plt003_variable_non_sensible_conforme if {
	inp := input_for({"postgres": object.union(conformant, {"environment": {"POSTGRES_DB": "zero_secret"}})})

	vs := compose.violation with input as inp
	count(vs) == 0
}

# --------------------------------------------------------------------------------------------
# PLT-004 — image non épinglée
# --------------------------------------------------------------------------------------------

test_plt004_etiquette_latest_refusee if {
	inp := input_for({"collector": {"image": "docker.io/otel/opentelemetry-collector-contrib:latest"}})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-004"}
	not compose.allow with input as inp
}

test_plt004_etiquette_latest_majuscules_refusee if {
	inp := input_for({"collector": {"image": "docker.io/otel/opentelemetry-collector-contrib:LATEST"}})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-004"}
}

test_plt004_image_sans_etiquette_refusee if {
	inp := input_for({"postgres": {"image": "docker.io/library/postgres"}})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-004"}
}

# Catégorie 2/5 : voisin trompeur. Le « : » de `registre.interne:5000` est un port de registre,
# pas une étiquette. Confondre les deux ferait passer une image flottante pour épinglée.
test_plt004_registre_avec_port_sans_etiquette_refuse if {
	inp := input_for({"postgres": {"image": "registre.interne:5000/postgres"}})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-004"}
}

test_plt004_registre_avec_port_et_etiquette_conforme if {
	inp := input_for({"postgres": {"image": "registre.interne:5000/postgres:17"}})
	vs := compose.violation with input as inp
	count(vs) == 0
}

test_plt004_empreinte_sha256_conforme if {
	inp := input_for({"postgres": {"image": "docker.io/library/postgres@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}})

	vs := compose.violation with input as inp
	count(vs) == 0
}

# Catégorie 4 : empreinte tronquée — forme ambiguë qui ne doit surtout pas être acceptée « à
# peu près ».
test_plt004_empreinte_sha256_tronquee_refusee if {
	inp := input_for({"postgres": {"image": "docker.io/library/postgres@sha256:0123456789abcdef"}})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-004"}
}

test_plt004_image_non_chaine_refusee if {
	inp := input_for({"postgres": {"image": 17}})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-000"}
}

# --------------------------------------------------------------------------------------------
# PLT-005 — authentification désactivée / mode développement
# --------------------------------------------------------------------------------------------

test_plt005_authentification_trust_refusee if {
	inp := input_for({"postgres": object.union(conformant, {"environment": {"POSTGRES_HOST_AUTH_METHOD": "trust"}})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-005"}
	not compose.allow with input as inp
}

test_plt005_authentification_scram_conforme if {
	inp := input_for({"postgres": object.union(conformant, {"environment": {"POSTGRES_HOST_AUTH_METHOD": "scram-sha-256"}})})

	vs := compose.violation with input as inp
	count(vs) == 0
}

# Un mot de passe vide n'est pas un « secret littéral » (PLT-003 ne le voit pas) : il est traité
# ici, pour qu'aucune des deux règles ne le laisse passer en croyant que l'autre s'en charge.
test_plt005_mot_de_passe_vide_refuse if {
	inp := input_for({"postgres": object.union(conformant, {"environment": {"POSTGRES_PASSWORD": ""}})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-005"}
}

test_plt005_serveur_en_mode_developpement_refuse if {
	inp := input_for({"openbao": object.union(conformant, {"command": ["server", "-dev"]})})
	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-005"}
}

test_plt005_commande_de_production_conforme if {
	inp := input_for({"openbao": object.union(conformant, {"command": ["server", "-config=/etc/openbao/config.hcl"]})})

	vs := compose.violation with input as inp
	count(vs) == 0
}

# --------------------------------------------------------------------------------------------
# PLT-006 — montage de l'hôte en lecture-écriture
# --------------------------------------------------------------------------------------------

test_plt006_montage_lie_en_ecriture_refuse if {
	inp := input_for({"softhsm-init": object.union(conformant, {"volumes": ["./softhsm/init-token.sh:/init/init-token.sh"]})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-006"}
	not compose.allow with input as inp
}

test_plt006_montage_lie_en_lecture_seule_conforme if {
	inp := input_for({"softhsm-init": object.union(conformant, {"volumes": ["./softhsm/init-token.sh:/init/init-token.sh:ro,Z"]})})

	vs := compose.violation with input as inp
	count(vs) == 0
}

# Catégorie 2 : voisin. Une option « rw » explicite ne doit pas être confondue avec « ro », et
# un volume nommé n'est pas un montage de l'hôte.
test_plt006_montage_lie_en_rw_explicite_refuse if {
	inp := input_for({"softhsm-init": object.union(conformant, {"volumes": ["/var/lib/softhsm:/var/lib/softhsm:rw"]})})

	vs := compose.violation with input as inp
	rule_ids(vs) == {"PLT-006"}
}

test_plt006_volume_nomme_conforme if {
	inp := input_for({"postgres": object.union(conformant, {"volumes": ["zero-secret-softhsm-tokens:/var/lib/softhsm/tokens"]})})

	vs := compose.violation with input as inp
	count(vs) == 0
}

# --------------------------------------------------------------------------------------------
# État réel de deploy/compose.dev.yml au 2026-08-25
# --------------------------------------------------------------------------------------------
#
# Transcription fidèle du fichier tel qu'il est aujourd'hui (les commentaires YAML, qui portent
# les justifications actuelles, disparaissent à la conversion — c'est précisément la raison
# d'être du mécanisme d'exemption par label).
#
# Ce test n'est pas décoratif : il fige l'écart constaté entre la politique et l'artefact. Si
# une règle est ajoutée ou si deploy/ est corrigé, il échoue et force à reconstater l'écart
# plutôt qu'à le découvrir en CI. Corriger deploy/compose.dev.yml est hors périmètre de ce lot.

compose_dev_reel := {
	"postgres": {
		"image": "docker.io/library/postgres:17",
		"environment": {
			"POSTGRES_DB": "zero_secret",
			"POSTGRES_HOST_AUTH_METHOD": "trust",
		},
		"ports": ["127.0.0.1:5432:5432"],
		"volumes": ["zero-secret-postgres-data:/var/lib/postgresql/data"],
		"healthcheck": {
			"test": ["CMD-SHELL", "pg_isready -U postgres"],
			"interval": "2s",
			"timeout": "3s",
			"retries": 15,
		},
	},
	"openbao": {
		"image": "docker.io/openbao/openbao:2",
		"command": ["server", "-dev"],
		"cap_add": ["IPC_LOCK"],
		"ports": ["127.0.0.1:8200:8200"],
		"healthcheck": {
			"test": ["CMD", "wget", "-q", "-O-", "http://127.0.0.1:8200/v1/sys/health?standbyok=true"],
			"interval": "2s",
			"timeout": "3s",
			"retries": 15,
		},
	},
	"softhsm-init": {
		"image": "docker.io/library/debian:bookworm-slim",
		"entrypoint": ["/bin/sh", "-c"],
		"command": ["apt-get update -qq && apt-get install -y -qq --no-install-recommends softhsm2 opensc >/dev/null && /init/init-token.sh"],
		"volumes": [
			"./softhsm/init-token.sh:/init/init-token.sh:ro,Z",
			"zero-secret-softhsm-tokens:/var/lib/softhsm/tokens",
			"zero-secret-env-out:/env-out",
		],
		"restart": "no",
	},
	"otel-collector": {
		"image": "docker.io/otel/opentelemetry-collector-contrib:latest",
		"command": ["--config=/etc/otel-collector-config.yaml"],
		"volumes": ["./otel/otel-collector-config.yaml:/etc/otel-collector-config.yaml:ro,Z"],
		"ports": ["127.0.0.1:4317:4317", "127.0.0.1:4318:4318"],
	},
}

test_compose_dev_reel_ecart_constate if {
	inp := input_for(compose_dev_reel)
	vs := compose.violation with input as inp

	# Quatre non-conformités, aucune de plus, aucune de moins.
	pairs(vs) == {
		["PLT-005", "postgres"], # POSTGRES_HOST_AUTH_METHOD: trust
		["PLT-001", "openbao"], # cap_add: IPC_LOCK
		["PLT-005", "openbao"], # command: server -dev
		["PLT-004", "otel-collector"], # image :latest
	}

	not compose.allow with input as inp
}

# Le pendant du test précédent : ce que le fichier réel fait DÉJÀ correctement doit rester
# vérifié, sinon une régression sur ces points passerait inaperçue derrière l'écart connu.
test_compose_dev_reel_points_deja_conformes if {
	inp := input_for(compose_dev_reel)
	vs := compose.violation with input as inp
	ids := rule_ids(vs)
	svcs := services_of(vs)

	# softhsm-init ne déclenche rien : image épinglée, montage lié en lecture seule, pas de
	# port publié, pas de secret en argument.
	not "softhsm-init" in svcs

	# Aucune publication de port hors boucle locale, aucun secret littéral nulle part, aucune
	# forme inanalysable.
	not "PLT-002" in ids
	not "PLT-003" in ids
	not "PLT-006" in ids
	not "PLT-000" in ids
}
