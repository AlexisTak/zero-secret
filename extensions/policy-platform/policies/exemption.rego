# Exigence couverte : contrat d'entrée et mécanisme d'exemption des politiques de conformité
#   plateforme. Une non-conformité ne peut être levée QUE par une exemption déclarée dans
#   l'artefact lui-même, portant une référence ADR et une date de réexamen bornée, et uniquement
#   pour la règle et le service qu'elle nomme, en environnement de développement.
# ADR : aucun à ce jour. Le choix Rego/OPA pour la conformité plateforme est annoncé par
#   CLAUDE.md (« Cedar (accès) + Rego/OPA (plateforme) ») mais n'a jamais été acté — cf.
#   audit.md §5.2. Un ADR reste à rédiger ; ce lot ne présume pas de son contenu et se limite
#   à l'artefact d'infrastructure qui existe réellement (deploy/compose.dev.yml).
# Date de réexamen : 2027-02-25.
#
# Invariants (refus par défaut) :
# - Aucune donnée n'est lue hors de `input` : pas d'appel réseau, pas d'état externe, pas
#   d'horloge. La date d'évaluation arrive en entrée (`input.context.evaluated_at`), comme
#   `context.requested_at` côté Cedar. L'évaluation est donc rejouable hors ligne à l'identique.
# - Toute condition d'exemption est POSITIVE : une valeur absente, illisible ou d'un type
#   inattendu rend la conjonction indéfinie, donc l'exemption invalide, donc la violation
#   maintenue. Il n'existe aucun chemin où « je n'ai pas su analyser » produise « conforme ».
# - On détecte largement, on exempte étroitement : les champs analysés pour DÉTECTER une
#   non-conformité acceptent leurs formes multiples (map et liste pour `environment`), alors que
#   le champ qui porte une EXEMPTION n'accepte qu'une seule forme (map). Une forme non reconnue
#   penche toujours du côté du refus.
package zerosecret.platform.compose

import rego.v1

# --------------------------------------------------------------------------------------------
# Contrat d'entrée
# --------------------------------------------------------------------------------------------
#
# input := {
#   "context": {
#     "evaluated_at": "AAAA-MM-JJ",         # date d'évaluation, fournie par l'appelant
#     "environment": "dev|staging|production",
#     "source": "deploy/compose.dev.yml"    # informatif, non évalué
#   },
#   "compose": { ... }                      # le fichier Compose converti en JSON, tel quel
# }
#
# Invocation prévue (aucun outil n'est ajouté par ce lot) :
#   opa eval -d policies/platform -I 'data.zerosecret.platform.compose.violation'
# avec sur stdin l'objet ci-dessus. Le câblage CI de cette évaluation sur
# deploy/compose.dev.yml est un travail distinct : il suppose un convertisseur YAML→JSON dans
# tools/, hors du périmètre de ce lot.

known_environments := {"dev", "staging", "production"}

# Plafond de durée de vie d'une exemption, exprimé ICI et jamais laissé à l'appelant : une
# exemption dont la date de réexamen dépasse ce plafond n'est pas une exemption, c'est une
# dérogation permanente déguisée.
max_exemption_days := 366

max_exemption_ns := ns if {
	ns := ((max_exemption_days * 24) * 3600) * 1000000000
}

# Longueur minimale d'une justification. Une justification de trois mots n'est pas une
# justification : elle ne permet pas à un tiers de rejuger la décision.
min_justification_chars := 32

# Règles qu'aucune exemption ne peut lever, quelle que soit sa forme.
# PLT-000 : une entrée qu'on ne sait pas analyser ne s'exempte pas, elle se corrige.
# PLT-003 : règle absolue #1 du CLAUDE.md racine (aucun secret durable). Non négociable en
#           session : la lever demanderait de modifier cette liste, ce qui est visible en revue.
non_exemptable := {"PLT-000", "PLT-003"}

# Date d'évaluation, en nanosecondes. Indéfinie si le contexte est absent, non typé ou
# syntaxiquement invalide — auquel cas aucune exemption ne peut être valide (cf. `exempted`).
evaluated_at_ns := ns if {
	is_string(input.context.evaluated_at)
	regex.match(iso_date_anchored, input.context.evaluated_at)
	ns := time.parse_ns("2006-01-02", input.context.evaluated_at)
}

iso_date_anchored := `^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])$`

valid_context if {
	is_number(evaluated_at_ns)
	input.context.environment in known_environments
}

# --------------------------------------------------------------------------------------------
# Exemptions
# --------------------------------------------------------------------------------------------
#
# Forme attendue, sur le service concerné et lui seul :
#
#   labels:
#     io.zero-secret.exemption.PLT-001: "ADR-014 IPC_LOCK requis par OpenBao reexamen=2027-02-23"
#
# La valeur doit contenir une référence ADR (`ADR-nnn`) et une date de réexamen
# (`reexamen=AAAA-MM-JJ`) strictement postérieure à la date d'évaluation et distante d'au plus
# `max_exemption_days`. Les accents sont proscrits dans le marqueur `reexamen=` : il est destiné
# à être analysé par un outil, pas lu.

exemption_label_prefix := "io.zero-secret.exemption."

default exempted(_, _) := false

exempted(rule_id, service) if {
	# 1. La règle admet d'être exemptée.
	not rule_id in non_exemptable

	# 2. Le contexte d'évaluation est exploitable.
	valid_context

	# 3. Ce lot ne couvre que l'environnement de développement local : hors dev, aucune
	#    exemption n'est honorée, quelle que soit sa qualité. Un lot dédié aux environnements
	#    déployés devra statuer explicitement — d'ici là, refus par défaut.
	input.context.environment == "dev"

	# 4. L'exemption est portée par le service visé, sous la forme map uniquement.
	labels := labels_of(service)
	key := sprintf("%s%s", [exemption_label_prefix, rule_id])
	value := labels[key]

	# 5. La justification tient debout.
	justification_valid(value)
}

# Labels du service, uniquement sous forme d'objet. La forme liste (`- "cle=valeur"`), pourtant
# valide en Compose, n'est pas reconnue ici : elle est signalée par PLT-000 (type inattendu) et
# ne peut donc pas servir de support à une exemption.
labels_of(service) := l if {
	svc := service_objects[service]
	is_object(svc.labels)
	l := svc.labels
}

default justification_valid(_) := false

justification_valid(text) if {
	is_string(text)
	j := trim_space(text)
	count(j) >= min_justification_chars
	regex.match(`ADR-[0-9]{3,}`, j)

	now := evaluated_at_ns
	review := review_date(j)

	# Bornes de durée de vie, des deux côtés :
	# - une exemption dont le réexamen est échu (ou fixé au jour même) ne protège plus rien ;
	# - une exemption dont le réexamen est repoussé au-delà du plafond est une dérogation
	#   permanente. `reexamen=2035-01-01` doit être refusé aussi sûrement qu'une date échue.
	review > now
	review - now <= max_exemption_ns
}

# Date de réexamen extraite de la justification. Indéfinie si le marqueur est absent, présent
# plusieurs fois de façon ambiguë, ou syntaxiquement invalide.
review_date(j) := ns if {
	m := regex.find_all_string_submatch_n(review_marker, j, -1)
	count(m) == 1
	ns := time.parse_ns("2006-01-02", m[0][1])
}

review_marker := `reexamen=(20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01]))`
