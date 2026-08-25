# Exigence couverte : un fichier Compose du dépôt (aujourd'hui `deploy/compose.dev.yml`, seul
#   artefact d'infrastructure réellement présent) n'est déclaré conforme que si AUCUN de ses
#   services n'élève ses privilèges, n'expose un port hors de la boucle locale, n'embarque de
#   secret littéral, n'utilise d'image non épinglée, ne désactive un mécanisme
#   d'authentification, ni ne monte l'hôte en écriture — sauf exemption nominative, justifiée
#   par un ADR et bornée dans le temps (voir exemption.rego).
# ADR : aucun à ce jour (cf. exemption.rego et audit.md §5.2). Règles absolues adossées :
#   CLAUDE.md racine #1 (aucun secret durable) pour PLT-003, #2 (refus par défaut) pour PLT-000.
# Tests : policies/tests/platform/ (cas nominaux ET cas d'attaque, par règle).
# Date de réexamen : 2027-02-25.
#
# Portée assumée de ce lot :
# - Il ne couvre QUE la forme Compose. Ni OpenTofu, ni Ansible, ni quadlet Podman, ni manifeste
#   Kubernetes : ces artefacts n'existent pas encore dans deploy/ malgré la table de CLAUDE.md.
#   Écrire des règles pour des fichiers absents produirait une couverture fictive.
# - Il ne couvre pas les services construits localement (`build:`), les formes longues de
#   `volumes`, les plages de ports, ni la forme liste de `labels`. Ces formes ne sont pas
#   ignorées : elles sont refusées par PLT-000 (« je ne sais pas analyser » ⇒ refus), et leur
#   prise en charge est un élargissement de périmètre qui devra s'accompagner de ses tests.
# - `expose:` n'est pas traité : il ne publie rien sur l'hôte. Le cloisonnement inter-conteneurs
#   relève des réseaux, hors périmètre de ce lot.
#
# Ce qu'une décision de ce fichier N'EST PAS : une décision d'accès. Aucun principal, aucune
# action, aucune ressource ici — l'accès est traité par Cedar dans policies/access/.
package zerosecret.platform.compose

import rego.v1

# --------------------------------------------------------------------------------------------
# Décision
# --------------------------------------------------------------------------------------------

# Refus par défaut. `allow` n'est vrai que si l'entrée a pu être analysée ENTIÈREMENT et que le
# corpus n'a rien à redire. L'absence de violation ne suffit pas : une entrée vide, tronquée ou
# d'un type inattendu produit zéro violation « naturellement », ce qui est précisément le piège
# des politiques de conformité. `valid_input` ferme ce chemin.
default allow := false

allow if {
	valid_input
	count(violation) == 0
}

valid_input if {
	valid_context
	is_object(input.compose)
	is_object(input.compose.services)
	count(input.compose.services) > 0
}

# Sévérités indicatives, portées par la politique plutôt que par l'outil qui l'exécute.
severity := {
	"PLT-000": "high",
	"PLT-001": "critical",
	"PLT-002": "high",
	"PLT-003": "critical",
	"PLT-004": "medium",
	"PLT-005": "high",
	"PLT-006": "medium",
}

# `object.get` avec valeur par défaut : un identifiant de règle absent du barème ne doit pas
# rendre la violation indéfinie (elle disparaîtrait silencieusement du rapport).
viol(rule_id, service, detail) := {
	"rule": rule_id,
	"service": service,
	"detail": detail,
	"severity": object.get(severity, rule_id, "high"),
}

# --------------------------------------------------------------------------------------------
# Accès à l'entrée
# --------------------------------------------------------------------------------------------

services := s if {
	is_object(input.compose)
	is_object(input.compose.services)
	s := input.compose.services
}

# Seuls les services dont la définition est un objet sont analysables. Les autres sont signalés
# par PLT-000 ci-dessous, jamais ignorés.
service_objects[name] := svc if {
	svc := services[name]
	is_object(svc)
}

array_field(svc, field) := v if {
	is_array(svc[field])
	v := svc[field]
}

default has_key(_, _) := false

has_key(obj, k) if {
	keys := object.keys(obj)
	k in keys
}

# --------------------------------------------------------------------------------------------
# PLT-000 — entrée inanalysable, ambiguë ou hors périmètre (jamais exemptable)
# --------------------------------------------------------------------------------------------

# Ces deux gardes passent par des règles nommées (`compose_is_object`, `services_is_object`)
# plutôt que par `not is_object(input.compose)` écrit directement. Ce n'est pas cosmétique :
# une référence absente passée en argument d'un appel nié rend le CORPS ENTIER indéfini, donc
# la violation ne se déclenche pas — l'entrée la plus incomplète serait alors la mieux traitée.
# Une règle sans argument, elle, est simplement indéfinie, et sa négation vaut vrai.
violation contains v if {
	not compose_is_object
	v := viol("PLT-000", "-", "input.compose absent ou de type inattendu")
}

violation contains v if {
	compose_is_object
	not services_is_object
	v := viol("PLT-000", "-", "input.compose.services absent ou de type inattendu")
}

compose_is_object if is_object(input.compose)

services_is_object if is_object(input.compose.services)

violation contains v if {
	count(services) == 0
	v := viol("PLT-000", "-", "aucun service décrit : entrée vide, refus par défaut")
}

violation contains v if {
	not valid_context
	v := viol(
		"PLT-000", "-",
		"contexte d'évaluation incomplet : context.evaluated_at (AAAA-MM-JJ) et context.environment requis",
	)
}

violation contains v if {
	some name, svc in services
	not is_object(svc)
	v := viol("PLT-000", name, sprintf("définition de service illisible pour '%s'", [name]))
}

# Un service sans image n'est pas analysable par ce lot (cas d'un service `build:`).
violation contains v if {
	some name, svc in service_objects
	not has_key(svc, "image")
	v := viol("PLT-000", name, "service sans 'image' : hors périmètre de ce lot, refus par défaut")
}

# Champ présent mais d'un type qui empêche l'analyse. C'est la classe de contournement la plus
# économique : donner à l'analyseur une forme qu'il ne sait pas lire pour qu'il ne trouve rien.
expected_types := {
	"cap_add": "array",
	"command": "array_or_string",
	"devices": "array",
	"entrypoint": "array_or_string",
	"env_file": "array_or_string",
	"environment": "object_or_array",
	"image": "string",
	"ipc": "string",
	"labels": "object",
	"network_mode": "string",
	"pid": "string",
	"ports": "array",
	"privileged": "boolean",
	"security_opt": "array",
	"userns_mode": "string",
	"volumes": "array",
}

violation contains v if {
	some name, svc in service_objects
	some field, kind in expected_types
	value := svc[field]
	not type_ok(kind, value)
	v := viol("PLT-000", name, sprintf("champ '%s' de type inattendu : analyse impossible, refus par défaut", [field]))
}

type_ok("array", x) if is_array(x)

type_ok("string", x) if is_string(x)

type_ok("object", x) if is_object(x)

type_ok("boolean", x) if is_boolean(x)

type_ok("array_or_string", x) if is_array(x)

type_ok("array_or_string", x) if is_string(x)

type_ok("object_or_array", x) if is_object(x)

type_ok("object_or_array", x) if is_array(x)

# Entrées de listes dont la forme n'est pas couverte (forme longue d'un volume, port numérique,
# plage de ports…). Refus explicite plutôt que silence.
violation contains v if {
	some name, svc in service_objects
	some entry in array_field(svc, "ports")
	not is_string(entry)
	not is_object(entry)
	v := viol("PLT-000", name, sprintf("entrée de 'ports' de forme non reconnue : %v", [entry]))
}

violation contains v if {
	some name, svc in service_objects
	some entry in array_field(svc, "volumes")
	not is_string(entry)
	v := viol("PLT-000", name, sprintf("entrée de 'volumes' de forme non reconnue (forme longue non couverte) : %v", [entry]))
}

# --------------------------------------------------------------------------------------------
# PLT-001 — élévation de privilège du conteneur
# --------------------------------------------------------------------------------------------

violation contains v if {
	some name, svc in service_objects
	svc.privileged == true
	not exempted("PLT-001", name)
	v := viol("PLT-001", name, "conteneur privilégié (privileged: true)")
}

# Aucune capacité Linux n'est autorisée par défaut : la liste blanche est vide, chaque ajout se
# justifie nominativement. IPC_LOCK (verrouillage mémoire d'OpenBao) inclus.
violation contains v if {
	some name, svc in service_objects
	some capability in array_field(svc, "cap_add")
	not exempted("PLT-001", name)
	v := viol("PLT-001", name, sprintf("capacité Linux ajoutée sans exemption : %v", [capability]))
}

violation contains v if {
	some name, svc in service_objects
	some opt in array_field(svc, "security_opt")
	is_string(opt)
	unconfined(opt)
	not exempted("PLT-001", name)
	v := viol("PLT-001", name, sprintf("confinement du noyau désactivé : %s", [opt]))
}

default unconfined(_) := false

unconfined(opt) if indexof(lower(opt), "unconfined") != -1

unconfined(opt) if indexof(lower(opt), "label:disable") != -1

# Partage d'espace de noms avec l'hôte : équivalent fonctionnel d'un conteneur privilégié.
violation contains v if {
	some name, svc in service_objects
	some field in {"pid", "ipc", "network_mode", "userns_mode"}
	value := svc[field]
	is_string(value)
	startswith(lower(value), "host")
	not exempted("PLT-001", name)
	v := viol("PLT-001", name, sprintf("espace de noms partagé avec l'hôte : %s: %s", [field, value]))
}

violation contains v if {
	some name, svc in service_objects
	count(array_field(svc, "devices")) > 0
	not exempted("PLT-001", name)
	v := viol("PLT-001", name, "accès direct à un périphérique de l'hôte (devices)")
}

# Le montage du socket du moteur de conteneurs vaut privilège root sur l'hôte, sans que le
# service n'ait jamais à déclarer `privileged`. Contournement classique — traité au même rang.
violation contains v if {
	some name, svc in service_objects
	some mount in array_field(svc, "volumes")
	is_string(mount)
	regex.match(`(?i)(docker|podman|containerd|crio)[^:]*\.sock`, mount)
	not exempted("PLT-001", name)
	v := viol("PLT-001", name, sprintf("socket du moteur de conteneurs monté dans le conteneur : %s", [mount]))
}

# --------------------------------------------------------------------------------------------
# PLT-002 — exposition réseau
# --------------------------------------------------------------------------------------------
#
# Convention constatée dans deploy/compose.dev.yml : toute publication est liée à 127.0.0.1.
# La règle en fait une exigence, pour tous les ports et pas seulement les « sensibles » : une
# liste de ports sensibles est une liste à trous, et le service qui écoute sur un port non listé
# est exactement celui qu'on oublie.

violation contains v if {
	some name, svc in service_objects
	some entry in array_field(svc, "ports")
	is_string(entry)
	not regex.match(loopback_published_port, entry)
	not exempted("PLT-002", name)
	v := viol("PLT-002", name, sprintf("port publié hors de la boucle locale : %s", [entry]))
}

loopback_published_port := `^(?:127\.0\.0\.1|\[::1\]):[0-9]{1,5}:[0-9]{1,5}(?:/(?:tcp|udp))?$`

violation contains v if {
	some name, svc in service_objects
	some entry in array_field(svc, "ports")
	is_object(entry)
	not loopback_host_ip(entry)
	not exempted("PLT-002", name)
	v := viol("PLT-002", name, sprintf("port publié sans host_ip de boucle locale : %v", [entry]))
}

default loopback_host_ip(_) := false

loopback_host_ip(entry) if entry.host_ip in {"127.0.0.1", "::1"}

# --------------------------------------------------------------------------------------------
# PLT-003 — secret durable (règle absolue #1 — JAMAIS exemptable)
# --------------------------------------------------------------------------------------------
#
# Aucun appel à `exempted` dans cette section : c'est volontaire et cela se voit en revue. La
# garde `non_exemptable` d'exemption.rego est une seconde barrière, pas la première.

env_pairs contains {"service": name, "name": k, "value": val} if {
	some name, svc in service_objects
	is_object(svc.environment)
	some k, val in svc.environment
}

env_pairs contains {"service": name, "name": k, "value": val} if {
	some name, svc in service_objects
	is_array(svc.environment)
	some entry in svc.environment
	is_string(entry)
	idx := indexof(entry, "=")
	idx > 0
	k := substring(entry, 0, idx)
	val := substring(entry, idx + 1, -1)
}

violation contains v if {
	some pair in env_pairs
	secret_name(pair.name)
	literal_value(pair.value)
	v := viol(
		"PLT-003", pair.service,
		sprintf("valeur littérale dans une variable d'environnement sensible : %s", [pair.name]),
	)
}

violation contains v if {
	some name, svc in service_objects
	has_key(svc, "env_file")
	v := viol("PLT-003", name, "env_file interdit : aucun secret durable dans un fichier .env (règle absolue #1)")
}

default secret_name(_) := false

# Deux familles : les termes qui sont sans ambiguïté des secrets où qu'ils apparaissent, et les
# termes courts (key, pin, pw) délimités par des séparateurs pour éviter les faux positifs de
# sous-chaîne (« MAPPING » contient « PIN »).
secret_name(k) if regex.match(`(?i)(password|passwd|passphrase|secret|credential|token)`, k)

secret_name(k) if regex.match(`(?i)(^|_)(key|keys|apikey|api_key|pin|pw)(_|$)`, k)

default literal_value(_) := false

# Une référence pure à une variable de l'hôte n'est pas un secret durable écrit dans le dépôt.
# Une référence AVEC valeur par défaut (`${VAR:-motdepasse}`) en est un : la valeur par défaut
# est littérale et sera utilisée dès que la variable est absente.
literal_value(val) if {
	is_string(val)
	count(trim_space(val)) > 0
	not regex.match(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`, val)
	not regex.match(`^\$[A-Za-z_][A-Za-z0-9_]*$`, val)
}

literal_value(val) if is_number(val)

literal_value(val) if is_boolean(val)

# Déplacer le secret de l'environnement vers la ligne de commande est le contournement immédiat
# de la règle précédente. Même traitement.
arg_strings contains {"service": name, "arg": value} if {
	some name, svc in service_objects
	some field in {"command", "entrypoint"}
	value := svc[field]
	is_string(value)
}

arg_strings contains {"service": name, "arg": item} if {
	some name, svc in service_objects
	some field in {"command", "entrypoint"}
	value := svc[field]
	is_array(value)
	some item in value
	is_string(item)
}

violation contains v if {
	some entry in arg_strings
	some m in regex.find_all_string_submatch_n(cli_secret_pattern, entry.arg, -1)
	not path_like(m[2])
	not env_reference(m[2])
	v := viol(
		"PLT-003", entry.service,
		sprintf("secret littéral probable en argument de ligne de commande : %s=…", [m[1]]),
	)
}

cli_secret_pattern := `(?i)(-{0,2}[a-z0-9_-]*(?:token|password|passwd|secret|api[_-]?key|passphrase|credential)[a-z0-9_-]*)=(\S+)`

default path_like(_) := false

path_like(s) if startswith(s, "/")

path_like(s) if startswith(s, "./")

path_like(s) if startswith(s, "../")

path_like(s) if startswith(s, "~")

default env_reference(_) := false

env_reference(s) if regex.match(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`, s)

# --------------------------------------------------------------------------------------------
# PLT-004 — image non épinglée
# --------------------------------------------------------------------------------------------
#
# Convention constatée dans deploy/compose.dev.yml : registre explicite et étiquette figée
# (`postgres:17`, `openbao:2`, `debian:bookworm-slim`). Une seule exception s'y trouve
# aujourd'hui, `otel/opentelemetry-collector-contrib:latest`, que cette règle refuse — elle
# n'est pas couverte par une exemption et constitue donc une non-conformité réelle, pas un
# faux positif. Corriger deploy/ est hors du périmètre de ce lot.

violation contains v if {
	some name, svc in service_objects
	is_string(svc.image)
	not pinned_image(svc.image)
	not exempted("PLT-004", name)
	v := viol("PLT-004", name, sprintf("image non épinglée : %s", [svc.image]))
}

mutable_tags := {"latest", "main", "master", "edge", "stable", "nightly", "dev", "test"}

default pinned_image(_) := false

# Épinglage par empreinte : forme la plus forte, acceptée telle quelle.
pinned_image(ref) if regex.match(`@sha256:[0-9a-f]{64}$`, ref)

pinned_image(ref) if {
	indexof(ref, "@") == -1
	tag := image_tag(ref)
	regex.match(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`, tag)
	normalized := lower(tag)
	not normalized in mutable_tags
}

# L'étiquette se cherche dans le DERNIER segment du chemin : `registre.local:5000/postgres`
# contient un « : » qui n'est pas une étiquette mais un port de registre. Confondre les deux
# ferait passer une image non épinglée pour épinglée.
image_tag(ref) := tag if {
	segments := split(ref, "/")
	last_index := count(segments) - 1
	last := segments[last_index]
	idx := indexof(last, ":")
	idx > 0
	tag := substring(last, idx + 1, -1)
}

# --------------------------------------------------------------------------------------------
# PLT-005 — authentification désactivée / service en mode développement
# --------------------------------------------------------------------------------------------
#
# Présent deux fois dans deploy/compose.dev.yml (`POSTGRES_HOST_AUTH_METHOD: trust`, OpenBao
# `server -dev`), justifié en commentaire mais nulle part de façon exploitable par un outil.
# C'est l'objet même du mécanisme d'exemption : rendre la justification lisible par la machine
# et lui donner une date de péremption.

violation contains v if {
	some pair in env_pairs
	auth_disabling(pair.name, pair.value)
	not exempted("PLT-005", pair.service)
	v := viol("PLT-005", pair.service, sprintf("authentification affaiblie par la variable %s", [pair.name]))
}

default auth_disabling(_, _) := false

auth_disabling(k, val) if {
	upper(k) == "POSTGRES_HOST_AUTH_METHOD"
	lower_string(val) == "trust"
}

auth_disabling(k, val) if {
	upper(k) == "ALLOW_EMPTY_PASSWORD"
	lower_string(val) in {"yes", "true", "1"}
}

auth_disabling(k, val) if {
	secret_name(k)
	is_string(val)
	trim_space(val) == ""
}

lower_string(val) := normalized if {
	is_string(val)
	normalized := lower(val)
}

violation contains v if {
	some entry in arg_strings
	dev_mode_arg(entry.arg)
	not exempted("PLT-005", entry.service)
	v := viol("PLT-005", entry.service, sprintf("service démarré en mode développement : %s", [entry.arg]))
}

default dev_mode_arg(_) := false

dev_mode_arg(s) if regex.match(`(?i)(^|\s)-{1,2}dev(-mode)?(\s|$)`, s)

# --------------------------------------------------------------------------------------------
# PLT-006 — montage de l'hôte en lecture-écriture
# --------------------------------------------------------------------------------------------
#
# Un montage lié (bind) accessible en écriture donne au conteneur un droit d'écriture sur
# l'arborescence du poste — y compris sur les scripts que le conteneur exécute lui-même.
# deploy/compose.dev.yml respecte déjà cette règle (`:ro,Z` sur ses deux montages liés) ; elle
# est écrite pour empêcher la régression, pas pour signaler l'existant.

violation contains v if {
	some name, svc in service_objects
	some mount in array_field(svc, "volumes")
	is_string(mount)
	bind_source(mount)
	opts := mount_options(mount)
	not read_only(opts)
	not exempted("PLT-006", name)
	v := viol("PLT-006", name, sprintf("montage de l'hôte en lecture-écriture : %s", [mount]))
}

mount_source(mount) := src if {
	parts := split(mount, ":")
	src := parts[0]
}

default bind_source(_) := false

bind_source(mount) if startswith(mount_source(mount), "/")

bind_source(mount) if startswith(mount_source(mount), "./")

bind_source(mount) if startswith(mount_source(mount), "../")

bind_source(mount) if startswith(mount_source(mount), "~")

mount_options(mount) := opts if {
	parts := split(mount, ":")
	count(parts) >= 3
	opts := parts[2]
}

mount_options(mount) := "" if {
	parts := split(mount, ":")
	count(parts) < 3
}

default read_only(_) := false

read_only(opts) if "ro" in split(opts, ",")
