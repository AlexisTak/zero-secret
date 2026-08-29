#!/usr/bin/env python3
"""Contrôle statique de deploy/compose.dev.yml.

Remplace la version à base de grep, qui laissait passer les formes les plus probables d'une
régression : port non entre guillemets (`- 5432:5432`), syntaxe longue (`host_ip:`),
`network_mode: host`, `cap_add`, montage de socket. Le fichier est parsé en YAML, jamais
grepé — un motif textuel ne peut pas couvrir toutes les écritures valides d'une même
configuration Compose.

Refus par défaut (règle absolue #2) : toute erreur — PyYAML absent, fichier illisible,
structure inattendue — est un échec explicite, jamais un « OK » silencieux.

Codes de sortie : 0 conforme, 1 non conforme ou contrôle impossible.
"""

import sys

# Capacites supplementaires tolerees, par service. IPC_LOCK sur openbao empeche le noyau de
# transferer la memoire du magasin de secrets vers le swap (deploy/compose.dev.yml:28) : c est la
# configuration recommandee par OpenBao, et la retirer ferait fuir des secrets sur disque. Toute
# autre capacite, sur ce service ou un autre, doit etre justifiee puis ajoutee ici explicitement.
CAPACITES_AUTORISEES = {"openbao": {"IPC_LOCK"}}

HOTE_ATTENDU = "127.0.0.1"

SOCKETS_INTERDITES = ("docker.sock", "podman.sock", "containerd.sock")


def erreurs_ports(service, config):
    """Vérifie que chaque port publié est borné à 127.0.0.1, sous les deux syntaxes Compose."""
    out = []
    for entree in config.get("ports") or []:
        if isinstance(entree, dict):
            # Syntaxe longue : {target, published, host_ip, ...}. host_ip absent = 0.0.0.0.
            hote = entree.get("host_ip")
            if hote != HOTE_ATTENDU:
                out.append(
                    "%s: port %s publié sur host_ip=%s (attendu %s)"
                    % (service, entree.get("published", "?"), hote or "0.0.0.0 (défaut)", HOTE_ATTENDU)
                )
            continue

        # Syntaxe courte : "127.0.0.1:5432:5432", "5432:5432", 5432, "5432".
        texte = str(entree)
        segments = texte.split(":")
        if len(segments) < 3:
            # Aucune IP explicite : Compose publie sur 0.0.0.0.
            out.append("%s: port %s publié sans IP explicite (bind 0.0.0.0 par défaut)" % (service, texte))
            continue
        hote = ":".join(segments[:-2])  # supporte une IPv6 entre crochets
        if hote != HOTE_ATTENDU:
            out.append("%s: port %s publié sur %s (attendu %s)" % (service, texte, hote, HOTE_ATTENDU))
    return out


def erreurs_privileges(service, config):
    """Signale privilèges, capacités, namespaces partagés et confinement désactivé."""
    out = []

    if config.get("privileged") is True:
        out.append("%s: privileged: true" % service)

    autorisees = CAPACITES_AUTORISEES.get(service, set())
    for cap in config.get("cap_add") or []:
        if str(cap).upper() not in autorisees:
            out.append("%s: cap_add %s non justifié" % (service, cap))

    for champ in ("network_mode", "pid", "ipc", "uts"):
        valeur = config.get(champ)
        if valeur is not None and str(valeur).startswith("host"):
            out.append("%s: %s: %s — namespace de l'hôte partagé" % (service, champ, valeur))

    for opt in config.get("security_opt") or []:
        if "unconfined" in str(opt):
            out.append("%s: security_opt %s — confinement désactivé" % (service, opt))

    if str(config.get("user", "")).strip() in ("root", "0", "0:0"):
        out.append("%s: user: root explicite" % service)

    for volume in config.get("volumes") or []:
        source = volume.get("source", "") if isinstance(volume, dict) else str(volume).split(":")[0]
        if any(sock in str(source) for sock in SOCKETS_INTERDITES):
            out.append("%s: montage de socket de démon conteneur (%s)" % (service, source))

    return out


def main(chemin):
    try:
        import yaml
    except ImportError:
        print(
            "check_compose_dev: PyYAML absent — contrôle impossible, refus par défaut.\n"
            "  Installer avec: python -m pip install pyyaml",
            file=sys.stderr,
        )
        return 1

    try:
        with open(chemin, encoding="utf-8") as fichier:
            document = yaml.safe_load(fichier)
    except OSError as err:
        print("check_compose_dev: %s illisible : %s" % (chemin, err), file=sys.stderr)
        return 1
    except yaml.YAMLError as err:
        print("check_compose_dev: %s n'est pas un YAML valide : %s" % (chemin, err), file=sys.stderr)
        return 1

    services = (document or {}).get("services")
    if not isinstance(services, dict) or not services:
        print("check_compose_dev: aucune section services exploitable dans %s" % chemin, file=sys.stderr)
        return 1

    erreurs = []
    for service, config in services.items():
        if not isinstance(config, dict):
            erreurs.append("%s: définition de service inattendue (%s)" % (service, type(config).__name__))
            continue
        erreurs.extend(erreurs_ports(service, config))
        erreurs.extend(erreurs_privileges(service, config))

    if erreurs:
        for erreur in erreurs:
            print("check_compose_dev: %s" % erreur, file=sys.stderr)
        return 1

    print(
        "check_compose_dev: OK — %d service(s) vérifié(s), aucun bind non-loopback, "
        "aucun privilège non justifié" % len(services)
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: check_compose_dev.py <chemin-compose>", file=sys.stderr)
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
