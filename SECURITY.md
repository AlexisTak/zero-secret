# Politique de sécurité

zero-secret est un prototype d'infrastructure d'accès sans secrets statiques, développé par
Alexis Gallard. Il est destiné à être audité par des tiers ; toute
vulnérabilité signalée est traitée sérieusement, y compris sur du code encore en lot L0.

## Signaler une vulnérabilité

**Ne pas ouvrir d'issue publique.** Envoyer un rapport à alexis_gallard@outlook.fr avec :

- une description de la vulnérabilité et son impact ;
- les étapes de reproduction, ou un correctif proposé le cas échéant ;
- la version ou le commit concerné.

Accusé de réception sous 5 jours ouvrés. Divulgation coordonnée : un correctif est visé avant
publication publique du détail technique, sauf accord contraire avec le rapporteur.

## Périmètre

- `apps/`, `crates/`, `pkg/` — code des composants critiques et d'orchestration.
- `policies/` — politiques Cedar et Rego.
- `deploy/` — infrastructure as code de l'environnement de référence.

Hors périmètre : dépendances tierces (à signaler à leur mainteneur — voir `make audit` et le
SBOM dans `security/sbom/` pour l'inventaire), environnements de démonstration non officiels.

## Ce que ce projet ne fait pas encore

Voir « Limites assumées » dans [docs/architecture.md](docs/architecture.md). En particulier,
la reprise après sinistre n'est pas prête et la compromission de l'IdP reste un risque critique
résiduel structurel — aucun accès critique ne doit transiter par ce système avant le lot L6.
