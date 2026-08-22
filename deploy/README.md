# deploy/

Infrastructure as code. Modification limitée à l'environnement `dev` sans validation explicite.

```
deploy/
  compose.dev.yml   environnement de dev local (make up/down) — Postgres, OpenBao, SoftHSM2, OTel
  migrations/       migrations SQL, appliquées dans l'ordre par tools/migrate.sh
  softhsm/          script d'initialisation du token SoftHSM2 (PIN généré à l'exécution)
  otel/             config du collecteur OTel de dev
  opentofu/         provisionnement infrastructure (hors dev local)
  ansible/          configuration des hôtes
  quadlets/         unités Podman durcies pour un déploiement au-delà du dev local
  k8s/              manifestes Kubernetes durcis
```

`compose.dev.yml`, pas `quadlets/`, pilote l'environnement de dev local (`make up`) : c'est ce
que `Makefile` invoque directement. `quadlets/` est réservé à un déploiement plus proche de la
production, pas encore écrit.

Aucun secret durable dans ce dossier : mots de passe PostgreSQL, PIN SoftHSM2 et jeton root
OpenBao sont tous générés à l'exécution (`tools/migrate.sh`, `softhsm/init-token.sh`, ou par
OpenBao lui-même), jamais commités.
