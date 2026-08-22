# deploy/

Infrastructure as code. Modification limitée à l'environnement `dev` sans validation explicite.

```
deploy/
  opentofu/   provisionnement infrastructure
  ansible/    configuration des hôtes
  quadlets/   unités Podman (environnement local — make up/down)
  k8s/        manifestes Kubernetes durcis
```
