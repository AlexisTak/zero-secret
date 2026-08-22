# tests/

Tests qui traversent plusieurs composants — les tests unitaires vivent avec le code qu'ils testent
(`apps/*`, `crates/*`, `pkg/*`).

```
tests/
  e2e/            parcours complet, plusieurs composants réels (make up)
  conformance/    vecteurs Wycheproof, conformité WebAuthn/FIDO2
  load/           tests de charge, objectifs de service (docs/architecture.md)
  adversarial/    les six scénarios d'attaque de docs/architecture.md, sous forme exécutable
```
