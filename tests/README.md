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

`tests/e2e/jit_flow_demo.sh` (`make demo-jit`) : démonstration reproductible du parcours JIT
complet (identité → décision → credential éphémère → audit), orchestrant les preuves déjà
existantes contre une PostgreSQL et un SoftHSM2 réels — pas un nouveau mock. Documente aussi,
explicitement, ce qu'elle ne prouve pas (mTLS interne, cérémonie WebAuthn avec un authentificateur
matériel, performance).
