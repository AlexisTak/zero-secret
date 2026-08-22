# zs-crypto — façade cryptographique

Ce crate est le **seul** point d'entrée cryptographique du projet. Tout le reste du dépôt
en dépend et n'importe aucune bibliothèque crypto directement.

Ces instructions priment sur le `CLAUDE.md` racine dans ce dossier.

## Ne fais rien ici sans validation humaine explicite

Ajouter une suite, changer un algorithme, modifier un paramètre, toucher à la période de
recouvrement : chacune de ces actions se prépare avec le sous-agent `referent-crypto`, se
documente par un ADR, et attend une validation. Décris ce que tu ferais, puis arrête-toi.

## Invariants

1. **Aucune primitive écrite ici.** On compose des bibliothèques auditées. Si une opération
   n'existe dans aucune bibliothèque retenue, ce n'est pas une invitation à l'implémenter.
2. **L'API expose des intentions, pas des algorithmes.** `seal_audit_event`, `establish_channel`,
   `sign_decision` — jamais `ecdsa_sign` ni `aes_gcm_encrypt` dans la surface publique.
3. **Toute suite est versionnée** : `<intention>/vN`, décrite dans une configuration signée.
4. **La vérification accepte les versions de la période de recouvrement ; l'émission n'utilise
   que la version courante.** Une suite retirée est refusée explicitement, jamais ignorée.
5. **Hybridation stricte** : une signature ou un échange hybride n'est valide que si les deux
   composantes le sont. Aucun chemin ne doit permettre de n'en valider qu'une.
6. **Comparaisons en temps constant** pour tout secret, empreinte ou tag d'authentification.
   Elles sont fournies ici et nulle part ailleurs.
7. **Aucune clé privée ne quitte le HSM.** Les opérations sur clés critiques sont déléguées à
   `zs-hsm`. Ce crate ne manipule que des clés publiques et du matériel éphémère.
8. **Effacement du matériel sensible** en mémoire après usage (`zeroize`), y compris sur les
   chemins d'erreur.
9. **Toute suite est déclarée au CBOM.** Une suite ajoutée sans entrée CBOM fait échouer la
   construction — c'est voulu, ne contourne pas.

## Exigences de test

- Vecteurs de test Wycheproof et vecteurs officiels de chaque spécification, exécutés en CI.
- Tests de non-régression sur le refus : suite retirée refusée, hybride à composante unique
  refusée, version inconnue refusée, algorithme `none` refusé.
- Fuzzing de tout analyseur d'entrée (structures signées, attestations, jetons).
- Couverture ≥ 95 %. Une ligne non couverte dans ce crate doit être justifiée.
- Toute nouvelle suite s'accompagne d'une mesure — pas d'une estimation — de son impact sur la
  taille des messages et la latence.

## Cibles post-quantiques

```
audit-seal/v1   → ECDSA P-256
audit-seal/v2   → ECDSA P-256 + ML-DSA-65        (hybride, cible)
channel-kex/v1  → X25519
channel-kex/v2  → X25519 + ML-KEM-768            (hybride, cible)
```

Échéance structurante : à partir de 2027, l'ANSSI n'accepte plus en qualification les produits
sans composante post-quantique.
