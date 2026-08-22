# Modèle de menaces — console-web

**Dernière révision** : 2026-08-22 — **Déclencheur** : lot L0.5, avant tout code console

## Périmètre

Interface utilisateur, rendu serveur (TypeScript). **Aucune logique de sécurité côté client** —
c'est la contrainte de conception la plus importante de ce composant : toute décision, toute
vérification doit être reproduite côté serveur (`admin-api`, `access-broker`) ; le client ne
fait qu'afficher et transmettre.

## Actifs

- La session utilisateur (jeton de session côté serveur, pas un secret d'accès au sens du
  système zero-secret lui-même — mais sa compromission permettrait d'agir au nom de
  l'utilisateur dans l'interface).
- L'intégrité du rendu — une page compromise pourrait afficher une fausse décision ou capturer
  des saisies (motif, justification) avant leur envoi légitime.
- La confiance de l'utilisateur dans ce qu'il voit à l'écran (une décision `DENY` affichée comme
  `ALLOW`, par exemple, casserait la garantie de bout en bout même si le serveur a raison).

## Entrées non fiables

| Entrée | Origine | Analyseur | Couverte par fuzzing ? |
|---|---|---|---|
| Réponses API (`access-broker`, `admin-api`) | Backend, réseau | Client HTTP standard, pas de logique de confiance ajoutée côté rendu | Sans objet — la validation de fond est déjà faite côté serveur |
| Saisies utilisateur (motif, justification, recherche) | Utilisateur | Échappement systématique avant rendu (XSS), validation de schéma avant envoi | Non prévu — surface classique web, couverte par les pratiques standard plutôt que par du fuzzing dédié |

## STRIDE

| Menace | Scénario concret | Probabilité | Impact | Mesure compensatoire | Risque résiduel |
|---|---|---|---|---|---|
| **S**poofing | Une page de phishing imite `console-web` pour capturer des identifiants | Faible pour l'authentification elle-même (WebAuthn lie l'assertion au domaine — scénario 1), mais possible pour capturer motif/justification avant l'étape WebAuthn | Moyen (pas d'accès direct au système, mais ingénierie sociale facilitée) | Aucune logique de sécurité côté client signifie qu'il n'y a rien à voler côté client qui donnerait un accès direct — l'authentification reste protégée par WebAuthn quel que soit ce qui se passe avant | Le vol de motif/justification saisis avant l'étape d'authentification reste possible sur un domaine usurpé — risque résiduel assumé, relevant de la sensibilisation utilisateur plus que du code |
| **T**ampering | Modification du DOM ou des requêtes pour afficher un état différent de la réalité serveur | Moyenne (toute page web est manipulable côté client par un utilisateur ou une extension) | Faible si aucune décision réelle n'en dépend (« aucune logique de sécurité côté client ») | Toute action sensible est revérifiée côté serveur (`admin-api`, `access-broker`) ; le rendu client n'est qu'un affichage | Un affichage trompeur pourrait induire l'utilisateur en erreur (ex. lui faire croire qu'un accès a été révoqué alors qu'il ne l'a pas été) sans compromettre le système lui-même — risque d'expérience utilisateur, pas de sécurité du système, mais à ne pas négliger pour la confiance |
| **R**epudiation | Sans objet direct — ce composant ne produit pas d'événement d'audit lui-même, il relaie des actions vers des composants qui en produisent | Non applicable | Non applicable | Les événements d'audit sont produits par `access-broker`/`admin-api`, pas par `console-web` | Non applicable ici — le risque de répudiation existe, mais porte sur les composants qui produisent réellement l'audit |
| **I**nformation Disclosure | Fuite de données affichées (décisions, journal, identités) via une faille XSS ou une session mal isolée | Moyenne (surface web classique) | Moyen à élevé selon la donnée exposée | Rendu serveur (moins de logique côté client à compromettre qu'un SPA classique), échappement systématique, budget de dépendances plafonné (`CLAUDE.md` racine) | Le rendu serveur réduit mais n'élimine pas la surface XSS classique — reste un risque résiduel standard du développement web, à couvrir par les pratiques OWASP habituelles |
| **D**enial of Service | Saturation de l'interface (moins critique, le plan de contrôle tolère l'indisponibilité) | Moyenne | Faible (n'affecte pas le plan de données ni les credentials déjà émis) | Architecture à trois plans : l'indisponibilité de l'interface n'affecte pas l'accès déjà accordé | Un `console-web` indisponible bloque l'administration et la demande d'accès via interface, mais pas le fonctionnement du système déjà en cours — impact borné par conception |
| **E**levation of Privilege | Le client falsifie un rôle ou une permission affichée pour obtenir un accès non autorisé via l'interface | Faible si aucune décision n'est prise côté client | Élevé si la contrainte « aucune logique de sécurité côté client » est violée quelque part | Revue de code systématique sur ce point précis — c'est une règle absolue du `CLAUDE.md` racine (Stack : « aucune logique de sécurité côté client ») | Le risque résiduel est une régression future qui introduirait une vérification côté client par commodité — à surveiller par revue, pas seulement par cette règle écrite |

## LINDDUN — volet vie privée

Affiche des données personnelles (identités, activité) déjà traitées en amont par `admin-api`
et `audit-collector` — n'introduit pas de nouveau traitement, mais élargit la surface
d'exposition visuelle (capture d'écran, session non verrouillée sur un poste partagé). Pas de
donnée biométrique.

## Scénarios d'attaque testés

| Menace | Test | Statut |
|---|---|---|
| Décision côté client contournant le serveur | `tests/adversarial/` — vérifier qu'aucune route ne permet d'agir sans validation serveur | Non écrit |
| XSS sur un champ texte libre (motif, justification) | `tests/adversarial/` — injection dans un champ affiché ailleurs | Non écrit |
| Session non isolée entre utilisateurs | `tests/adversarial/` — fuite de session sur poste partagé | Non écrit |

## Hypothèses de sécurité

- `access-broker` et `admin-api` revérifient systématiquement toute action initiée depuis
  l'interface — ce composant ne fait aucune hypothèse inverse.
- Le navigateur de l'utilisateur applique correctement les protections WebAuthn (liaison à
  l'origine) — ce composant en dépend sans le vérifier lui-même.
- Le budget de dépendances est plafonné et suivi (règle absolue #10 du `CLAUDE.md` racine) — une
  dépendance front-end non justifiée élargirait la surface d'attaque sans bénéfice proportionné.
