# Gouvernance du dépôt

[English](../repository-governance.md) | [Français](repository-governance.md) | [简体中文](../zh-CN/repository-governance.md)

La politique souhaitée et revue pour `alebgl77/open-shadow-ai` se trouve dans [`.github/main-protection.json`](../../.github/main-protection.json). Commiter ce fichier n'active pas la protection de branche GitHub. Son application doit être effectuée séparément par un administrateur autorisé du dépôt, puis vérifiée par une nouvelle lecture API. Ce fichier est une requête complète de mise à jour de la branche `main`, pas un relevé de ses paramètres effectifs.

## Politique à mainteneur unique

La politique impose les pull requests, une branche à jour et les 32 contextes de contrôles PR obligatoires de la [CI](../../.github/workflows/ci.yml). Chaque contexte est lié à l'application GitHub Actions, ID `15368` ; un contrôle du même nom émis par une autre application ne peut le satisfaire. Les obligations s'appliquent aussi aux administrateurs. Force push et suppression de branche sont désactivés, les discussions doivent être résolues et aucune dérogation au passage par une PR n'est configurée.

`required_approving_review_count` vaut volontairement `0` tant que le dépôt a un seul mainteneur. La configuration de revue PR non nulle conserve l'obligation de PR sans demander une approbation que l'auteur ne peut donner à sa propre demande. Ce profil n'impose aucune approbation humaine et ne remplace pas une revue indépendante du code/de la sécurité. Il invalide les revues devenues obsolètes à chaque nouveau commit poussé. Si un second mainteneur est nommé par un changement d'accès autorisé séparément, revoyez cette politique et relevez le nombre à au moins `1` pour exiger une revue humaine indépendante. Ce modèle n'accorde aucun accès au dépôt.

Les contrôles couvrent Python 3.12/3.13, frontend, métadonnées réseau, PowerShell, intégration Compose, sécurité des dépendances, agents hors ligne, images applicatives, constructions des services maintenus et qualification de production. La matrice de signature s'exécute seulement après un push sur `main` ; elle ne constitue pas un prérequis de PR. Exiger ses 20 exécutions réservées à main sur les PR bloquerait leur fusion indéfiniment.

## Revue et application

Exécutez les tests du contrat hors ligne depuis la racine du dépôt, dans l'environnement de développement vérifié par hash du projet :

```sh
python -m pytest -q tests/test_repository_governance.py
python -m ruff check tests/test_repository_governance.py
```

Ces tests analysent le workflow réel avec un chargeur YAML sûr et développent ses matrices littérales sans évaluer d'expressions GitHub. Ils rejettent contrôles manquants ou dupliqués, liaisons d'application erronées, changements de nom/condition non pris en charge et écarts au profil revu à mainteneur unique. Ils n'interrogent pas GitHub et ne prouvent pas l'application effective.

Avant application, examinez politique et commit exacts, confirmez les droits d'administration actuels, inspectez protection de branche et rulesets existants, et vérifiez la réussite de tous les contrôles obligatoires pour le commit courant de la PR. Mettez à jour et retestez le modèle si noms de jobs ou dimensions de matrice changent. Une règle incompatible ou une évolution concurrente de politique exige une nouvelle revue ; ne l'écrasez pas aveuglément.

Un administrateur autorisé peut inspecter l'état courant avec GitHub CLI :

```sh
gh api repos/alebgl77/open-shadow-ai/branches/main
gh api repos/alebgl77/open-shadow-ai/branches/main/protection
gh api repos/alebgl77/open-shadow-ai/rulesets
```

Un `404` sur l'endpoint de protection doit être interprété avec les droits d'accès et les réponses de branche/rulesets ; il ne prouve pas seul l'absence de protection. Une fois les prérequis revus satisfaits, appliquez cette requête exacte depuis la racine du dépôt :

```sh
gh api --method PUT repos/alebgl77/open-shadow-ai/branches/main/protection --input .github/main-protection.json
gh api repos/alebgl77/open-shadow-ai/branches/main/protection
gh api repos/alebgl77/open-shadow-ai/branches/main
```

Vérifiez l'état renvoyé, sans supposer qu'une requête réussie a installé chaque paramètre :

- `required_status_checks.strict` vaut `true` ; `checks` contient exactement les 32 paires contexte/application distinctes du modèle. GitHub peut renseigner l'ancienne liste `contexts` dans sa réponse bien que la requête l'envoie vide.
- `enforce_admins.enabled` vaut `true` ; la réponse de branche contient `protected: true`.
- `required_pull_request_reviews` est non nul, avec `0` approbation requise, invalidation des revues obsolètes activée, revue des propriétaires de code désactivée et approbation du dernier push désactivée. Aucun utilisateur, équipe ou application de contournement n'est présent.
- Résolution des discussions activée ; force push et suppression désactivés. GitHub représente ces champs de réponse par des objets contenant `enabled`, au lieu des booléens de la requête.
- Aucune restriction de push ou exception non revue n'est apparue. Examinez les rulesets avec la protection de branche avant de déclarer la politique effective vérifiée.

Conservez une trace datée, liée au code, de la requête revue et des métadonnées de relecture bornées. N'y incluez ni tokens d'authentification, ni journaux CI bruts, ni données du dépôt sans rapport. Revérifiez après évolution des workflows ou de la gouvernance. Les administrateurs peuvent ensuite modifier la protection : cette configuration ne constitue pas une frontière de sécurité immuable.

Le contrat API, dont la valeur valide zéro approbation pour un mainteneur unique et les contrôles liés à leur application, est documenté dans [l'API REST de protection de branche GitHub](https://docs.github.com/en/rest/branches/branch-protection?apiVersion=2022-11-28#update-branch-protection).
