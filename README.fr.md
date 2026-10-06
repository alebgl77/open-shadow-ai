# Open Shadow AI

[![CI](https://github.com/alebgl77/open-shadow-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/alebgl77/open-shadow-ai/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)


**Découvrez les usages IA de votre organisation, avec les preuves derrière chaque constat.**

Open Shadow AI rassemble des métadonnées réseau, des inventaires de postes et des informations Microsoft dans une interface d'investigation auto-hébergée. Le projet vise une installation par organisation, de la startup au pilote d'un parc géré.

Logiciel en phase de développement : les packages Docker/Kubernetes et les scripts sont fournis pour évaluation. Un déploiement réel Docker, Kubernetes, AD ou Entra nécessite une validation opérationnelle. Aucune certification ou couverture exhaustive n'est revendiquée.

## La découverte en mouvement

Trois schémas muets en français illustrent l'empreinte IA, les niveaux de preuve et la reprise des collecteurs. Ces illustrations éditoriales utilisent des données synthétiques ; elles ne sont pas des captures de l'interface.

![Illustration des signaux réseau, postes et AD/Entra convergeant vers les catégories LLM, code, médias et API ; données synthétiques](docs/assets/motion/footprint.gif)

[Voir les trois schémas](docs/motion.md) · [Ouvrir/télécharger le MP4](docs/assets/motion/footprint.mp4) · [Voir l'affiche statique](docs/assets/motion/footprint.webp)

## Essayer l'interface

Prérequis : **Node.js 22.22.2+ (22.x)**. Lancez la démonstration isolée :

```bash
cd frontend
npm ci
npm run demo
```

Ouvrez la route `/demo` à l'adresse locale affichée par le serveur de développement. Cette session utilise des données synthétiques, sans identifiants backend ni connexion à vos annuaires ou à votre parc. Pour poursuivre avec l'installation complète, arrêtez le serveur de démonstration puis exécutez `cd ..`.

## Démarrage

Prérequis : Git, Python 3.12+, Docker Engine et Compose v2 fonctionnels.

```powershell
git clone https://github.com/alebgl77/open-shadow-ai.git
cd open-shadow-ai
./scripts/bootstrap.ps1
docker compose config --quiet
docker compose up -d --build
docker compose run --rm api python -m shadai.cli create-admin
```

Sous Linux/macOS, remplacer le bootstrap PowerShell par `bash scripts/bootstrap.sh`. Le bootstrap génère les secrets manquants sans afficher leur valeur ni remplacer ceux déjà présents. `-DryRun` permet une prévisualisation.

L'interface est accessible sur [localhost:3000](http://localhost:3000). Cette écoute locale HTTP est destinée à l'évaluation ; prévoir une terminaison HTTPS avant de connecter des postes distants.

## Choisir les sources

- **AD local :** exporter des utilisateurs et ordinateurs dans des OU explicites avec RSAT. Le script ne modifie pas l'annuaire.
- **Entra :** activer le profil Docker après création d'une application dédiée et attribution des permissions de lecture minimales.
- **Parc Windows hybride :** tester l'agent sur une OU pilote, puis utiliser vos outils GPO, Intune ou Configuration Manager. L'installation du serveur ne déploie aucun agent.
- **Réseau :** sélectionner un parseur DNS/proxy correspondant au format réellement envoyé.
- **Autres annuaires :** utiliser le contrat d'ingestion générique ; les connecteurs natifs restent à développer.

[Guide Microsoft et AD](docs/microsoft.md) · [Déploiement et exploitation](docs/deployment.md) · [SSO et SCIM](docs/sso-scim.md) · [Couverture des collecteurs](docs/collectors.md)

La connexion OIDC et le provisionnement SCIM 2.0 des comptes de la console sont facultatifs, avec un guide Microsoft Entra ID. Ils sont désactivés par défaut et utilisent des secrets distincts du collecteur d'inventaire. Un administrateur local reste disponible pour la récupération. SCIM gère les accès à la console ; il ne collecte pas les salariés ni les appareils observés.

## Lire les résultats correctement

Une résolution DNS n'est pas une preuve de prompt. Une application présente dans l'annuaire ou une extension installée n'est pas une preuve d'usage. Les identifiants de modèle, tokens et coûts nécessitent des événements instrumentés ; les coûts calculés sont des estimations.

Les chemins d'URL, chaînes de requête et user-agents ne sont jamais stockés. À l'ingestion, le chemin (sans sa chaîne de requête) et le user-agent sont comparés en mémoire aux motifs du catalogue, limités aux hôtes de chaque produit ; seule l'entrée du catalogue reconnue est conservée. `privacy.match_transient_signals: false` désactive cette comparaison.

Les tableaux distinguent observations, inventaires et informations indisponibles. Les appareils non gérés, modèles locaux non collectés, proxys de contournement, domaines partagés et IA intégrée aux SaaS peuvent rester invisibles.

## Du pilote à l'entreprise

Le package fournit une base Docker Compose, une configuration Kubernetes pour bases externes et des procédures d'export/installation. Avant production : tester sauvegarde et restauration, capacité, mises à jour, accès, politique de conservation et supervision des collecteurs. Le sous-ensemble OIDC/SCIM livré nécessite une validation avec votre fournisseur d'identité ; SAML et l'isolation multi-organisations ne sont pas implémentés.

![Architecture](docs/assets/architecture.svg)

[Analyse concurrentielle](docs/market-analysis.md) · [Contribuer](CONTRIBUTING.md) · [Signaler une vulnérabilité](SECURITY.md) · [Licence Apache-2.0](LICENSE)
