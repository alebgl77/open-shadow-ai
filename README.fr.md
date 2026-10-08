<p align="center"><img src="docs/assets/brand-mark.svg" width="72" alt="Emblème Open Shadow AI"></p>

# Open Shadow AI

[English](README.md) | [Français](README.fr.md) | [简体中文](README.zh-CN.md)

[![CI](https://github.com/alebgl77/open-shadow-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/alebgl77/open-shadow-ai/actions/workflows/ci.yml)
[![Licence : Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**Découvrez l'IA sur votre infrastructure, avec les preuves derrière chaque constat.**

Comprenez quels services et outils d'IA apparaissent dans votre environnement, d'où vient chaque signal et ce qu'il permet réellement d'établir. Rassemblez métadonnées réseau, inventaires des postes et signaux des annuaires Microsoft dans une interface d'investigation.

[Guide de mise en œuvre pour experts](docs/fr/README.md) · [Démarrage](#démarrage) · [Documentation et couverture linguistique](docs/README.md) · [Déploiement (référence en anglais)](docs/deployment.md) · [Qualification de production (référence en anglais)](docs/production-qualification.md) · [Exploitation des collecteurs (référence en anglais)](docs/collector-operations.md) · [Microsoft et Active Directory (référence en anglais)](docs/microsoft.md) · [SSO et SCIM (référence en anglais)](docs/sso-scim.md) · [Architecture (référence en anglais)](docs/architecture.md) · [Roadmap](docs/fr/roadmap.md)

> Logiciel en phase initiale, destiné à l'évaluation et aux pilotes maîtrisés. Une organisation par installation. Docker, Kubernetes et les environnements Microsoft réels exigent une validation opérationnelle sur votre infrastructure ; aucune certification ni aucun SLA de production ne sont revendiqués.

Le backend est en préversion **0.3.0** ; l'agent autonome pour les postes est en version **0.1.0**. Les guides anglais, français et chinois simplifié proposent les mêmes procédures de mise en œuvre. Les références détaillées et comptes rendus historiques conservent leur langue indiquée et la portée propre à leurs sources.

La console propose l'anglais, le français et le chinois simplifié avant et après connexion. La préférence de langue validée, locale au navigateur, est séparée de l'authentification ; l'anglais est utilisé sans préférence disponible ou si le stockage est bloqué. Les données brutes des sources et identifiants techniques/API conservent leurs valeurs originales. Voir la [couverture linguistique](docs/README.md).

Ces langues ont été introduites sur `main` par le [commit `7a12513`](https://github.com/alebgl77/open-shadow-ai/commit/7a12513eb1e1e3a800ba8d71f4726a3b5045b669). La préversion publiée `v0.3.0`, au commit `49a58d7`, précède la localisation. Les deux révisions sources déclarent `0.3.0` ; consignez le commit exact déployé pour vérifier les fonctionnalités disponibles et leurs preuves CI.

![Interface d'investigation Open Shadow AI avec des données de démonstration synthétiques](docs/assets/dashboard-desktop.webp)

## La découverte en mouvement

Trois schémas muets en français expliquent l'empreinte IA, les niveaux de preuve et la reprise des collecteurs. Ces illustrations éditoriales utilisent des données synthétiques ; elles sont distinctes de l'interface réelle présentée ci-dessus.

![Illustration des signaux réseau, postes et AD/Entra convergeant vers les catégories LLM, code, médias et API ; données synthétiques](docs/assets/motion/footprint.gif)

[Voir les trois schémas (référence en anglais)](docs/motion.md) · [Ouvrir/télécharger le MP4](docs/assets/motion/footprint.mp4) · [Voir l'affiche statique](docs/assets/motion/footprint.webp)

## Pourquoi ce projet

- **Des preuves vérifiables.** Distinguez observations réseau, logiciels installés, inventaire des annuaires et usage instrumenté.
- **Une infrastructure sous votre contrôle.** Hébergez l'API, les files, le stockage des événements et l'interface.
- **Une adoption progressive.** Commencez par une source de journaux ou quelques postes gérés.
- **Un catalogue ouvert.** Examinez et améliorez les signatures utilisées pour les classifications.
- **Des limites explicites.** Un signal absent reste inconnu ; une requête DNS n'est ni un prompt ni une facture.

## La direction envisagée

Voir l'empreinte. Comprendre le risque. Garder le contrôle. La [roadmap en six étapes](docs/fr/roadmap.md) prévoit une découverte enrichie, la visibilité des agents, une analyse locale facultative, des investigations sourcées, des usages encadrés et une qualification continue. Chaque étape future comporte des critères mesurables ; les technologies candidates restent des propositions à évaluer.

## Essayer l'interface

Prérequis : **Node.js 22.22.2+ (22.x)**. Lancez la démonstration isolée :

```bash
cd frontend
npm ci
npm run demo
```

Ouvrez la route `/demo` à l'adresse locale affichée par le serveur de développement. Cette session synthétique ne demande aucun identifiant backend et ne se connecte ni à vos annuaires ni à votre parc. Pour poursuivre avec l'installation complète, arrêtez le serveur de démonstration puis exécutez `cd ..`.

## Démarrage

Prérequis : Git, Python 3.12+ et un Docker Engine fonctionnel avec Compose v2. Aucun runtime Docker n'est fourni. L'interface initiale écoute en HTTP sur localhost ; les agents distants nécessitent un reverse proxy HTTPS.

```bash
git clone https://github.com/alebgl77/open-shadow-ai.git
cd open-shadow-ai
bash scripts/bootstrap.sh
docker compose config --quiet
docker compose up -d --build
docker compose exec -T api python /app/entrypoint.py python -m shadai.workers.redis_lifecycle reconcile --execute --legacy-writers-stopped
docker compose up -d --wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend
docker compose run --rm api python -m shadai.cli create-admin
```

Sous Windows, remplacez le bootstrap Bash par `./scripts/bootstrap.ps1`. Les deux préservent les secrets et la configuration existants. Utilisez `-DryRun` ou `--dry-run` pour prévisualiser.

Attendez que les nouveaux workers initialisent leurs groupes Redis réels avant la réconciliation ; réessayez si cette initialisation est encore en cours. Lors d'une mise à niveau, arrêtez tous les anciens producteurs, workers et clients de rejeu avant de lancer la version indexée. La readiness exige le schéma de rétention réconcilié. Consultez la [rétention des files (référence en anglais)](docs/queue-retention.md) et la [qualification (référence en anglais)](docs/production-qualification.md) pour les comportements de panne et la répétition isolée.

Ouvrez [localhost:3000](http://localhost:3000). Les migrations PostgreSQL s'exécutent dans le service `migrate` avant le démarrage de l'API ; les deux schémas ClickHouse sont chargés sur un volume neuf. La [mise à jour d'une installation existante (référence en anglais)](docs/deployment.md#updates) exige une migration ClickHouse distincte.

L'activation des collecteurs est explicite :

```bash
docker compose --profile syslog up -d
# After configuring Entra IDs and its separately provisioned client-secret file:
docker compose --profile entra up -d
```

Les exports AD et installations sur les postes sont réalisés par l'opérateur, selon le [guide Microsoft (référence en anglais)](docs/microsoft.md). Installer le serveur ne déclenche pas de scan automatique du parc.

Les administrateurs peuvent inscrire des collecteurs à périmètre restreint dans **Sources et couverture**, distribuer leurs clés à affichage unique par un canal privé, puis les renouveler ou les révoquer. Les collecteurs de postes, réseau et syslog disposent de files de livraison persistantes et bornées ; l'état du pipeline distingue travail en attente, entrées conservées et pertes de capture inconnues. Le [guide d'exploitation (référence en anglais)](docs/collector-operations.md) détaille inscription, reprise après redémarrage, supervision authentifiée et rétention des identités.

La [connexion OIDC et le provisionnement SCIM facultatifs (référence en anglais)](docs/sso-scim.md) gèrent l'accès à la console, notamment avec Microsoft Entra ID. Ils sont désactivés dans le déploiement de base et utilisent des identifiants distincts du collecteur d'inventaire. La connexion d'un administrateur local reste disponible pour la récupération.

## Ce qui est livré

| Fonctionnalité | État et limite pratique |
|---|---|
| Interface React d'investigation, catalogue et processus de gouvernance | Implémentés ; à évaluer avec vos données |
| Parseurs DNS/proxy et collecteur syslog | Implémentés ; le parseur et le listener doivent correspondre à la source |
| [Analyse réseau passive (référence en anglais)](docs/network-analysis.md) | Imports de métadonnées Zeek/Suricata/TShark, PCAP hors ligne facultatif ou capteur live explicitement choisi, vue des preuves `/network` ; les noms observés ne prouvent pas des requêtes IA |
| Agent pour les postes | Inventaire des processus, conteneurs, runtimes et extensions implémenté ; vérification par OS et déploiement de parc à réaliser |
| Collecteur Microsoft Entra | Inventaire des service principals et grants facultatifs implémenté ; classification IA fondée sur des mappings d'application-ID revus ; validation sur tenant réel à réaliser |
| Active Directory local | Exporteur PowerShell en lecture seule, limité aux OU ; validation RSAT/AD réel à réaliser |
| Ingestion générique d'événements | Lots authentifiés et bornés ; les adaptateurs personnalisés restent votre travail d'intégration |
| Inscription et reprise des collecteurs | Identifiants à affichage unique et portée limitée, rotation/révocation, files locales bornées et rejeu explicite des dead letters ; vérifier les résultats CI natifs et magasins du commit déployé |
| Preuves de modèle/tokens/coûts | Métadonnées instrumentées acceptées lorsqu'elles sont fournies ; les journaux réseau ne produisent pas ces valeurs |
| Autres annuaires (LDAP, Okta, Google Workspace) | Contrat d'ingestion personnalisé disponible ; connecteurs natifs prévus |
| Docker Compose | Package de déploiement et test de services CI fournis ; valider le premier démarrage |
| Kubernetes | Base pour magasins externes ; validation du cluster, ingress, sauvegardes et montée en charge à réaliser |
| SSO OIDC et provisionnement SCIM 2.0 de la console | Sous-ensemble facultatif implémenté avec guide Entra ; validation d'interopérabilité sur tenant réel à réaliser |
| Isolation multi-organisations et gestion automatisée du parc | Prévues ; une organisation par installation actuellement |
| Blocage en ligne, DLP des prompts et analyse comportementale complète | Hors du produit actuel |

## Architecture

![Architecture Open Shadow AI](docs/assets/architecture.svg)

[Schéma draw.io éditable](docs/assets/architecture.drawio) · [Mermaid et flux de données (référence en anglais)](docs/architecture.md)

Le package Python et le préfixe des variables d'environnement restent `shadai` pour compatibilité. Le nom public du projet est **Open Shadow AI**.

## Preuves, confidentialité et limites

La configuration par défaut ne stocke jamais les chemins d'URL, chaînes de requête ou user agents. À l'ingestion, les chemins sans chaîne de requête et les user agents sont comparés en mémoire aux motifs du catalogue limités aux hôtes de chaque produit ; seule l'entrée reconnue du catalogue est conservée. `privacy.match_transient_signals: false` désactive cette comparaison. Traitez noms d'utilisateur, identifiants d'appareil et exports d'annuaire comme des données personnelles ou organisationnelles. Définissez rétention et accès selon votre déploiement.

L'appartenance d'une identité expire indépendamment selon chaque observation (par défaut au plus 30 jours) ; les comptes affichés portent sur des identifiants distincts observés, pas sur l'effectif salarié. La pseudonymisation facultative du serveur affecte les nouveaux traitements et ne nettoie ni l'historique ni les files locales en clair. Les scores de risque conservent leur dernier calcul et exposent une date nullable ainsi qu'un indicateur d'obsolescence. Le nettoyage historique est une maintenance explicite et bornée ; voir [rétention et pseudonymisation des identités (référence en anglais)](docs/collector-operations.md#retain-and-pseudonymize-identities).

Une résolution DNS indique un contact avec un domaine, pas une interaction IA achevée. Une extension installée ou une application d'annuaire indique présence ou autorisation, pas usage. Les identifiants de modèle sont des preuves déclarées ; les totaux de tokens et coûts nécessitent une instrumentation. Les coûts calculés restent des estimations jusqu'à leur rapprochement avec la facturation du fournisseur.

Postes non gérés, DNS chiffré non observé, outils locaux, domaines partagés, IA intégrée aux SaaS et contournements de passerelle peuvent laisser des angles morts. Consultez le [guide de couverture (référence en anglais)](docs/collectors.md) et l'[analyse de marché (référence en anglais)](docs/market-analysis.md).

## Contribuer

Consultez [CONTRIBUTING.md (référence en anglais)](CONTRIBUTING.md), proposez une modification limitée et reproductible et fournissez des fixtures synthétiques pour les collecteurs. Signalez les vulnérabilités en privé selon [SECURITY.md (référence en anglais)](SECURITY.md).

Licence [Apache-2.0](LICENSE). Copyright des contributeurs Open Shadow AI.

Pour le dimensionnement et le déploiement progressif, voir la [planification de capacité (référence en anglais)](docs/capacity.md). Toute affirmation de débit exige des mesures sur votre charge.
