# Corrections de l'audit du 15 octobre 2026

[English](../audit-remediation-2026-10-15.md) | [Français](audit-remediation-2026-10-15.md) | [简体中文](../zh-CN/audit-remediation-2026-10-15.md)

Ce guide d'exploitation décrit les contrats corrigés pour les dix constats de l'audit global. Chaque constat constitue une modification logique ; la documentation est maintenue séparément. Il ne s'agit ni d'une annonce de version, ni d'un résultat CI du commit courant, ni d'une certification de production. Vérifiez que le code déployé contient ces modifications et conservez son commit exact, la révision de configuration et les preuves de construction. La version `0.3.0` seule ne les identifie pas. Pour les prérequis d'installation, consultez le [guide pour experts](README.md).

## 1. Modifications logiques et critères de validation

| Constat | Contrat corrigé | Vérification opérationnelle |
|---|---|---|
| F01 — Confidentialité Entra | `prepare_event` en mode de confiance s'exécute avant la sérialisation et la rétention en file. La pseudonymisation activée protège les nouveaux champs d'identité à cette frontière ; la préparation signée et les octets exacts des nouvelles tentatives restent cohérents. | Testez un inventaire synthétique avec la configuration de confidentialité prévue ; vérifiez redémarrage et nouvelles tentatives du collecteur. Les données brutes déjà conservées ne sont pas nettoyées. |
| F02 — Calcul des mots de passe | Chaque processus API admet au plus quatre opérations bcrypt simultanées dans un service borné, partagé entre vérification de connexion et hachage des mots de passe créés par un administrateur. Le travail natif s'exécute hors de la boucle événementielle ; l'annulation d'une requête ne libère pas sa capacité prématurément. | Vérifiez connexions réussies/échouées et création de comptes sous concurrence bornée. La saturation renvoie `429`, l'indisponibilité `503`, avec `Retry-After: 1` dans les deux cas. Le quota distinct de connexion par pair conserve `429` et `Retry-After: 60`. |
| F03 — Sondes Kubernetes | Les trois étapes des workers utilisent les sondes de démarrage, de vie et de disponibilité propres à leur étape, comme le générateur de qualification cible. Un PID vivant ou un Redis joignable ne peut plus masquer seul un worker bloqué. | Vérifiez initialisation, heartbeat local, progression de l'étape et dépendances réelles dans le cluster cible ; préservez le `/tmp` privé inscriptible et le contexte de sécurité existant. |
| F04 — Images maintenues | gosu sélectionne `github.com/moby/sys/user v0.4.1` au lieu de `v0.1.0` pour `CVE-2026-61801`. Les autres modules sélectionnés et compilateurs épinglés restent inchangés. Les cinq recettes maintenues passent à la révision `3`. | Reconstruisez et examinez les résultats natifs Linux amd64/arm64, les analyses des runtimes finaux et leur provenance. Les tags locaux `maintained.3` ne prouvent ni publication ni correction d'une image déjà déployée. |
| F05 — Politique du dépôt | La politique souhaitée de `main` impose une PR, les 32 contrôles liés à l'application GitHub Actions `15368`, une branche strictement à jour et l'application aux administrateurs ; force push et suppression sont désactivés et les discussions doivent être résolues. | Appliquez après revue et CI du commit courant, puis relisez les paramètres effectifs. Le nombre volontaire d'approbations du profil à mainteneur unique est `0` ; aucune approbation humaine n'est imposée. Un modèle commité n'active rien. |
| F06 — Bornes UTC | Les dates canoniques qui débordent lors de leur normalisation UTC sont invalides. Les requêtes externes reçoivent `422` ; les enveloppes internes invalides suivent le traitement d'erreur permanente, sans nouvelle tentative transitoire. | Exercez les deux directions des bornes UTC avec des dates synthétiques et vérifiez que les données invalides ne sont pas acceptées en file. |
| F07 — Isolation des enregistrements TCP | Un enregistrement malformé est rejeté indépendamment par le parseur afin de laisser passer les enregistrements TCP voisins valides. Les erreurs de livraison et l'annulation continuent de se propager. | Envoyez un enregistrement synthétique invalide entre deux valides ; vérifiez séparément refus de livraison et annulation. L'isolation du parseur n'est pas une garantie de livraison. |
| F08 — Date source Palo Alto | Une date explicite clé/valeur valide est prioritaire ; à défaut, l'en-tête RFC5424 fournit la date déclarée. Les dates absentes, NILVALUE `-` ou invalides sont rejetées au lieu d'être remplacées par l'heure d'import. | Vérifiez champs temporels de l'exporteur, fuseaux et rejeux historiques avant activation. Un champ explicite malformé est rejeté même si l'en-tête est valide. |
| F09 — Réactivation des détections | Un rejeu ancien, quelle que soit sa force, ne peut rouvrir une détection `stale` ou `archived`. Un signal entrant actuel la rouvre selon les mêmes seuils qu'une nouvelle détection. | Vérifiez rejeu et frontière des 30 jours. Un score frais inférieur à `0.70` donne `suspected`, inférieur à `0.90` donne `probable`, sinon `high_confidence` ; la force agrégée historique ne choisit pas le statut rouvert. |
| F10 — Preuves réseau | Les échantillons candidats sont fusionnés avant sélection, dédupliqués par UUID d'événement dans son périmètre, puis les dix plus récents sont conservés selon les instants UTC réels et un départage déterministe. Une arrivée ancienne n'évince pas une preuve récente au seul motif qu'elle arrive en dernier. | Vérifiez entrées désordonnées, fractions de seconde/fuseaux et doublons. La sélection ne modifie ni compteurs d'activité agrégés, ni idempotence des reçus, ni limites de preuve. |

Ces changements n'inventent pas de liens IP-poste, d'attribution à un salarié, de requêtes IA achevées, de prompts, de modèles, de totaux de tokens ou d'emplacements de fichiers sources. La cartographie distingue toujours observations réseau et installations déclarées sur les postes. Décisions et notes d'analyste restent séparées du statut automatique.

## 2. Compatibilité, confidentialité et horloges sources

F01 affecte les nouveaux lots Entra préparés ; activer la pseudonymisation ne réécrit ni les streams Redis historiques, ni AOF/sauvegardes, ni payloads en attente déjà conservés, ni magasins d'événements ou exports. Préservez les clés correspondantes et les contrôles de rétention existants. L'identification et le nettoyage de l'historique nécessitent un plan de maintenance borné, approuvé séparément, après revue des conséquences sur sauvegarde/restauration et rejeu. Ne supprimez pas les données conservées et ne changez pas les clés de chiffrement pour faire réussir une validation.

F08 rejette volontairement les enregistrements sans date. Configurez l'exporteur pour transmettre une date valide ; ne remplacez pas celle-ci par l'heure de collecte afin de rendre récentes des données anciennes. Les en-têtes RFC5424 exigent des dates calendaires RFC3339 prises en charge avec décalages valides. Les formats locaux explicites existants utilisent le fuseau source configuré. Les dates BSD historiques omettent l'année et l'infèrent de l'horloge de traitement ; elles ne conviennent pas à un rejeu historique non ambigu. Utilisez alors une date contenant l'année. La rétention évalue toujours la date d'observation déclarée.

F02 présente les réponses connues de saturation/indisponibilité en anglais, français et chinois simplifié sans exposer les erreurs brutes du serveur. Les quatre places sont par processus API, sans quota de mots de passe global au cluster. Le dimensionnement exige toujours des mesures ; ajouter des processus API modifie le travail natif total admis. Conservez limites par pair et réglages des proxys de confiance.

La correction du bootstrap écrit des fins de ligne LF uniquement dans les fichiers secrets nouvellement créés ; la sortie CRLF sous Windows peut introduire un retour chariot rejeté par ClickHouse. Les fichiers existants restent inchangés octet pour octet : les secrets CRLF déjà générés ne sont donc pas réparés. Ne modifiez ni ne remplacez sur place les fichiers de mots de passe en service : les installations existantes concernées nécessitent une rotation coordonnée des identifiants, cohérente avec ceux des magasins et les sauvegardes. Les contrôles de confidentialité et de sécurité existants restent en vigueur.

## 3. Préparer et vérifier le code

Utilisez un checkout de confiance de la révision revue et un environnement de développement jetable. Cet exemple Bash installe les dépendances commitées vérifiées par hash et les projets locaux ; sous Windows, remplacez l'activation par `./tmp/audit-remediation-env/Scripts/Activate.ps1` dans PowerShell. Ne réutilisez pas cet environnement comme runtime de production.

```bash
python -m venv tmp/audit-remediation-env
source tmp/audit-remediation-env/bin/activate
python -m pip install --only-binary=:all: --require-hashes -r requirements/build.txt
python -m pip install --only-binary=:all: --require-hashes -r requirements/development.txt
python -m pip install --no-deps --no-build-isolation . ./agent
git rev-parse HEAD
```

Exécutez les groupes de régression ciblés et les contrôles sources existants depuis la racine du dépôt. Ces commandes sont des procédures de vérification, sans affirmer qu'un commit courant précis les a réussies :

```bash
python -m pytest -q tests/test_entra_privacy.py tests/test_password_work.py tests/test_kubernetes_worker_probes.py tests/test_repository_governance.py tests/test_canonical_utc_bounds.py tests/test_syslog_record_isolation.py tests/test_paloalto_timestamps.py tests/test_detection_reactivation.py tests/test_network_evidence_ordering.py
python -m pytest -q tests/test_service_builds.py tests/test_image_scan_layout.py tests/test_monitoring_alerts.py
python -m ruff check src tests agent/shadai_agent migrations scripts
python scripts/lock-dependencies.py --check
python scripts/verify-image-pins.py
```

Avec la chaîne Node.js 22.x prise en charge, vérifiez aussi le frontend localisé :

```bash
cd frontend
npm ci
npm test
npm run build
cd ..
```

Examinez les résultats complets, y compris tests ignorés et refus de l'environnement ; n'additionnez pas les comptes de suites qui se recouvrent. Un test source local ou un binaire compilé pour une autre cible ne remplace pas les constructions OCI natives, preuves d'analyse, qualification des vrais magasins ou contrôles ACL Windows.

Les fixtures de gouvernance ne sont chargées que lors de l'exécution de leurs tests, ce qui permet de collecter une sélection de tests runtime sans les fichiers propres au dépôt tout en conservant toutes les assertions de gouvernance. Vérifiez les deux corrections avec les jobs natifs runtime et Windows concernés pour le commit exact revu.

## 4. Reconstruire et redéployer de manière maîtrisée

Avant la fenêtre de maintenance, sauvegardez magasins, configuration et clés correspondantes, répétez la restauration et suspendez collecteurs/producteurs distants et écritures applicatives. Préservez volumes privés et identifiants. Depuis un schéma plus ancien, terminez d'abord la [procédure de mise à niveau existante, en anglais](../deployment.md#updates) ; les commandes suivantes ne remplacent pas l'ordre des migrations ClickHouse/PostgreSQL/Redis.

Pour une installation déjà sur le schéma audité, reconstruisez et redémarrez les services de base revus avec sa configuration privée existante :

```bash
docker compose config --quiet
docker compose build
docker compose up -d
docker compose up -d --wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend
docker compose ps --all
curl --fail http://127.0.0.1:8443/health
curl --fail http://127.0.0.1:8443/ready
```

Utilisez les mêmes fichiers Compose facultatifs que l'installation pour SSO/supervision ; reconstruisez/recréez collecteurs activés et les deux profils de supervision selon leurs procédures, si applicables. Un redémarrage de la base seule ne met à jour ni Prometheus/node-exporter facultatifs ni agents distants. Vérifiez chaque image déployée par rapport à sa recette/source revue et ses preuves de construction. Remplacer des fichiers ne supprime pas leurs anciens octets dans les couches inférieures et ne répare pas automatiquement les conteneurs précédemment lancés. La CI du projet ne publie ni ne déploie ces images.

Pour Kubernetes, préparez un overlay privé avec images immuables approuvées, routes vers les magasins externes et secrets existants. Suivez le [guide Kubernetes en anglais](../../deploy/kubernetes/README.md), rendez et validez côté serveur la configuration préparée avant application. Pour la base préparée :

```bash
kubectl kustomize deploy/kubernetes/base > rendered.yaml
kubectl apply --dry-run=server -k deploy/kubernetes/base
kubectl -n open-shadow-ai get pods
kubectl -n open-shadow-ai rollout status deployment/api
```

Validez sondes et dépendances de chaque étape, ingress/TLS, NetworkPolicy, interruptions et restauration dans le cluster réel. Démarrage/vie restent locaux ; la disponibilité résout les fichiers secrets montés via `/app/entrypoint.py`. Conservez délai de sonde 6 secondes, démarrage toutes les 5 secondes/60 échecs, vie/disponibilité toutes les 10 secondes/3 échecs et `/tmp` inscriptible de 64 MiB. Un manifeste rendu ou une API saine ne qualifie pas le cluster.

## 5. Requalification et preuves CI

Répétez dans un environnement Docker dédié, jetable et suffisamment dimensionné. Utilisez un nouveau répertoire privé par exécution, examinez le plan avant de l'exécuter et conservez le rapport lié au code. Ces commandes concernent le laboratoire isolé, jamais les données de production :

```bash
python scripts/qualification-lab.py plan --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
python scripts/qualification-lab.py run --execute --docker-context default --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
```

Suivez la [qualification et la reprise, en anglais](../production-qualification.md), pour délais, reprise et nettoyage vérifié. Constructions/analyses/provenance natives doivent couvrir les deux architectures Linux prises en charge ; AD/Entra/SSO réels et capacité/RPO/RTO de l'installation exigent leurs propres preuves. Ne masquez pas les constats et n'assouplissez pas les protections des sondes, fichiers, rétention ou analyses pour obtenir un résultat vert.

Comparez les métadonnées CI au commit exact revu :

```bash
git rev-parse HEAD
gh run list --workflow ci.yml --limit 10 --json databaseId,headSha,event,status,conclusion
```

Sélectionnez l'exécution, le commit et l'événement correspondants et vérifiez les 32 contrôles PR obligatoires, toutes les entrées de matrice comprises. Après fusion, vérifiez séparément les preuves de signature du push sur main pour cette source ; une ancienne exécution verte ne prouve pas un nouveau commit. Consultez les états des jobs/étapes sans télécharger journaux bruts, annotations ou artefacts mixtes contenant des données sensibles.

## 6. Appliquer et vérifier la gouvernance du dépôt

Suivez la [gouvernance du dépôt](repository-governance.md) pour la requête exacte revue, ses prérequis et les champs de relecture. F05 exige une application externe autorisée après la CI du commit courant, pas le seul commit de `.github/main-protection.json`. Examinez les rulesets avec la protection de branche. Le profil à mainteneur unique impose PR et contrôles aux administrateurs mais aucune approbation humaine ; relever ce nombre exige une décision revue sur les responsables et accès. Ce guide n'implique aucun accès supplémentaire, fusion, release, déploiement de production ou purge historique.
