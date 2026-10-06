# Qualification de production

La qualification du laboratoire est une répétition jetable. Elle ne mesure ni la capacité d'une installation réelle, ni son RPO/RTO, ni la représentativité des signaux Microsoft ou du corpus. Vérifiez le job obligatoire `production-qualification` du commit déployé. Le moteur Docker local était arrêté pendant le développement ; aucune exécution locale des magasins, de l'OOM ou de la restauration n'est annoncée.

## Démarrage et mise à niveau

Sur une installation neuve, démarrez les magasins, la migration du catalogue et les nouveaux workers sans attendre la readiness globale. Leur initialisation crée les groupes Redis réels. Lancez ensuite la réconciliation dans l'environnement configuré, avant d'annoncer l'installation prête ou d'activer les collecteurs :

```bash
docker compose up -d --build
docker compose exec -T api python /app/entrypoint.py python -m shadai.workers.redis_lifecycle reconcile --execute --legacy-writers-stopped
docker compose up -d --wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend
```

Si les groupes ne sont pas encore initialisés, attendez leur création et relancez la réconciliation ; ne créez pas une readiness fictive. Pour une mise à niveau, arrêtez **tous** les anciens writers, workers et clients de replay avant de lancer la nouvelle version et cette commande. Sans schéma valide, l'ACK conserve prudemment les sources ; la rétention peut atteindre le plafond d'admission. Les writers doivent être arrêtés avant les magasins dans une sauvegarde froide. Voir [le contrat Redis](queue-retention.md).

## Laboratoire isolé

Un hôte Linux non root, Docker et Compose v2 sont requis. L'UID/GID de l'hôte est utilisé par l'API, les workers et les inspecteurs du laboratoire afin de lire les secrets privés ; le rapport distingue cet UID du runtime livré, `10001`. Les magasins utilisent leur entrypoint officiel. Aucun socket Docker n'est monté dans les conteneurs.

```bash
python scripts/qualification-lab.py plan --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
python scripts/qualification-lab.py run --execute --docker-context default --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
python scripts/qualification-lab.py resume --execute --docker-context default --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
python scripts/qualification-lab.py clean --docker-context default --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
python scripts/qualification-lab.py clean --execute --remove-volumes --docker-context default --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
```

Le répertoire doit être nouveau ; il est créé en `0700`, les fichiers en `0600`. Un UUID identifie les projets source et restauration ainsi que leurs labels. Le journal vérifie IDs, date de création, labels, contexte, profil, code et secrets au resume. Une annulation conserve les volumes et l'état de phase. Le nettoyage recontrôle chaque ressource ; les volumes demandent `--remove-volumes` en plus de `--execute`. Aucune suppression globale `compose down`, aucun wildcard de volume et aucun effacement de répertoire ne sont utilisés.

Le profil CI émet **1 000 événements synthétiques, 10/s, lots de 10, concurrence 2**, avec délai total par requête 5 s et drain 120 s. Ses budgets sont 1 500 s, 500 requêtes, 2 MiB par requête et 10 GiB de fichiers. Ces valeurs sont des entrées de test. Elles ne sont pas une capacité annoncée. Les UUID5 et les octets conservés identifient chaque retry ; le rapport sépare tentatives, acceptations HTTP, persistance logique unique, lignes physiques, reçus, latence HTTP et latence jusqu'au reçu PostgreSQL.

La deadline monotone commence avant la préparation des fixtures. Chaque POST et chaque GET de cible/readiness utilise un sous-processus stdlib isolé, sans proxy d'environnement ni redirect, avec TLS vérifié et réponse limitée à 64 KiB. URL, clé et octets passent uniquement par stdin borné ; aucune donnée fournisseur n'est journalisée. DNS, en-têtes et corps lents partagent le minimum du délai de requête et du budget restant. À l'expiration ou l'annulation, le child est tué puis récolté dans un budget de nettoyage séparé d'au plus 1 s par child, en concurrence bornée. Une requête expirée n'est jamais comptée comme acceptée ; son résultat serveur reste non confirmé.

Les scénarios obligatoires exécutent la charge, l'arrêt/reprise ingestion, l'arrêt corrélation, un arrêt de consumer après preuve de PEL, puis le reclaim. La restauration arrête tous les writers et magasins, archive les volumes possédés en lecture seule, valide chaque chemin/lien/hash avant import dans des volumes neufs, compare les inventaires avant les workers puis vérifie une écriture neuve et le travail en attente. Les liens ClickHouse relatifs internes sont conservés ; chemins absolus, traversal, liens sortants, appareils et FIFO sont refusés. Les helpers d'archive sont sans réseau, avec rootfs en lecture seule et capacités ciblées `DAC_READ_SEARCH`, puis `CHOWN/FOWNER` à l'import.

La restauration exige dix nouvelles acceptations distinctes, puis leurs lignes ClickHouse, reçus ingestion et reçus corrélation, ainsi que l'événement en PEL sauvegardé. La seule reprise du pending ne suffit pas. Le budget disque concerne la somme des fichiers réguliers privés de l'exécution, contrôlée avant copie/import et après copie ; les liens sont refusés. Chaque export reçoit le budget restant moins 10 MiB de réserve de métadonnées, avec au plus 1 GiB dans le tmpfs du helper. Les données des volumes et les autres tmpfs ont leurs mesures/limites distinctes ; ce plafond d'artifacts n'est pas une limite physique globale des magasins.

Redis pression est **distinct**, 32 MiB, `noeviction`, AOF, sans port publié. Les tests `redis_pressure` exécutent les phases seed/assert, y compris le refus SSO sous OOM. `SHADAI_REQUIRE_REDIS_PRESSURE=1` rend les prérequis obligatoires ; un test manquant ou skipped empêche le succès. Le manifest IDs/hashes est privé et partagé, en lecture seule pendant assert. Le clone AOF doit redémarrer un autre processus Redis. Le Redis normal n'est jamais reconfiguré en pression.

`report.json` contient les scénarios required/executed/status, les hashes du profil/code, l'environnement, les mesures et les preuves manquantes. Codes : **0** critères satisfaits ; **1** mesure/critère échoué ; **2** prérequis ou preuve absent. Des objectifs facultatifs explicites (`max_http_p95_seconds`, `max_end_to_end_p95_seconds`, `max_recovery_seconds`, `max_restore_seconds`, `minimum_precision`, `minimum_recall`) ne passent jamais sans mesure. Gardez les archives, fixtures, inventaires et secrets privés ; les artifacts CI publiés ne contiennent que rapport, hashes source et JUnit.

Un échec après la préparation et avant le premier scénario figure dans `evidence.failure` : phase, étape fixe, type d'erreur autorisé, code fixe et code de sortie borné si disponible. Le diagnostic distingue Compose, découverte des ressources, initialisation, readiness et enrollment. Si Compose et la découverte échouent tous deux, Compose reste la cause principale et la découverte apparaît dans `secondary`. Aucun argument, URL, secret, message d'exception, stdout ou stderr n'entre dans ce diagnostic ; les erreurs Docker portent les codes `docker_nonzero`, `docker_timeout`, `docker_process_error` ou `docker_output_budget`. Un diagnostic ne remplace aucune preuve manquante et ne rend pas l'exécution réussie.

## Sondes par processus

Chaque worker publie au maximum 4 KiB sous `/tmp/shadai-probe`, répertoire `0700`, fichier `0600`, par remplacement atomique. Aucun événement, compte, DSN ou erreur fournisseur n'y figure. PID, ticks de démarrage et boot ID empêchent la réutilisation d'une identité. Le heartbeat provient de la même boucle asyncio toutes les 5 s.

Startup exige l'initialisation réelle ; liveness exige un heartbeat de 0–30 s et ne contacte aucun magasin. Readiness exige le progrès local : poll ≤90 s ou handler ≤300 s, et les dépendances/états de chaque stream connus, dont `retention_ready`. Une panne de magasin laisse le processus vivant et non prêt. Purge exige un cycle **réussi** dans les 27 h et une phase bornée ; une exception suivie d'un sommeil ne devient pas un succès. Les budgets `SHADAI_PROBE_*` sont validés. Les exec readiness passent par `/app/entrypoint.py` pour résoudre les secrets ; ils n'héritent pas des DSN modifiés dans le processus worker.

Le laboratoire vérifie SIGSTOP avec une seconde réplique saine, un handler asynchrone suspendu vivant/non prêt et une panne Redis sans augmentation du compteur de redémarrage.

Les sous-commandes et attentes utilisent le budget global restant. La remise en route du seul processus volontairement suspendu et l'arrêt de son peer disposent d'un nettoyage de sécurité séparé limité à 10 s : recontrôler les IDs, exécuter réellement SIGCONT par Docker puis arrêter le peer nécessite plusieurs allers-retours au daemon. Ce nettoyage ne transforme pas un scénario interrompu en réussite. Pour le profil CI, le budget de travail est 1 500 s ; les budgets de terminaison ajoutés sont au plus 12 s (10 s Docker et, conservativement, deux nettoyages HTTP d'1 s), soit un plafond applicatif déclaré de **1 512 s**. Aucun navigateur de qualification cible n'est lancé.

## Mesures physiques

[Le profil hôte optionnel](../docker-compose.host-monitoring.yml) est Linux uniquement, sans port public, avec les montages hôte en lecture seule. Il utilise l'image officielle [node_exporter 1.12.1](https://github.com/prometheus/node_exporter/releases/tag/v1.12.1), index multiarch immuable enregistré dans `requirements/images.json`, collecteurs mémoire/filesystem uniquement. Le [Dockerfile officiel](https://github.com/prometheus/node_exporter/blob/v1.12.1/Dockerfile) décrit son entrypoint et utilisateur. Prometheus utilise un job et des règles séparés.

```bash
docker compose -f docker-compose.host-monitoring.yml up -d
```

Le laboratoire compare un scrape réel à `/proc/meminfo` et `statvfs(/)` : égalité pour les totaux, tolérance temporelle 5 % pour mémoire disponible et 1 % pour disque disponible, plancher 64 MiB. Il mesure aussi Docker stats, Redis `INFO memory` et `statvfs` de chaque volume possédé. RSS Redis, usage/cache Docker, limites et espace filesystem restent distincts ; plusieurs volumes d'un même filesystem ne sont pas additionnés. Kubernetes peut utiliser `kubelet_volume_stats_available_bytes/capacity_bytes` existants ; si absents, l'espace est **inconnu**, aucune jauge applicative physique n'est inventée.

## Qualité du catalogue

```bash
python -m shadai.qualification quality --corpus deploy/qualification/corpora/synthetic-reference.jsonl --catalog catalog/builtin --output /chemin/prive/quality.json
```

Le CLI appelle réellement `CatalogMatcher.resolve_event` et fige les hashes du catalogue. Le JSONL commence par un manifest de provenance, période, méthode de labelling et sampling frame ; chaque cas contient source/protocole, événement canonique, vérité `true/false/null` et attribution attendue. Doublons, champs inconnus, versions, non-finis et dépassements sont refusés. Limites : corpus 64 MiB, cas 64 KiB, 100 000 cas, catalogue 16 MiB total/1 MiB par fichier.

Profil, YAML et corpus sont lus une seule fois, au plus limite+1 octet, après contrôle de fichier régulier sans lien ; POSIX utilise aussi `NOFOLLOW/NONBLOCK` pour les remplacements concurrents. Les hashes correspondent aux octets effectivement parsés et indexés. Aucun sous-répertoire d'overrides n'entre dans cette évaluation figée.

Le corpus livré est **SYNTHETIC**, sans représentativité : TP=1, FP=1, FN=2, TN=1, precision=0,5, recall=1/3, F1=0,4. Un positif abstenu ou sans signal est FN. Vérité inconnue exclue du dénominateur supervisé mais présente dans la couverture. Dénominateur nul → `null` avec raison. Ambiguïtés, absence de signal et erreurs d'attribution restent séparées. Le rapport par cas contient uniquement ID/status/attribution. Ces métriques décrivent le matching de métadonnées normalisées, pas la capture, un usage réel de modèle ou une probabilité calibrée.

## Installation réelle

```bash
python -m shadai.qualification target plan --plan deploy/qualification/profiles/target-plan.json --output /chemin/prive/plan.json
python -m shadai.qualification target preflight --plan /chemin/prive/target.json --output /chemin/prive/preflight.json
python -m shadai.qualification target load --execute --plan /chemin/prive/target.json --output /chemin/prive/load.json
python -m shadai.qualification target kubernetes --execute --plan /chemin/prive/target.json --output /chemin/prive/kube.json
python -m shadai.qualification target idp --plan /chemin/prive/target.json --output /chemin/prive/idp-metadata.json
python -m shadai.qualification target evaluate --plan /chemin/prive/target.json --evidence /chemin/prive/evidence.json --output /chemin/prive/evaluation.json
```

Sans `--execute`, load ne transmet rien ; Kubernetes rend sans apply. Avec `--execute`, Kubernetes effectue un **server dry-run** et un inventaire nodes/pods/endpoints/NetworkPolicy sur le contexte/namespace exacts. Il ne modifie pas le cluster. Le profil rendu a API/front/ingestion/corrélation ×2, purge ×1, PDB minAvailable=1, anti-affinité hostname obligatoire, maxSurge=0/maxUnavailable=1, stores externes dédiés, legacy désactivé, cookies Secure et images par digest. Cela ne prouve pas la HA : scheduling, ingress/TLS, réseau, probes et pannes de nœud/stores restent des preuves cible à fournir sous plan de maintenance et objectifs explicites.

`target` exige `namespace`, `kubernetes_context`, `origin`, `issuer`, `stores` (IDs postgres/redis/clickhouse), `images` (api/frontend/worker), `egress_cidrs` explicites, `runtime_secret_name`, `tls_secret_name`, `ingress_namespace` et `ingress_pod_selector` exact. Les deux sélecteurs ingress sont intersectés. Les placeholders et egress `/0` sont refusés. Le Secret runtime existant fournit database_url, redis_url, clickhouse_host/user/database, jwt_secret, encryption_key, ch_password, oidc_client_id/secret ; aucun secret n'est monté dans le frontend. N'élargissez pas `TRUSTED_PROXY_IPS` pour rendre le test vert ; faites écraser les en-têtes par l'ingress exact. Les politiques de TLS magasins et de SCIM restent à configurer et vérifier sur la cible.

`secret_files` contient uniquement des chemins locaux privés absolus : `collector_key` (JSON collector_id/api_key/run_id d'un collector dédié **existant**) et `run_directory_marker` (fichier privé dans un répertoire `0700`). L'action cible possède une deadline monotone unique avant préparation ; GET et kubectl utilisent son budget restant. `idp` sans `--execute` vérifie uniquement health/readiness et les métadonnées OIDC de l'issuer exact par GET bornés. Cela ne qualifie ni connexion, ni session, ni MFA.

`idp --execute` est désactivé sur toutes les plateformes : refus `unsupported_browser_containment`, résultat `not_evaluated`, exit 2, avant GET, lancement de Node/Chromium ou lecture de références de compte. Chromium démarre dans une autre session/groupe POSIX ; arrêter le groupe Node ne prouve pas son arrêt. Le helper JavaScript conservé retourne uniquement ce refus, sans lire les arguments ni écrire de preuve. Un test de nettoyage de descendants non détachés ne constitue pas une qualification Chromium. La connexion/MFA humaine réelle, le retour neuf, session/me, cookies HttpOnly/Secure, CSRF/logout et propagation rôle/désactivation exigent des observations autorisées sur la cible réelle. `target evaluate` ne transforme jamais des flags de succès JSON fournis par l'appelant en preuve indépendante.
