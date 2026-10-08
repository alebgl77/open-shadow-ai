# Guide de mise en œuvre pour experts

[English](../en/README.md) | [Français](README.md) | [简体中文](../zh-CN/README.md)

Ce guide accompagne les spécialistes de l'infrastructure et de l'identité depuis une évaluation bornée jusqu'à un pilote soumis à une revue opérationnelle. Il couvre le backend en préversion **0.3.0** et l'agent autonome **0.1.0**. Ses procédures opérationnelles ont été alignées le **8 octobre 2026** en prenant pour socle le commit source `49a58d778d3014879e30a3ac5334df45cd426dbf`. La console et les guides en trois langues ont été fusionnés dans `main` au [commit `7a12513eb1e1e3a800ba8d71f4726a3b5045b669`](https://github.com/alebgl77/open-shadow-ai/commit/7a12513eb1e1e3a800ba8d71f4726a3b5045b669). La préversion publiée `v0.3.0`, au commit `49a58d7`, précède la localisation ; les deux révisions sources déclarent `0.3.0`. Consignez le commit exact déployé pour vérifier les fonctionnalités disponibles et leurs preuves CI. Toute évolution ultérieure exige ses propres preuves opérationnelles et CI. Exécutez les commandes depuis la racine du dépôt, sauf indication contraire. Leur syntaxe reprend les procédures détaillées ; remplacez les hôtes, identifiants, chemins et interfaces d'exemple par des valeurs revues avant exécution.

Une installation sert **une seule organisation**. `tenant_id` contrôle un périmètre, sans constituer une frontière d'isolation. Aucune certification de production, aucun SLA, débit d'entreprise mesuré, déploiement automatique du parc ou détection universelle de l'IA ne sont revendiqués. Les guides complets anglais, français et chinois simplifié couvrent les mêmes procédures ; les documents détaillés liés sont signalés comme références en anglais. Les audits historiques et journaux de modifications conservent leur langue et leur portée de validation. Les schémas animés existants utilisent des libellés français et des données synthétiques. La [roadmap française](roadmap.md) présente les étapes futures et leurs critères de passage.

Le sélecteur de langue de la console fonctionne avant et après connexion, en anglais, français et chinois simplifié. Sa préférence validée, locale au navigateur, est indépendante de l'authentification ; un stockage absent ou bloqué entraîne un retour à l'anglais. Les valeurs brutes des sources et identifiants techniques/API restent littéraux. Voir la [documentation et sa couverture linguistique](../README.md).

## 1. Définir le périmètre et les preuves

Consignez responsables de déploiement, de données et de sources, postes/OU/segments du pilote, champs autorisés, rétention, rôles d'accès et critères d'arrêt. Commencez avec une source, un positif synthétique connu et des négatifs sans IA. Conservez commit exact, digests d'images, révision de configuration et résultats CI avec les preuves du pilote. Une capture d'état sain ne démontre ni l'exhaustivité de la capture ni la justesse d'attribution.

L'API authentifie ingestion et accès à la console. Redis transporte neuf streams de sources vers les workers d'ingestion, puis `matches` vers les workers de corrélation. ClickHouse conserve les métadonnées d'événement ; PostgreSQL contient catalogue, détections, identités, reçus et état des accès. Purge et maintenance explicite des files ont des responsabilités distinctes. L'interface présente ces preuves ; elle ne scanne pas le parc. Voir [Architecture (référence en anglais)](../architecture.md) et [Couverture des sources (référence en anglais)](../collectors.md).

| Signal | Ce qu'il permet d'établir | Ce qui reste non démontré |
|---|---|---|
| DNS, SNI, HTTP Host, métadonnées proxy | Observation d'un nom ou d'une connexion depuis un point de mesure documenté | Requête IA achevée, contenu, salarié, modèle, tokens ou facture |
| Processus/conteneur/runtime/extension sur un poste | Présence ou logiciel observé en cours d'exécution | Usage réel d'un modèle ou visibilité de tous les profils de navigateur |
| Objet AD, application/grant Entra | Présence ou autorisation dans l'annuaire | Activité, équivalence d'identité hybride ou usage de l'application |
| Événement instrumenté | Métadonnées modèle/tokens/coût explicitement fournies | Routage interne du fournisseur ; un coût calculé reste estimatif jusqu'au rapprochement avec la facture |

TLS masque le contenu. DoH masque les noms recherchés à l'adaptateur DNS passif ; le SNI d'un résolveur ne les restitue pas. ECH protège le nom interne : une offre peut être GREASE, son acceptation reste inconnue, et l'absence de SNI ne diagnostique pas ECH à elle seule. Les métadonnées prises en charge suppriment le SNI externe lorsqu'une offre ECH est identifiée, mais certaines versions peuvent manquer ces offres. QUIC exige une identification par la source ou le dissecteur ; UDP/443 ne prouve ni QUIC ni IA. NAT, VPN, utilisateurs distants, CDN partagés, trafic non répliqué, modèles locaux et IA intégrée aux SaaS laissent des angles morts. IP et empreintes ne sont pas des identités du catalogue ; aucun rapprochement automatique AD/DHCP/IP-salarié n'est réalisé. Plusieurs observations ne peuvent pas être additionnées en nombre de requêtes IA.

## 2. Préparer l'hôte et installer Compose

Exigez Git, Python 3.12+ et un Docker Engine fonctionnel avec Compose v2 ; Docker n'est pas fourni. La démonstration d'interface nécessite aussi Node.js 22.22.2+ dans la branche 22.x. Le budget initial de pilote est de 4 vCPU/8 GiB RAM, hypothèse à mesurer plutôt que garantie de dimensionnement. Validez CPU, disque, horloges et réseau avant de connecter des sources. Le package définit de vrais contrôles de services CI Linux ; les contrôles statiques de l'hôte de rédaction ne les remplacent pas.

Sous Linux/macOS, lancez le bootstrap depuis un checkout de confiance :

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

Sous Windows, remplacez uniquement la commande de bootstrap par :

```powershell
./scripts/bootstrap.ps1
```

Les deux bootstraps préservent la configuration et les six secrets de base existants ; `--dry-run` ou `-DryRun` prévisualisent l'opération. Sous Unix, les secrets utilisent un parent privé `0700`. Windows vérifie propriétaire, ACL complètes, reparse points et ancêtres avant de générer des octets ; les nouveaux répertoires autorisent utilisateur courant et SYSTEM sans élévation administrateur. Un arbre existant refusé exige une destination privée de confiance, pas une réparation automatique des permissions.

Démarrez d'abord les nouveaux workers sans attendre la readiness globale : ils créent les groupes Redis réels. Si la réconciliation signale une initialisation incomplète, attendez puis réessayez. Schéma réconcilié et sentinelles des hashes sont obligatoires avant readiness et activation des collecteurs. Pour les mises à niveau, arrêtez d'abord tous les anciens producteurs, workers et clients de rejeu. `--legacy-writers-stopped` affirme cette réalité opérationnelle ; cette option ne les arrête pas. Les migrations PostgreSQL précèdent l'API. Les volumes ClickHouse neufs reçoivent les deux schémas ; les volumes existants nécessitent la migration distincte de la section 9.

Ouvrez `http://localhost:3000`, créez un administrateur local de récupération et vérifiez le pipeline :

```bash
docker compose ps --all
curl --fail http://127.0.0.1:8443/health
curl --fail http://127.0.0.1:8443/ready
docker compose logs --tail 100 api ingest-worker correlation-worker
```

Les magasins ne publient aucun port hôte ; API et interface écoutent sur localhost. `/health` établit la santé du processus API, `/ready` celle de ses dépendances. La readiness des workers exige aussi progression locale et état de rétention ; un pipeline inactif ou bloqué doit être évalué séparément. Voir [Déploiement (référence en anglais)](../deployment.md).

## 3. Établir les secrets, TLS et les frontières de l'organisation

Définissez `SHADAI_TENANT_ID` de manière cohérente et dédiez les identifiants des magasins externes à cette installation. Les secrets du bootstrap ne créent pas d'identifiant Microsoft utilisable, secret client OIDC, token SCIM ou token métriques. Distribuez chacun par le canal de gestion des secrets approuvé, dans des fichiers privés ; jamais dans Git, `.env`, arguments de commande, stockage navigateur, logs ou SYSVOL. Protégez le compte hôte et le daemon Docker.

Le port 8443 sert du HTTP interne. Publiez une origine HTTPS de confiance via un reverse proxy devant l'interface, qui relaie `/api/` ; gardez les ports directs API/magasins privés. Agents et upload AD exigent HTTPS, valident les certificats et refusent les redirections. Définissez `SHADAI_CA_BUNDLE` ou l'option de fichier CA du collecteur pour une CA privée. Configurez directement l'endpoint final et maintenez la vérification.

Le réseau Compose `edge` dédié utilise par défaut `172.30.0.0/24`, frontend `172.30.0.2`, API `172.30.0.3`. En cas de chevauchement, modifiez ensemble **les trois** `SHADAI_EDGE_SUBNET`, `SHADAI_EDGE_FRONTEND_IP`, `SHADAI_EDGE_API_IP`, puis recréez le réseau en maintenance. Uvicorn ne fait confiance qu'à cette adresse frontend ; nginx écrase les en-têtes d'adresse client entrants. Un proxy supplémentaire en amont exige une confiance real-IP limitée à son adresse exacte et un ingress restreint ; sinon ses clients partagent un quota de connexion. N'élargissez jamais `TRUSTED_PROXY_IPS` et n'autorisez pas `*` pour faire passer un test.

Utilisez `CORS_ORIGINS` exact uniquement si l'accès entre origines est nécessaire. Les cookies de console sont HttpOnly, SameSite=Strict, Secure/`__Host-` hors localhost ; vérifiez `SESSION_COOKIE_SECURE` selon l'origine publique réelle. Les écritures authentifiées par cookie exigent `X-CSRF-Token`. TLS PostgreSQL se configure dans `DATABASE_URL`, TLS Redis dans `REDIS_URL` avec `rediss://`. ClickHouse externe utilise TLS natif avec `CLICKHOUSE_SECURE=true` et normalement le port 9440 ; CA privée, certificats client et réglages de nom d'hôte figurent dans [Configuration TLS (référence en anglais)](../deployment.md#remote-access-and-tls).

## 4. Préparer Kubernetes avec des magasins externes

La base exige PostgreSQL/Redis/ClickHouse externes, un CNI appliquant NetworkPolicy, des connexions privées chiffrées, un contrôleur ingress et un certificat TLS existant de confiance. Elle ne fournit ni opérateur de base, ni HA des magasins, ni émission de certificat. Construisez les images API/worker/frontend dans le registre approuvé et remplacez toutes les images runtime et migration par des digests immuables vérifiés dans un overlay privé.

Provisionnez namespace et Secret `open-shadow-ai-runtime` par le gestionnaire de secrets existant. Clés requises : `DATABASE_URL`, `REDIS_URL`, `CLICKHOUSE_HOST`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`, `JWT_SECRET`, `ENCRYPTION_KEY`, `AGENT_API_KEY`. Configurez organisation, CIDR/ports réels des bases, sélecteurs DNS et ingress. Les plages TEST-NET ne fournissent volontairement aucune route de production. Appliquez les deux schémas ClickHouse dans l'ordre par la procédure d'administration du magasin, puis achevez la migration PostgreSQL avant les applications :

```bash
kubectl apply -f deploy/kubernetes/base/namespace.yaml
# Provision the runtime Secret using your existing secret manager.
kubectl apply -f deploy/kubernetes/migrate.yaml
kubectl -n open-shadow-ai wait --for=condition=complete job/open-shadow-ai-migrate --timeout=180s
kubectl apply -k deploy/kubernetes/base
```

Ces commandes supposent les images et routes réelles préparées dans la configuration référencée. Effectuez le rendu et la validation serveur avant publication :

```bash
kubectl kustomize deploy/kubernetes/base > rendered.yaml
kubectl apply --dry-run=server -k deploy/kubernetes/base
kubectl -n open-shadow-ai get pods
kubectl -n open-shadow-ai rollout status deployment/api
```

Réconciliez Redis dans un nouveau pod de maintenance configuré après l'initialisation des groupes par les nouveaux workers ; le Job PostgreSQL ne migre pas Redis. Préservez `noeviction`, le graphe complet de références et le comportement de persistance mesuré du Redis externe. Les workers de base ont une réplique ; en ajouter exige des preuves de charge, reclaim et corrélation concurrente. Validez scheduling, ingress/TLS, NetworkPolicy, sondes, interruptions, magasins et restauration sur le cluster réel. Un manifeste ou server dry-run ne démontre pas la HA. Voir [Procédures Kubernetes (référence en anglais)](../../deploy/kubernetes/README.md).

## 5. Intégrer les inventaires AD et Entra

Utilisez RSAT ActiveDirectory sur un hôte de gestion avec lecture des OU pilotes explicites. Les requêtes à la racine du domaine sont refusées ; Domain Administrator n'est pas nécessaire pour l'exporteur. Prévisualisez puis exportez :

```powershell
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export' -WhatIf
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export'
```

Chaque exécution crée des lots privés compatibles API, au plus 500 objets, avec heures d'observation/GUID/SID et noms sélectionnés ; aucune mutation d'annuaire, mot de passe, extraction large d'attributs ou appartenance aux groupes. Pour l'upload, inscrivez `ad-pilot` avec `directory`, provisionnez sa clé privée et définissez explicitement le collecteur :

```powershell
$env:AGENT_API_KEY_FILE = 'C:/Protected/OpenShadowAI/collector-key.txt'
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export' -Upload -ApiUrl 'https://ai-inventory.example.com' -TenantId 'default' -CollectorId 'ad-pilot'
```

Les uploads échoués conservent JSON/IDs originaux ; un nouvel export est une nouvelle observation. Protégez exports et rétention. GUID/SID AD, object IDs Entra et IDs d'agent sont distincts ; leur mapping exige une validation indépendante.

Créez une application Entra dédiée à l'**inventaire**, provisionnez séparément `secrets/entra_client_secret.txt`, puis définissez `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_POLL_INTERVAL_SECONDS` (minimum 60). La permission applicative `Application.Read.All` avec consentement administrateur couvre les service principals. Les grants sont désactivés par `ENTRA_COLLECT_GRANTS=false` ; les activer exige le consentement plus large `Directory.Read.All`, après revue.

```bash
docker compose --profile entra up -d --build entra-collector
docker compose logs --tail 100 entra-collector
```

Le catalogue fourni n'inclut aucun mapping d'application-ID OAuth. Examinez les valeurs Graph **appId** vérifiées, pas les object IDs de service principals ou leurs noms ; adaptez l'exemple non chargé `catalog/local/entra-app.yaml.example`, préservez les signatures existantes si vous réutilisez un ID et synchronisez le catalogue. Inventaires/grants restent des preuves de présence/autorisation. Validez en conditions réelles permissions du tenant, throttling et observations. Voir [Procédures Microsoft (référence en anglais)](../microsoft.md).

## 6. Déployer OIDC, SCIM et MFA de manière maîtrisée

OIDC/SCIM sont facultatifs, désactivés par défaut et gèrent l'**accès à la console**, séparément de l'inventaire. Conservez un administrateur local de récupération testé. La connexion exige un utilisateur SCIM actif, pré-provisionné : issuer vérifié et `externalId` stable ; aucune création à la première connexion, liaison par email ou conversion de comptes locaux. OIDC générique exige discovery, client confidentiel authorization-code, PKCE S256 et RS256 ; utilisez un `sub` stable propre au client. Entra utilise une application de connexion single-tenant dédiée, l'issuer exact du tenant, `OIDC_IDENTITY_CLAIM=oid` et le même objectId utilisateur dans le `externalId` SCIM.

Enregistrez le callback HTTPS `/api/v1/auth/sso/callback`, pas le frontend `/auth/callback`. Ce dernier termine l'échange d'un cookie à usage unique via `POST /api/v1/auth/sso/session`, avec `Origin` exact et `X-SSO-CSRF: 1`. Configurez Conditional Access/MFA chez l'IdP : l'application ne vérifie pas elle-même une obligation de claim MFA. La connexion demande `openid profile`, aucune permission Graph d'inventaire.

Provisionnez `secrets/oidc_client_secret.txt` privé et `secrets/scim_bearer_token.txt` indépendant, généré à partir d'au moins 32 octets aléatoires. Configurez issuer/client/origine publique exacts et `SCIM_GROUP_ROLE_MAP` explicite ; les external IDs immuables de groupes accordent `viewer`, `analyst`, `admin`, le plus élevé s'applique, une map vide donne viewer. Toutes les répliques API doivent partager cette politique. Configurez l'application SCIM avec tenant URL `/api/v1/scim/v2`, Test Connection et mappings explicites : objectId→externalId, UPN→userName, enabled→active, objectId de groupe→externalId, appartenances→members. Commencez par les utilisateurs/groupes pilotes assignés et le provisionnement à la demande.

```bash
docker compose -f docker-compose.yml -f docker-compose.sso.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.sso.yml up -d --build
docker compose exec -T frontend nginx -s reload
```

Utilisez les deux fichiers Compose pour toutes les opérations ultérieures ; rechargez nginx après recréation API. Kubernetes ajoute un Secret `open-shadow-ai-identity` provisionné séparément, des réglages limités à l'API et un egress HTTPS IdP revu. NetworkPolicy standard n'autorise pas des noms d'hôte.

Testez connexions provisionnées/non provisionnées, correspondance des IDs, consentement refusé, expiration/rejeu, cookies/CSRF exacts, groupes mappés et désactivation avec session active. Désactivation/suppression/réduction de rôle révoquent les sessions affectées **à réception** ; le délai de synchronisation d'annuaire échappe à l'application. Réactivation ne ressuscite pas les anciens tokens. Les changements de profil/groupe non mappé ne terminent pas les sessions ; les rôles sont résolus à chaque requête. Le logout console n'est pas un logout global IdP. Coordonnez rotation avec le provisionneur et redémarrez l'API ; la rotation avec chevauchement du token SCIM n'est pas livrée. SCIM est un sous-ensemble borné sans Bulk, groupes imbriqués, filtres complets, SAML ou plusieurs IdP. Voir [Déploiement et recette des identités (référence en anglais)](../sso-scim.md) et [Admission SSO (référence en anglais)](../sso-admission.md).

## 7. Inscrire les collecteurs et établir la couverture

Un administrateur utilise **Sources et couverture → Collecteurs inscrits → Inscrire un collecteur** pour attribuer un ID immuable et la portée minimale. Enregistrez la clé à affichage unique dans un fichier privé ; une réponse perdue peut suivre un commit, donc inspectez le registre avant de réessayer. La rotation prévoit 3 600 secondes de chevauchement (0–86 400) et 365 jours d'expiration (1–365) par défaut ; la révocation du collecteur est définitive. Les clés de collecteur n'administrent ni registre ni métriques. Désactivez `ALLOW_LEGACY_AGENT_KEY` après credentials restreints et livraison vérifiée pour tous les producteurs ; le trafic historique est non attribué. Fournissez explicitement les overrides d'environnement aux services concernés, pas seulement dans `.env`.

Pour Windows, construisez le wheelhouse hors ligne propre à la plateforme et approuvez ses hashes. L'installateur SYSTEM exige un nouvel arbre d'installation protégé, Python/wheelhouse de propriétaires administratifs fiables et ancêtres sûrs ; Python par utilisateur est inadapté. Prévisualisez sur un poste, vérifiez tâche/inventaire HTTPS puis déployez progressivement via vos processus GPO/Intune/Configuration Manager. Installer le serveur ne déploie pas d'agents et ne modifie pas les GPO. SYSTEM peut manquer des profils de navigateur utilisateur ; les extensions demandent la portée `browser`. Mise à niveau, désinstallation et signatures restent à valider sur le parc.

Pour syslog, choisissez le parseur exact BIND/Windows DNS/Squid/PAN-OS/FortiGate, le fuseau IANA et l'horloge source corrects. TCP/1514 écoute par défaut sur localhost ; le transfert distant exige bind privé, firewall et relais TLS de confiance si nécessaire. L'authentification de l'émetteur syslog est distincte du réglage de clé HTTP historique. Activez après revue de la source :

```bash
docker compose --profile syslog up -d
```

Pour le réseau, provisionnez délibérément SPAN/TAP/mirror, utilisez des IDs capteur/site stables et préférez des logs persistés Zeek JSONL ou Suricata EVE. Inspectez avant livraison authentifiée :

```bash
python -m shadai.collectors.network --sensor-id office-mirror --site-id paris --format zeek-tls --input ssl.jsonl --dry-run --csv-output network-observations.csv
python -m shadai.collectors.network --sensor-id office-mirror --site-id paris --format zeek-tls --input ssl.jsonl --api-url https://shadai.example.test --api-key-file /etc/shadai/network-agent.key --ca-file /etc/shadai/organization-ca.pem --spool-dir /var/lib/shadai/network/office-mirror
```

Zeek TSV n'est pas une entrée JSONL ; l'extraction PCAP/live TShark est facultative et locale, jamais un upload PCAP. Les imports couvrent IPv4/IPv6 et DNS/TLS/QUIC/HTTP. Une interface live exige permissions de capture et sélection explicite ; installer le serveur n'en lance aucune. Les événements génériques utilisent des lots authentifiés de 1–500, timestamps avec fuseau, UUID stables et refusent les champs inconnus. Plus de cinq minutes dans le futur ou hors `ingestion_max_age_days` est refusé. Préservez les timestamps aux retries. Voir [Exploitation des collecteurs (référence en anglais)](../collector-operations.md), [Couverture (référence en anglais)](../collectors.md) et [Procédures réseau (référence en anglais)](../network-analysis.md).

## 8. Exploiter les files, la supervision et la capacité

Les spools SQLite poste/réseau/syslog conservent les métadonnées préparées en clair après redémarrage : par défaut 64 MiB de payloads, 2 048 lots, sept jours ; maxima 16 GiB, 100 000 lots, 365 jours, TTL plafonné par l'âge d'acceptation serveur. Budgétez séparément overhead SQLite/journaux/filesystem ; la quarantaine consomme la capacité. Les chemins privés exigent propriétaire réel du service et ancêtres fiables (`0700`/`0600` Unix, ACL Windows restreintes) ; ne diminuez pas les gardes. Entra rejoue en mémoire sans durabilité après crash ; AD conserve plutôt les JSON d'export.

Une première rétention hors ligne ne transmet rien avant discovery du binding cible/collecteur. Restaurez le bon principal après mismatch ; un autre tenant/inscription ne peut hériter des octets conservés. La rotation dans le même collecteur est compatible. Les baux permettent la reprise ; livraison au moins une fois avec IDs/reçus stables, sans garantie illimitée d'exactement une fois. Capture interrompue, perte UDP, drops avant enqueue, expiration et disque plein restent possibles. `capture_loss` demeure inconnu.

Redis prévoit 100 000 entrées conservées par stream source/`matches`, 10 000 pointeurs par DLQ, 500 records/2 MiB de champs par admission, seuil de maintenance explicite de sept jours. Les scripts gardés prévalident les destinations ; une allocation Lua ultérieure/OOM peut cependant laisser des écritures partielles ou incertaines. Gardez les octets non confirmés, préservez `noeviction`, mesurez mémoire et marge. Aucun TTL/MAXLEN automatique ne supprime sources pending ou pointeurs actifs. ACK en attente, lag non livré nullable et sources de rejeu conservées sont distincts. Prévisualisez le rejeu après résolution des données toxiques :

```bash
python -m shadai.workers.replay --group ingest_group --start 0-0 --end + --limit 100 --dry-run
python -m shadai.workers.replay --group ingest_group --start 0-0 --end + --limit 100 --execute
```

Le rejeu préserve champs et `accepted_at` de confiance ; l'ancien backlog sans cette valeur reste contrôlé par l'âge. Examinez la maintenance archive/discard explicite avant exécution ; ne supprimez jamais du pending pour faire taire une alerte. Vérifiez la politique AOF/fsync réelle avant de définir le RPO :

```bash
docker compose exec -T redis sh -c 'REDISCLI_AUTH="$(cat /run/secrets/redis_password)" redis-cli CONFIG GET appendonly appendfsync maxmemory maxmemory-policy'
```

`/metrics` exige identité admin ou token indépendant en lecture seule d'au moins 32 caractères non blancs. L'overlay facultatif Linux/Docker rootful utilise deux copies privées du même token pour UID10001 API et UID65534 Prometheus ; les secrets bind-mountés ne remappent pas le propriétaire. Gardez les routes de scrape privées et revérifiez l'authentification après rotation. Les métriques applicatives couvrent les files, pas mémoire/disque physiques. Mesurez AOF/mémoire Redis, CPU/RAM conteneurs, disques/inodes et croissance avec la supervision de l'infrastructure cible. Les règles d'alerte exigent responsables et receiver configuré séparément ; leur déclenchement ne notifie personne à lui seul. Prometheus exige aussi un watchdog externe.

Mesurez baseline, montée en charge bornée, latence API/erreurs, âge pending, locks, inserts, requêtes et durée de drain/reclaim. Arrêtez aux seuils prédéfinis. La projection utilise octets/événement mesurés plus indexes/réplication/sauvegardes. TTL des événements et purge quotidienne sont distincts des rétentions identité/files ; gardez `receipt_days >= ingestion_max_age_days + events_days + 1`. Définissez RPO/RTO et répétez à la taille prévue. Voir [Rétention des files (référence en anglais)](../queue-retention.md), [Supervision (référence en anglais)](../production-monitoring.md) et [Capacité (référence en anglais)](../capacity.md).

## 9. Sauvegarder, migrer et répéter le retour arrière

Avant mise à jour, sauvegardez magasins, config, commit de déploiement, clés de chiffrement correspondantes et spools/exports privés. Mettez producteurs distants et collecteurs facultatifs au repos, puis arrêtez les écritures applicatives. Arrêtez les clients SQLite avant snapshot. Chiffrez et restreignez les sauvegardes : la pseudonymisation serveur ne nettoie pas sauvegardes et spools locaux en clair. Les exports logiques PostgreSQL/ClickHouse omettent l'état pending/références Redis ; préservez volumes et limites réelles AOF/flush.

Procédure logique pour un petit pilote :

```bash
umask 077
mkdir -p backups
docker compose stop api frontend ingest-worker correlation-worker purge-worker
docker compose exec -T postgres pg_dump -U shadai -d shadai -Fc > backups/postgres.dump
docker compose exec -T clickhouse sh -c 'clickhouse-client --user shadai --password "$(cat /run/secrets/ch_password)" --query "SELECT * FROM shadai.events FORMAT Native"' > backups/events.native
docker compose exec -T redis sh -c 'REDISCLI_AUTH="$(cat /run/secrets/redis_password)" redis-cli SAVE'
```

Les objectifs de production exigent des sauvegardes natives de bases testées. Restaurez dans checkout/projet séparé, magasins vides, version/clés identiques, ports et réseau edge inutilisés. Gardez le nom de projet dans chaque commande ; les imports répétés sont dangereux. Restaurez les volumes Redis arrêtés par la plateforme de stockage ou documentez l'intervalle en vol abandonné. Comparez événements/détections, validez readiness/connexion et un nouvel événement synthétique de bout en bout. Restaurez les spools uniquement sur leur binding original vérifié.

La migration `003` verrouille les utilisateurs locaux et refuse noms vides ou doublons après case-fold ; renommez explicitement, sans fusion silencieuse. `004` ajoute les credentials restreints. **La migration `005` remet à zéro les tableaux/compteurs historiques d'identités non datés, efface `primary_evidence`, retire les extraits `sample_values`, `sample_observations`, `network_observations` et marque le risque obsolète.** Les détections restent présentes. L'âge de leurs preuves historiques d'identité ne peut être démontré ; la migration n'invente pas de dates récentes. Examinez ce changement irréversible sur une restauration isolée. ClickHouse `002_event_metadata.sql` doit précéder les commandes API qui démarrent leurs dépendances : la nouvelle sonde sélectionne `identity_sid`, absent des anciens volumes.

```bash
set -e
docker compose build
# Stop writers; start only stores, without waiting for the new ClickHouse schema probe.
docker compose stop api frontend ingest-worker correlation-worker purge-worker
docker compose up -d postgres clickhouse redis
docker compose exec -T clickhouse sh -c 'clickhouse-client --user shadai --password "$(cat /run/secrets/ch_password)" --multiquery' < migrations/clickhouse/002_event_metadata.sql
# --no-deps avoids starting an API dependency graph before the migrations have completed.
docker compose run --rm --no-deps api python -m shadai.cli init-db
docker compose up -d
docker compose exec -T api python /app/entrypoint.py python -m shadai.workers.redis_lifecycle reconcile --execute --legacy-writers-stopped
docker compose up -d --wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend
```

Attendez/réessayez la connexion aux magasins avant de continuer ; ClickHouse temporairement unhealthy est attendu jusqu'au succès SQL. Arrêtez également chaque producteur facultatif/distant ancien. Avec SSO, utilisez les deux fichiers Compose. Aucun rollback automatique de schéma. `003` refuse le downgrade après apparition d'identités/groupes/audit/révocations externes ; ne supprimez pas ces données pour contourner la garde. Restaurez une sauvegarde antérieure dans un environnement isolé avec code/configuration correspondants. Voir [Mise à jour et reprise (référence en anglais)](../deployment.md#updates).

## 10. Maintenir la confidentialité et les accès

Chemins, requêtes et user agents ne sont pas conservés. Le matching en mémoire est limité aux hôtes du produit ; `privacy.match_transient_signals: false` le désactive. Les signatures partagées à confiance égale restent ambiguës ; les chemins supprimés ne sont pas reconstructibles après changement de catalogue. Examinez signatures personnalisées et négatifs sources avant attribution.

L'appartenance des identités vieillit indépendamment à chaque observation ; défaut `min(30, events_days)`, positif et au plus rétention événements. Les comptes sont des identifiants distincts observés, pas l'effectif salarié. Consultez `risk_calculated_at` nullable et `risk_score_stale` ; l'heure d'une mise à jour générale ne prouve pas le recalcul. `PSEUDONYMIZE_IDENTITIES` crée des alias HMAC par champ avec la clé de chiffrement et efface IP source personnelle/texte libre IdP. Les pseudonymes restent des données organisationnelles corrélables. Cela affecte le nouveau traitement, pas événements historiques, sauvegardes ou spools.

Pour un nettoyage historique revu, répétez sur une restauration, mettez les collecteurs au repos, videz files/spools, arrêtez producteurs/rejeu et maintenez cet état jusqu'à vérification :

```bash
python -m shadai.workers.purge --scrub-personal-history --batch-size 500 --max-batches 100
```

Inspectez `complete`, `clickhouse_complete`, `sql_complete` et le curseur retourné ; reprenez uniquement avec le `--after-detection-id` reçu. Exit zéro exige l'achèvement synchrone vérifié ; un travail plafonné incomplet est nonzero. Comptes, notes et acteurs d'audit sont exclus. Changer la clé modifie la base des pseudonymes et le matériel chiffré ; gardez les sauvegardes correspondantes et planifiez la reconstruction. Voir [Maintenance de confidentialité (référence en anglais)](../collector-operations.md#retain-and-pseudonymize-identities).

## 11. Examiner les preuves de sécurité et de livraison

Vérifiez les gates obligatoires du commit exact : Linux/Python, frontend, Windows natif, vrais magasins/Compose, agent hors ligne, images natives amd64/arm64 et qualification. Locks/entrées de base avec hashes et SBOM/provenance BuildKit lient entrées et artifacts ; ils ne promettent pas des binaires identiques entre machines. Les scans doivent couvrir sujet/inventaire et conserver toutes sévérités et findings non corrigés. Erreurs scanner, couverture incomplète et findings high/critical corrigibles ou sévérité inconnue échouent selon le gate documenté.

Les observations SBOM des main modules gosu et node_exporter conservent **`UNKNOWN`** ; les versions de requêtes projetées depuis les sources revues ne sont pas des versions binaires inventées. L'absence du principal ClickHouse dans le SBOM est conservée, avec requête déclarée/observation CLI distincte. **GO-2026-5932 reste visible lorsqu'il est signalé** ; les recettes maintenues ne revendiquent pas son effacement dans toutes les couches. L'ancien audit npm sans finding nommé n'inventorie pas `braces` affecté embarqué dans Vite/Rollup. Les restrictions de watchers aux chemins littéraux atténuent la route d'outillage identifiée, pas tous les risques de parseur/plugin.

Les pushes internes de confiance sur `main` peuvent produire des attestations GitHub/Sigstore vérifiées pour archives OCI/preuves exactes après tous les gates requis. La signature porte sur les archives OCI exactes et manifestes de preuves séparés, pas sur une archive source ZIP GitHub. Les artifacts PR ne sont pas signés ; prédicats locaux, tags et tests ne sont ni signatures ni release signée. Vérifiez dépôt, workflow, ref/commit source, digest et runner hébergé. Les causes natives encore indiquées inconnues restent inconnues jusqu'à preuve liée nouvelle. Voir [Livraison et portée des scans (référence en anglais)](../production-delivery.md), [Validation (référence en anglais)](../validation.md), [Sécurité d'outillage frontend (référence en anglais)](../frontend-build-security.md) et [Politique de sécurité (référence en anglais)](../../SECURITY.md).

## 12. Expliciter qualification et go/no-go

Utilisez le laboratoire jetable Linux/nonroot Docker pour le job obligatoire `production-qualification` du commit exact. Il exerce charge synthétique, interruptions ingestion/corrélation, reclaim pending, sondes, mesures physiques, pression Redis isolée et restauration froide. Profil fixe : **1 000 événements synthétiques, 10/s, lots de 10, concurrence 2**, requêtes de 5 secondes, drain 120 secondes, budget travail 1 500 secondes, 500 requêtes, 2 MiB/requête et artifacts 10 GiB. Les allocations de terminaison donnent un plafond applicatif déclaré de **1 512 secondes**. Ce sont des entrées de test, pas capacité, RPO ou RTO de production.

La restauration froide doit comparer les inventaires privés complets avant les workers et établir **dix nouvelles acceptations distinctes plus l'événement PEL sauvegardé**, avec persistance ClickHouse et reçus PostgreSQL ingestion/corrélation pour chacun. La reprise pending seule est insuffisante. Les diagnostics localisent des étapes sans prouver cause ou succès. Le corpus qualité synthétique donne TP=1, FP=1, FN=2, TN=1, precision=0,5, recall=1/3, F1=0,4 ; vérité inconnue et dénominateurs nuls restent explicites. Il mesure le matching de métadonnées normalisées, pas capture, usage réel de modèle ou probabilité calibrée.

Les procédures cible preflight/load/Kubernetes/IdP/evaluate exigent plan revu sur contexte exact, collecteur dédié et preuves privées. Kubernetes `--execute` effectue server dry-run/inventaire, pas déploiement ou preuve HA. IdP sans exécution ne vérifie que métadonnées/santé. **`idp --execute` est désactivé sur toutes les plateformes** : `unsupported_browser_containment`, `not_evaluated`, exit 2 avant accès au navigateur ou références de compte. Les observations autorisées de connexion/MFA réelles, cookies, session/CSRF/logout et rôles/désactivation restent obligatoires. Des flags de succès fournis par l'appelant ne deviennent jamais des preuves indépendantes.

| Gate | Go pour l'étape suivante du pilote borné | No-go / preuve encore requise |
|---|---|---|
| Installation et files | Gates obligatoires du commit exact réussis ; migrations, réconciliation, readiness réelle et preuve synthétique de bout en bout complètes | Scénarios obligatoires skipped, preuves natives absentes/échouées, magasins unhealthy, graphe de rétention building |
| Sources et identités | Périmètres approuvés, clés/spools privés, rotation/révocation testées ; preuves positives/négatives et couverture explicites | Mapping inconnu promu en identité ; inventaire présenté comme usage ; recette live AD/Entra/IdP/MFA absente |
| Reprise et ressources | Restauration répétée, panne/drain bornés, capacité/marge mesurées et RPO/RTO convenus à taille prévue | Restauration pending seule, durabilité AOF face à panne électrique supposée, HA ou ressources non mesurées |
| Sécurité et exploitation | Scans/signatures liés acceptés si applicables ; findings résiduels revus ; responsables et route de notification testée | Erreur scanner/couverture incomplète, gate sécurité échoué, signature revendiquée sur PR, receiver non testé |

Codes : 0 pour critères mesurés satisfaits, 1 pour mesure/critère échoué, 2 pour prérequis/preuve absent. Objectifs facultatifs de précision/rappel/latence/reprise/restauration exigent mesures réelles. Un laboratoire réussi permet la revue de ses preuves déclarées ; la production exige recette spécifique cible des sources, accès, capacité, pannes, confidentialité et reprise. Voir [Procédure complète de qualification (référence en anglais)](../production-qualification.md).

## 13. Diagnostiquer et maintenir le pilote

| Symptôme | Investigation bornée et résolution |
|---|---|
| API vivante, workers non prêts | Examinez dépendances, groupes réels et `retention_ready` ; réessayez la réconciliation après initialisation ou corrigez la reconstruction interrompue en préservant le backlog |
| Ingestion 503 ou backlog | Examinez caps exactes, types/mémoire Redis et santé aval ; gardez les octets incertains ; distinguez pending/lag des originaux conservés |
| Collecteur 401/403 | Vérifiez expiration/révocation/portées source/tenant/collecteur ; restaurez la bonne clé, pas le binding d'une autre inscription |
| Rejet d'événement ancien/futur | Vérifiez fuseau/horloge source et fenêtre serveur ; ne réécrivez jamais les timestamps |
| Contact sain, aucune détection | Vérifiez parseur, négatifs/signatures partagées, appId Entra non mappé et provenance ; le silence peut être normal |
| Refus ACL spool/secret | Provisionnez un chemin privé de confiance pour le compte réel ; examinez ancêtres/reparse/hardlinks sans élargir les droits |
| SSO 429/503 ou connexion refusée | Vérifiez admission Redis partagée, pair proxy/issuer exacts, mapping SCIM actif et fournisseur ; utilisez l'administrateur local de récupération |
| Métriques absentes / aucune notification | Vérifiez copies de token privées/UID, scrape et inventaire des dix streams, puis route receiver ; une règle seule n'envoie rien |

Pour les workers, utilisez les [Diagnostics expurgés (référence en anglais)](../worker-diagnostics.md) ; ne collectez pas secrets bruts, requêtes de callback OAuth ou logs personnels de production dans des issues publiques. Examinez régulièrement collecteurs, accès, croissance du stockage, archives, risque obsolète et rétention. Répétez les vérifications après changements de source, identité, image, clé, rétention, topologie ou receiver. Proposez des reproductions synthétiques minimales selon les [Procédures de contribution (référence en anglais)](../../CONTRIBUTING.md) et signalez les vulnérabilités en privé selon la politique de sécurité.
