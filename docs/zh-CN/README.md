# 专家实施与运维手册

[English](../en/README.md) | [Français](../fr/README.md) | [简体中文](README.md)

本手册帮助基础设施与身份管理专业人员从范围受限的评估，推进到经过运维评审的试点。内容覆盖后端开发预览版 **0.3.0** 和独立终端代理 **0.1.0**，于 **2026-10-08** 根据源提交 `49a58d778d3014879e30a3ac5334df45cd426dbf` 核对。除非具体流程另有说明，所有命令均从仓库根目录执行。命令示例保留详细流程中的语法；执行前，必须将仅用于文档示例的主机名、ID、路径和网络接口替换为已审核的实际值。

每个部署仅服务**一个组织**。`tenant_id` 用于检查范围，不构成隔离边界。本项目不声称具备生产认证、SLA、经测量的企业级吞吐量、自动化设备群部署或全面 AI 检测能力。英语、法语和简体中文手册提供完整且等效的流程；详细链接文档均明确标为英文参考。历史审计与变更日志保留各自的语言和验证范围。现有动态示意图使用法语标注与合成数据。[路线图](roadmap.md)说明未来阶段及其交付门槛。

控制台的语言选择器在登录前后均可使用，支持英语、法语和简体中文。经过校验的浏览器本地偏好独立于身份验证；存储不存在或被阻止时，默认使用英语。原始来源值与机器/API 标识保持原样。参见[文档与语言覆盖范围（英文参考）](../README.md)。

## 1. 定义范围与证据

记录部署负责人、数据负责人、各来源负责人、试点设备/OU/网段、获准采集的字段、保留期、访问角色和停止条件。从一个来源开始，准备已知的合成正例和非 AI 反例。将准确的源提交、镜像摘要、配置版本和 CI 结果与试点证据一起保存。仅凭服务健康状态截图，无法证明采集完整或归属正确。

API 对数据接入和控制台访问进行身份验证。Redis 将九个来源流传递给接入工作进程，将 `matches` 流传递给关联工作进程。ClickHouse 保存事件元数据；PostgreSQL 保存目录、检测记录、身份、处理回执和访问状态。数据清理与显式队列维护各有职责。前端展示这些证据，不会扫描设备群。参见[架构（英文参考）](../architecture.md)与[来源覆盖范围（英文参考）](../collectors.md)。

| 信号 | 可支持的结论 | 尚不能证明的内容 |
|---|---|---|
| DNS、SNI、HTTP Host、代理元数据 | 在已记录的观测位置看到名称或连接 | 已完成的 AI 请求、内容、员工身份、模型、词元数或账单 |
| 终端进程/容器/运行时/扩展 | 资产存在或被观测到正在运行 | 实际模型使用或所有用户的浏览器配置文件 |
| AD 对象、Entra 应用/权限授予 | 目录中存在该对象或具备相应权限 | 活动、混合身份等价关系或应用使用 |
| 埋点事件 | 明确提供的模型/词元数/成本元数据 | 服务商内部路由；计算成本在与账单核对之前仍为估算 |

TLS 会隐藏内容。DoH 会向被动 DNS 适配器隐藏查询的名称；解析器的 SNI 无法恢复这些名称。ECH 保护内部名称：客户端提供 ECH 可能只是 GREASE，是否被接受仍然未知，仅缺少 SNI 也不能判断使用了 ECH。受支持的元数据在识别到 ECH 提议时会抑制外部 SNI，但不同版本可能漏识别这些提议。QUIC 需要由来源或协议解析器识别；仅有 UDP/443 既不能证明 QUIC，也不能证明 AI。NAT、VPN、远程用户、共享 CDN、未镜像的流量、本地模型和 SaaS 内嵌 AI 都可能造成覆盖缺口。IP 地址与指纹不是目录身份；系统不会自动将 AD/DHCP/IP 与员工关联。不能将多条观测相加作为 AI 请求数。

## 2. 准备主机并安装 Compose

需要 Git、Python 3.12+，以及可正常使用的 Docker Engine 和 Compose v2；项目不附带 Docker。界面演示还需要 22.x 系列的 Node.js 22.22.2+。试点可以从 4 vCPU/8 GiB RAM 的资源预算起步，但这是需要测量的假设，不是容量保证。连接来源之前，先验证 CPU、磁盘、时钟和网络访问。项目定义了实际 Linux CI 服务检查，编写文档主机上的静态检查不能替代这些验证。

在 Linux/macOS 上，从可信检出目录运行引导脚本：

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

在 Windows 上，仅将引导命令替换为：

```powershell
./scripts/bootstrap.ps1
```

两种引导方式均保留现有配置和六项基础机密值；使用 `--dry-run` 或 `-DryRun` 预览。Unix 机密文件使用私有 `0700` 父目录。Windows 会在生成机密字节之前检查所有者、完整 ACL、重解析点及祖先目录安全性；新目录仅允许当前用户与 SYSTEM 访问，无需管理员提权。如果现有目录树被拒绝，应提供可信私有路径，不要自动修复权限。

先启动新工作进程，不等待整体就绪：它们会创建实际 Redis 组。如果核对与重建报告初始化尚未完成，等待后重试。在就绪检查通过或启用采集器之前，必须完成保留结构与哈希哨兵的核对和重建。升级时，先停止所有旧版写入程序、工作进程和重放客户端。`--legacy-writers-stopped` 是对这一运维事实的声明，不会替你停止它们。PostgreSQL 迁移在 API 启动前运行。新的 ClickHouse 卷会加载两个结构文件。现有卷需要执行第 9 节中的独立迁移。

打开 `http://localhost:3000`，创建用于恢复的本地管理员，并检查处理流水线：

```bash
docker compose ps --all
curl --fail http://127.0.0.1:8443/health
curl --fail http://127.0.0.1:8443/ready
docker compose logs --tail 100 api ingest-worker correlation-worker
```

存储不发布主机端口；API/界面绑定本地主机。`/health` 证明 API 进程健康，`/ready` 检查其依赖。工作进程的就绪还要求本地处理进展与保留状态有效；空闲或阻塞的流水线需要单独评估。参见[部署（英文参考）](../deployment.md)。

## 3. 建立机密信息、TLS 与组织边界

保持 `SHADAI_TENANT_ID` 一致，并为本部署配置专用外部存储凭据。基础引导生成的机密值不会提供可用的 Microsoft 凭据、OIDC 客户端机密、SCIM 令牌或指标令牌。通过获准的机密信息管理渠道与私有文件分发每项凭据；不得将值放入 Git、`.env`、命令参数、浏览器存储、日志或 SYSVOL。保护主机账号与 Docker 守护进程。

8443 端口提供内部 HTTP。在前端之前配置反向代理，发布一个具有可信证书的 HTTPS 源站；前端转发 `/api/`，原始 API/存储端口保持私有。终端代理与 AD 上传要求 HTTPS，会验证证书并拒绝重定向。使用私有 CA 时，配置 `SHADAI_CA_BUNDLE` 或采集器的 CA 文件选项。直接配置最终地址，保持证书验证开启。

Compose 的专用 `edge` 网络默认使用 `172.30.0.0/24`，前端为 `172.30.0.2`，API 为 `172.30.0.3`。如与现有网络冲突，必须一致地调整**全部三项** `SHADAI_EDGE_SUBNET`、`SHADAI_EDGE_FRONTEND_IP`、`SHADAI_EDGE_API_IP`，并在维护窗口内重建网络。Uvicorn 只信任该前端地址；前端 nginx 会覆盖传入的客户端地址标头。增加上游代理时，需要仅信任其精确地址提供的真实 IP，并限制入站访问，否则代理后的客户端共享一个登录配额。不要为了通过测试扩大 `TRUSTED_PROXY_IPS` 或信任 `*`。

仅在需要跨源访问时配置精确的 `CORS_ORIGINS`。控制台 Cookie 使用 HttpOnly、SameSite=Strict，在 localhost 以外使用 Secure/`__Host-`；根据实际公开源站核对 `SESSION_COOKIE_SECURE`。使用 Cookie 验证身份的写入请求需要 `X-CSRF-Token`。PostgreSQL 的 TLS 参数放在 `DATABASE_URL` 中；Redis 使用 `rediss://` 的 `REDIS_URL`。外部 ClickHouse 使用原生 TLS，配置 `CLICKHOUSE_SECURE=true`，通常使用 9440 端口；私有 CA、客户端证书与主机名设置见 [TLS 配置（英文参考）](../deployment.md#remote-access-and-tls)。

## 4. 使用外部存储准备 Kubernetes

基础配置要求外部 PostgreSQL/Redis/ClickHouse、能够执行 NetworkPolicy 的 CNI、与存储之间的私有加密连接、入口控制器，以及已有的可信 TLS 证书。它不提供数据库 Operator、存储高可用或证书签发。构建 API/工作进程/前端镜像并推送到获准的镜像仓库，在私有覆盖配置中将所有运行时与迁移镜像替换为经过验证的不可变摘要。

使用现有机密信息管理系统创建命名空间及 `open-shadow-ai-runtime` Secret。必需键为 `DATABASE_URL`、`REDIS_URL`、`CLICKHOUSE_HOST`、`CLICKHOUSE_USER`、`CLICKHOUSE_PASSWORD`、`JWT_SECRET`、`ENCRYPTION_KEY` 和 `AGENT_API_KEY`。配置组织设置、实际数据库 CIDR/端口、DNS 选择器和入口选择器。TEST-NET 地址段有意不提供任何生产路由。通过存储管理流程依次应用两个 ClickHouse 结构文件，再在应用启动之前完成 PostgreSQL 迁移：

```bash
kubectl apply -f deploy/kubernetes/base/namespace.yaml
# Provision the runtime Secret using your existing secret manager.
kubectl apply -f deploy/kubernetes/migrate.yaml
kubectl -n open-shadow-ai wait --for=condition=complete job/open-shadow-ai-migrate --timeout=180s
kubectl apply -k deploy/kubernetes/base
```

这些命令假定所引用的配置已使用实际镜像与路由准备完毕。发布前，渲染清单并在服务器端验证：

```bash
kubectl kustomize deploy/kubernetes/base > rendered.yaml
kubectl apply --dry-run=server -k deploy/kubernetes/base
kubectl -n open-shadow-ai get pods
kubectl -n open-shadow-ai rollout status deployment/api
```

新工作进程完成组初始化后，在新建且配置完备的维护 Pod 中核对并重建 Redis 保留索引；PostgreSQL Job 不会迁移 Redis。保留外部 Redis 的 `noeviction`、完整引用关系图和经测量的持久化行为。基础工作进程各有一个副本；增加副本需要负载、待处理消息回收与并发关联的验证证据。在实际集群中验证 Pod 调度、入口/TLS、NetworkPolicy、探针、中断、存储与恢复。清单或服务器端模拟运行不能证明高可用。参见 [Kubernetes 流程（英文参考）](../../deploy/kubernetes/README.md)。

## 5. 接入 AD 与 Entra 清单

在管理主机上使用 RSAT ActiveDirectory，并确保账号有权读取明确选定的试点 OU。导出器拒绝域根目录查询，不要求域管理员。先预览，再导出：

```powershell
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export' -WhatIf
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export'
```

每次运行生成私有、与 API 兼容的批次，每批最多 500 条，包含观测时间/GUID/SID 和选定的名称；不会修改目录，不采集密码、广泛属性转储或组成员关系。上传时，以 `directory` 范围注册 `ad-pilot`，配置其私有密钥，并明确指定采集器：

```powershell
$env:AGENT_API_KEY_FILE = 'C:/Protected/OpenShadowAI/collector-key.txt'
./scripts/Export-ActiveDirectory.ps1 -SearchBase 'OU=Pilot,DC=example,DC=com' -OutputDirectory './ad-export' -Upload -ApiUrl 'https://ai-inventory.example.com' -TenantId 'default' -CollectorId 'ad-pilot'
```

上传失败时保留原始 JSON/ID；再次导出属于一次新观测。保护导出文件并设置保留期。AD GUID/SID、Entra 对象 ID 与代理 ID 是不同标识，映射必须独立验证。

创建专用 Entra **清单采集**应用，单独配置 `secrets/entra_client_secret.txt`，并设置 `ENTRA_TENANT_ID`、`ENTRA_CLIENT_ID`、`ENTRA_POLL_INTERVAL_SECONDS`（最小值为 60）。经管理员同意的 `Application.Read.All` 应用权限用于服务主体清单。`ENTRA_COLLECT_GRANTS=false` 默认关闭权限授予采集；启用时需要审核更广泛的 `Directory.Read.All` 并取得同意。

```bash
docker compose --profile entra up -d --build entra-collector
docker compose logs --tail 100 entra-collector
```

随项目提供的目录没有内置 OAuth 应用 ID 映射。审核经过验证的 Graph **appId** 值，而非服务主体对象 ID 或显示名称；修改不会自动加载的 `catalog/local/entra-app.yaml.example` 示例，复用 ID 时保留原有签名，再同步目录。清单与权限授予仍然只是存在或权限证据。在实际租户中验证权限、限流和观测。参见 [Microsoft 流程（英文参考）](../microsoft.md)。

## 6. 分阶段启用 OIDC、SCIM 与 MFA

OIDC/SCIM 为可选功能，默认关闭，用于管理**控制台访问**，与清单采集分离。保留经过测试的本地恢复管理员。登录要求已有活跃的 SCIM 预配用户，以经过验证的签发者与稳定 `externalId` 匹配；不在首次登录时创建账号，不按邮箱关联，也不转换本地用户。通用 OIDC 需要发现机制、机密客户端授权码流程、PKCE S256 与 RS256；使用稳定、针对该客户端的 `sub`。Entra 使用专用单租户登录应用、精确的租户签发者地址、`OIDC_IDENTITY_CLAIM=oid`，并在 SCIM `externalId` 中使用同一用户的 objectId。

注册 HTTPS 回调 `/api/v1/auth/sso/callback`，不要注册前端 `/auth/callback`。后者通过 `POST /api/v1/auth/sso/session` 完成一次性 Cookie 交换，要求精确的 `Origin` 及 `X-SSO-CSRF: 1`。在 IdP 中配置条件访问/MFA：应用不会独立强制检查 MFA 声明。登录请求 `openid profile`，不需要用于清单采集的 Graph 权限。

准备私有 `secrets/oidc_client_secret.txt`，以及使用至少 32 个随机字节独立生成的 `secrets/scim_bearer_token.txt`。配置精确的签发者/客户端/公开源站及明确的 `SCIM_GROUP_ROLE_MAP`；不可变的组外部 ID 授予 `viewer`、`analyst`、`admin`，取最高角色，空映射授予查看者权限。每个 API 副本必须使用相同策略。为 SCIM 企业应用配置租户 URL `/api/v1/scim/v2`，测试连接并明确映射：objectId→externalId、UPN→userName、enabled→active、组 objectId→externalId、成员关系→members。从分配到应用的试点用户/组开始，使用按需预配。

```bash
docker compose -f docker-compose.yml -f docker-compose.sso.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.sso.yml up -d --build
docker compose exec -T frontend nginx -s reload
```

后续所有操作都使用两个 Compose 文件；重新创建 API 后重载 nginx。Kubernetes 需要单独准备 `open-shadow-ai-identity` Secret、仅用于 API 的设置，以及经过审核的 IdP HTTPS 出站规则。标准 NetworkPolicy 不支持按主机名授权。

测试已预配与未预配用户登录、标识匹配、拒绝同意、过期/重放、准确的 Cookie/CSRF 行为、映射组，以及活跃会话期间的停用。禁用、删除或降低角色会在应用**收到变更时**撤销受影响的会话；目录同步延迟不受应用控制。重新激活不会恢复旧令牌。个人资料或未映射组的变更不会结束会话；角色在请求时解析。控制台退出不等于全局 IdP 退出。与预配系统协调凭据轮换并重启 API；当前不提供具有重叠有效期的 SCIM 令牌轮换。SCIM 仅提供范围受限的子集，不支持 Bulk、嵌套组、完整过滤器、SAML 或多个 IdP。参见[身份系统上线与验收（英文参考）](../sso-scim.md)及 [SSO 准入控制（英文参考）](../sso-admission.md)。

## 7. 注册采集器并建立覆盖范围

管理员通过**来源与覆盖范围 → 已注册采集器 → 注册采集器**分配不可变 ID 和最小来源范围。将一次性返回的密钥保存到私有位置；响应丢失时操作可能已经提交，重试前先检查注册信息。轮换默认重叠有效期为 3,600 秒（0–86,400），默认凭据有效期为 365 天（1–365）；已撤销的采集器永久禁用。采集器密钥不能管理注册信息，也不能访问指标。只有在每个数据生产端都已配置限定范围的凭据并验证投递后，才关闭 `ALLOW_LEGACY_AGENT_KEY`；旧版流量没有明确归属。向相关服务显式提供环境变量覆盖，不能仅写入 `.env`。

对于 Windows 终端，构建对应平台的离线 wheel 包目录，并审核哈希值。以 SYSTEM 运行的安装器要求新建受保护的安装目录树、Python/离线包目录由可信管理主体所有，以及安全的祖先目录；不适合使用用户级 Python。在一台设备上预览，验证计划任务与 HTTPS 清单采集，再通过现有 GPO/Intune/Configuration Manager 流程分阶段部署。服务器安装不会部署代理或修改 GPO。SYSTEM 可能无法读取所有用户的浏览器配置文件；扩展采集需要 `browser` 范围。升级、卸载与签名仍属于设备群验收工作。

对于 syslog，选择与来源完全匹配的 BIND/Windows DNS/Squid/PAN-OS/FortiGate 解析器，并配置正确的来源 IANA 时区和时钟。默认 TCP/1514 绑定本地主机；远程转发需要私有地址绑定、防火墙限制，并按要求使用可信 TLS 中继。syslog 发送方身份验证与 HTTP 旧版密钥设置相互独立。完成来源审核后启用：

```bash
docker compose --profile syslog up -d
```

对于网络元数据，明确配置 SPAN/TAP/镜像覆盖范围，使用稳定的传感器/站点 ID，优先采用持久保存的 Zeek JSONL 或 Suricata EVE 日志。在通过身份验证投递之前先检查：

```bash
python -m shadai.collectors.network --sensor-id office-mirror --site-id paris --format zeek-tls --input ssl.jsonl --dry-run --csv-output network-observations.csv
python -m shadai.collectors.network --sensor-id office-mirror --site-id paris --format zeek-tls --input ssl.jsonl --api-url https://shadai.example.test --api-key-file /etc/shadai/network-agent.key --ca-file /etc/shadai/organization-ca.pem --spool-dir /var/lib/shadai/network/office-mirror
```

Zeek TSV 不能作为 JSONL 输入；TShark 的 PCAP/实时提取为可选本地功能，不会上传 PCAP。导入支持 IPv4/IPv6 及 DNS/TLS/QUIC/HTTP。实时接口需要抓包权限并明确选择；安装服务器不会启动任何实时采集。通用事件使用经过身份验证的批次，每批 1–500 条，要求带时区的时间戳与稳定 UUID，并拒绝未知字段。超前五分钟以上或超出 `ingestion_max_age_days` 的时间戳会被拒绝。重试时保留原始时间戳。参见[采集器运维（英文参考）](../collector-operations.md)、[覆盖范围（英文参考）](../collectors.md)与[网络流程（英文参考）](../network-analysis.md)。

## 8. 管理队列、监控与容量

终端/网络/syslog 的 SQLite 本地持久化队列可以在重启后保留准备好的明文元数据：默认保留 64 MiB 载荷、2,048 批、七天；上限为 16 GiB、100,000 批、365 天，TTL 同时受服务器接收年龄上限约束。SQLite、日志和文件系统开销需要单独预留；隔离批次也占用容量。私有路径必须由实际服务账号所有，并具有可信祖先目录（Unix 使用 `0700`/`0600`；Windows 使用受限 ACL）；不要削弱防护检查。Entra 仅重试内存中的批次，不保证崩溃后保留；AD 则保留导出的 JSON。

首次启动离线时可以保留数据，但在目标/采集器发现流程确认绑定之前，不会发送任何数据。出现不匹配时，恢复正确主体；其他租户或注册身份不能接管保留的字节。同一采集器的密钥轮换可以与恢复兼容。租约支持重启恢复；至少一次投递依赖稳定 ID/回执，不提供无限期的严格一次处理保证。采集停机、UDP 丢失、入队前丢弃、过期和磁盘已满都仍可能发生。`capture_loss` 为未知。

Redis 默认每个来源/匹配流最多保留 100,000 条，每个死信队列最多保留 10,000 个指针，每次准入最多 500 条记录/2 MiB 字段字节；显式维护默认使用七天截止年龄。新的防护脚本在写入前检查目标；后续 Lua 分配或内存不足仍可能造成部分写入或结果不确定。保留未经确认的字节，维持 `noeviction`，测量内存和余量。不会通过自动 TTL/MAXLEN 删除待处理来源或活跃指针。待确认消息、可能未知的尚未投递积压量，与保留的重放来源分别统计。修复有问题的数据后，先以模拟模式检查重放：

```bash
python -m shadai.workers.replay --group ingest_group --start 0-0 --end + --limit 100 --dry-run
python -m shadai.workers.replay --group ingest_group --start 0-0 --end + --limit 100 --execute
```

重放保留原始字段与可信 `accepted_at`；不含该字段的旧积压仍需验证原始观测年龄。执行之前检查显式归档/丢弃维护；不得为了消除告警裁剪待处理消息。设定 RPO 之前，验证实际 AOF/fsync 策略：

```bash
docker compose exec -T redis sh -c 'REDISCLI_AUTH="$(cat /run/secrets/redis_password)" redis-cli CONFIG GET appendonly appendfsync maxmemory maxmemory-policy'
```

`/metrics` 需要管理员身份，或独立的只读令牌，令牌至少包含 32 个非空白字符。可选的 Linux/rootful Docker 覆盖配置为 API UID10001 和 Prometheus UID65534 分别使用同一令牌的两份私有副本；绑定挂载的机密文件不会重新映射所有权。抓取路径保持私有，轮换后再次验证身份检查。应用指标覆盖队列，不覆盖物理内存/磁盘。通过目标基础设施监控测量 Redis AOF/内存、容器 CPU/RAM、存储磁盘/inode 及增长。告警规则需要负责人和独立配置的接收端；仅触发规则不会发送通知。Prometheus 本身也需要外部看门狗。

测量基线、范围受限的分阶段负载速率、API/错误响应延迟、待处理年龄、锁、插入、查询延迟，以及排空/回收时间。达到预定阈值时停止。容量预测使用测量的每事件字节数，并计入索引/复制/备份。事件 TTL 与每日清理不同于身份/队列保留；保持 `receipt_days >= ingestion_max_age_days + events_days + 1`。定义 RPO/RTO，并在预期数据规模下演练。参见[队列保留（英文参考）](../queue-retention.md)、[监控（英文参考）](../production-monitoring.md)与[容量（英文参考）](../capacity.md)。

## 9. 备份、迁移与回滚演练

更新之前，备份存储、配置、部署提交、匹配的加密密钥，以及采集器私有本地队列/导出文件。暂停远程生产端和可选采集器，再停止应用写入程序。快照前停止 SQLite 客户端。加密备份并限制访问：服务器假名化不会清理备份或本地明文队列。仅做 PostgreSQL/ClickHouse 逻辑导出会遗漏 Redis 待处理/引用状态；保留存储卷，并明确实际 AOF/刷新边界。

小型试点的逻辑备份流程如下：

```bash
umask 077
mkdir -p backups
docker compose stop api frontend ingest-worker correlation-worker purge-worker
docker compose exec -T postgres pg_dump -U shadai -d shadai -Fc > backups/postgres.dump
docker compose exec -T clickhouse sh -c 'clickhouse-client --user shadai --password "$(cat /run/secrets/ch_password)" --query "SELECT * FROM shadai.events FORMAT Native"' > backups/events.native
docker compose exec -T redis sh -c 'REDISCLI_AUTH="$(cat /run/secrets/redis_password)" redis-cli SAVE'
```

生产恢复目标需要经过测试的数据库原生备份。在独立检出目录/项目中恢复，使用空存储、匹配的版本/密钥、未使用的端口和边缘子网。每条命令都保留该项目名；重复导入并不安全。通过存储平台恢复已停止的 Redis 卷，或明确记录被丢弃的在途数据时间区间。比较事件/检测记录，验证就绪和登录，并完成一个新的合成事件的端到端验证。本地队列只能恢复到原始、已验证的绑定。

迁移 `003` 锁定本地用户，并拒绝空名称或大小写折叠后的重名；明确重命名，绝不静默合并账号。迁移 `004` 增加限定范围的凭据。**迁移 `005` 重置无法确定观测年龄的历史身份数组/计数，清除 `primary_evidence`，删除保留的 `sample_values`、`sample_observations` 和 `network_observations` 摘录，并将风险标记为过期。** 检测记录本身仍然保留。其历史身份依据的观测年龄无法证明；迁移不会赋予新的日期。在恢复副本中评审这一不可逆的证据/计数变化。ClickHouse `002_event_metadata.sql` 必须在会启动依赖的 API 命令之前执行，因为新健康探针会查询旧卷中不存在的 `identity_sid`：

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

先等待存储可连接，必要时重试，再继续执行；SQL 成功之前，ClickHouse 暂时显示不健康属于预期情况。所有可选/远程旧版写入程序也必须停止。启用 SSO 时使用两个 Compose 文件。没有自动结构回滚。存在外部身份/组/审计/撤销记录之后，`003` 拒绝降级；不要删除记录绕过检查。在隔离环境中，使用匹配的代码/配置恢复迁移前备份。参见[更新与恢复（英文参考）](../deployment.md#updates)。

## 10. 维护隐私与访问

不保留路径、查询字符串或用户代理。内存匹配以产品主机为范围；`privacy.match_transient_signals: false` 可禁用该功能。置信度相同的共享签名仍有歧义；目录变化之后，已丢弃的路径不能重建。归属判定前，审核自定义签名与来源反例。

身份成员关系按每次观测独立计算年龄；默认为 `min(30, events_days)`，必须为正且不能超过事件保留期。计数表示观测到的不同标识，不代表员工人数。检查可空的 `risk_calculated_at` 和 `risk_score_stale`；一般更新时间不能证明重新计算过风险。`PSEUDONYMIZE_IDENTITIES` 使用加密密钥派生的按字段隔离 HMAC，为个人字段生成假名，并清除个人来源 IP/自由格式 IdP 文本。假名仍是可关联的组织数据。此设置影响新处理，不影响历史事件、备份或本地队列。

进行已评审的历史清理时，先在恢复数据上演练，暂停采集器，排空队列/本地队列，停止写入/重放，并在整个验证过程中维持该状态：

```bash
python -m shadai.workers.purge --scrub-personal-history --batch-size 500 --max-batches 100
```

检查 `complete`、`clickhouse_complete`、`sql_complete` 和返回游标；受限 SQL 续跑只能使用返回的 `--after-detection-id`。仅在同步工作全部完成且通过验证时退出码才为零；达到处理上限但未完成时退出码非零。账号、备注与审计操作者不在清理范围内。更换加密密钥会改变假名生成基础与加密材料；保留匹配的备份并规划重建。参见[隐私维护（英文参考）](../collector-operations.md#retain-and-pseudonymize-identities)。

## 11. 审查安全与交付证据

检查准确提交对应的强制 Linux/Python、前端、Windows 原生、真实存储/Compose、离线代理、原生 amd64/arm64 镜像及验收验证门槛。通过哈希锁定的依赖锁定文件/基础输入及 BuildKit SBOM/来源证明，将输入与产物绑定；它们不保证不同机器生成相同二进制。镜像扫描必须覆盖其扫描对象/清单，保留所有严重级别及尚无修复的发现。扫描器错误、覆盖不完整，以及可修复的高危/严重或严重级别未知的发现，均按已记录的门槛判定失败。

对于 gosu 和 node_exporter，主模块 SBOM 观测保留 **`UNKNOWN`**；经审核、从源码推导的查询版本不应被伪造为二进制版本。ClickHouse 缺失的主要 SBOM 条目保持原状，同时提供独立声明的查询/CLI 观测。**凡报告中出现 GO-2026-5932，均继续保留可见**；维护中的构建方案不声称从每个镜像层消除了它。早前 npm 审计对具名包报告的零发现，并不覆盖 Vite/Rollup 中嵌入的受影响 `braces`。仅允许字面路径的监视限制缓解已识别的构建工具路径，不覆盖每种解析器/插件风险。

可信的内部 `main` 推送，在全部必要门槛通过后，可能生成针对确切 OCI 归档/证据的已验证 GitHub/Sigstore 证明。签名范围仅限确切的 OCI 归档与独立证据清单，不包括 GitHub 源代码 ZIP。PR 产物没有签名；本地声明文件、标签和测试不等于签名或已签名发行版。验证仓库、工作流、源引用/提交、摘要和托管运行器约束。原生诊断中仍标为未知的根因，在新的绑定证据确认之前仍为未知。遵循[交付与扫描范围（英文参考）](../production-delivery.md)、[验证（英文参考）](../validation.md)、[构建工具安全（英文参考）](../frontend-build-security.md)及[安全策略（英文参考）](../../SECURITY.md)。

## 12. 明确验收验证与推进或停止的条件

使用一次性 Linux/非 root Docker 实验环境，运行准确提交所要求的 `production-qualification` 作业。它测试合成负载、接入/关联中断、待处理消息回收、进程探针、物理资源测量、隔离的 Redis 压力与冷恢复。固定测试配置为 **1,000 个合成事件、10/s、每批 10 条、并发度 2**，请求期限 5 秒、排空期限 120 秒、工作预算 1,500 秒、500 次请求、每请求 2 MiB、产物上限 10 GiB。加上终止宽限后，声明的应用时间上限为 **1,512 秒**。这些是测试输入，不代表生产容量或 RPO/RTO。

冷恢复必须在工作进程启动之前比较完整私有清单，并证明**十个新接受的不同事件，加上已备份的 PEL 事件**，每个事件均在 ClickHouse 中持久化，并具有 PostgreSQL 接入/关联回执。仅恢复待处理消息并不足够。诊断可定位阶段，不能证明根因或成功。合成质量语料得到 TP=1、FP=1、FN=2、TN=1、精确率=0.5、召回率=1/3、F1=0.4；真实标签未知及分母为零的情况仍须明确。它测量的是规范化元数据匹配，不是采集能力、真实模型使用或校准后的概率。

目标环境运行器的预检/负载/Kubernetes/IdP/评估流程，需要经过审核、与实际上下文完全匹配的计划、专用采集器和私有证据。Kubernetes 的 `--execute` 执行服务器端模拟运行/清单读取，不执行部署，也不能证明高可用。IdP 流程不执行时只检查元数据/健康状态。**`idp --execute` 在所有平台上均已禁用**，会在浏览器启动或访问账号引用之前返回 `unsupported_browser_containment`、`not_evaluated`，退出码为 2。仍需要经人工授权的实际登录/MFA、Cookie、会话/CSRF/退出，以及角色/停用观测。调用者提供的成功标记不能成为独立证据。

| 门槛 | 允许进入下一个范围受限的试点阶段 | 不允许推进或仍需补充的证据 |
|---|---|---|
| 安装与队列 | 准确提交的强制门槛通过；迁移、核对与重建、实际就绪和合成端到端验证完成 | 必需场景被跳过、原生证据缺失或失败、存储不健康、保留关系图仍在构建 |
| 来源与身份 | 范围已批准、凭据/本地队列私有、轮换/撤销已测试；有明确正例/反例和覆盖证据 | 将未知映射当作身份、把清单称为使用、缺少实际 AD/Entra/IdP/MFA 验收 |
| 恢复与资源 | 已演练恢复、限定故障与排空时长、已测量容量/余量，并按预期规模约定 RPO/RTO | 只恢复待处理消息、假定 AOF 断电持久性、未测量高可用或资源覆盖 |
| 安全与运维 | 已接受适用的绑定扫描/签名、审核剩余发现、有负责人及经过测试的通知路径 | 扫描器错误/覆盖不全、安全门槛失败、声称 PR 产物有签名、接收端未经测试 |

退出码 0 表示测量标准满足，1 表示测量/标准失败，2 表示缺少前提或证据。可选的精确率/召回率/延迟/故障恢复/备份恢复目标需要实际测量。实验环境成功后可以评审其声明范围内的证据；生产部署需要针对目标环境完成来源、访问、容量、故障、隐私和恢复验收。参见[完整验收验证流程（英文参考）](../production-qualification.md)。

## 13. 排障并维护试点

| 症状 | 范围受限的排查与处理 |
|---|---|
| API 存活，工作进程未就绪 | 检查依赖、实际组及 `retention_ready`；初始化后重试核对与重建，或修复中断的关系图重建，保留积压 |
| 接入返回 503 或出现积压 | 检查准确的保留上限、Redis 类型/内存和下游健康状态；保留结果不确定的字节；区分待处理/未投递积压与保留原始记录 |
| 采集器返回 401/403 | 检查过期/撤销/来源/租户/采集器范围；恢复正确密钥，不要绑定到其他注册身份的队列 |
| 旧事件或未来事件被拒绝 | 验证来源时区/时钟及服务器年龄窗口；不得改写来源时间戳 |
| 联系正常但没有检测记录 | 核对解析器、反例/共享签名、未映射的 Entra appId 和观测来源；无活动可能是正常情况 |
| 本地队列/机密文件 ACL 被拒绝 | 在实际账号下准备可信私有路径；检查祖先目录/重解析点/硬链接，不要扩大权限 |
| SSO 返回 429/503 或拒绝登录 | 检查共享 Redis 准入、精确代理对端/签发者、活跃 SCIM 映射及提供商状态；使用本地恢复管理员 |
| 缺少指标或未收到通知 | 验证私有令牌副本/UID、抓取及完整十流清单，再检查接收端路由；仅配置规则不会发送通知 |

工作进程故障时，使用[脱敏诊断（英文参考）](../worker-diagnostics.md)；不要将原始机密值、OAuth 回调查询字符串或包含个人信息的生产日志放入公开问题。定期检查采集器、访问、存储增长、归档、过期风险和保留策略。来源、身份系统、镜像、密钥、保留期、拓扑或接收端发生变化后，重新演练。通过[贡献流程（英文参考）](../../CONTRIBUTING.md)提交最小合成复现，并根据安全策略私下报告漏洞。
