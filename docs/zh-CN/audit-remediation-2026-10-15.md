# 2026 年 10 月 15 日审计修复

[English](../audit-remediation-2026-10-15.md) | [Français](../fr/audit-remediation-2026-10-15.md) | [简体中文](audit-remediation-2026-10-15.md)

本运维指南说明项目全面审计中十项问题的修复契约。每项问题对应一项逻辑变更；文档单独维护。本指南不是版本发布公告、当前提交的 CI 结果或生产认证。请确认实际部署的源码包含这些变更，并保留准确提交、配置修订及构建证据。仅凭版本号 `0.3.0` 无法识别这些变更。安装前提见[专家手册](README.md)。

## 1. 逻辑变更与验收

| 问题 | 修复后的契约 | 运维检查 |
|---|---|---|
| F01 — Entra 隐私 | 可信 `prepare_event` 在队列序列化和保留之前执行。启用假名化后，新身份字段在此边界受保护；签名预处理与重试的准确字节保持一致。 | 使用计划的隐私配置测试合成清单，验证采集器重启和重试行为。不会清理已经保留的原始数据。 |
| F02 — 密码计算 | 每个 API 进程通过同一个有上限服务最多接纳四项并发 bcrypt 操作，登录验证和管理员创建密码的哈希共用容量。原生计算不占用事件循环；请求取消不会提前释放原生工作的容量。 | 在受限并发下检查成功/失败登录及账号创建。容量饱和返回 `429`，服务不可用返回 `503`，两者均带 `Retry-After: 1`。独立的来源登录配额保留 `429` 和 `Retry-After: 60`。 |
| F03 — Kubernetes 探针 | 三个工作阶段均使用目标验证渲染器采用的阶段专属启动、存活和就绪探针。仅有活动 PID 或 Redis 可达不能再掩盖停滞的工作进程。 | 在目标集群验证初始化、本地心跳、阶段进展及实际依赖；保留可写的私有 `/tmp` 和现有安全上下文。 |
| F04 — 维护镜像 | gosu 选择 `github.com/moby/sys/user v0.4.1`，替代 `v0.1.0` 以修复 `CVE-2026-61801`。其他已选模块和编译器固定版本不变。五项维护配方统一升至修订 `3`。 | 重新构建并检查 Linux amd64/arm64 原生结果、最终运行时扫描和来源证据。本地 `maintained.3` 标签不证明镜像已发布或此前部署已修复。 |
| F05 — 仓库策略 | 期望的 `main` 策略要求 PR、绑定 GitHub Actions 应用 `15368` 的全部 32 项检查、严格保持分支最新且约束管理员；禁用强制推送和删除，要求解决讨论。 | 审查及当前提交 CI 通过后才应用，再回读有效设置。单维护者配置有意采用 `0` 次必需批准，不强制人工批准。提交模板本身不会启用保护。 |
| F06 — UTC 边界 | 在 UTC 规范化中溢出的规范时间戳无效。外部请求收到 `422`；无效内部信封按永久无效处理，不按临时故障重试。 | 使用合成时间戳覆盖 UTC 两端边界，检查无效数据不会作为已接受事件入队。 |
| F07 — TCP 记录隔离 | 解析器独立拒绝格式错误的记录，使相邻有效 TCP 记录能够继续处理。投递失败与取消仍会传播。 | 在两条有效记录之间发送合成无效记录；另行检查投递拒绝和取消。解析器隔离不等于投递保证。 |
| F08 — Palo Alto 来源时间 | 有效显式键值时间优先，否则使用 RFC5424 标头报告的时间。缺失、NILVALUE `-` 或无效时间被拒绝，不再替换成导入时间。 | 启用前验证导出器时间字段、时区和旧数据重放。即使标头有效，格式错误的显式字段仍会被拒绝。 |
| F09 — 发现重新激活 | 无论强度如何，旧回填都不能重新打开 `stale` 或 `archived` 发现。当前传入信号使用与新建发现相同的评分阈值重新打开它。 | 检查回填和 30 天边界。新信号评分低于 `0.70` 为 `suspected`，低于 `0.90` 为 `probable`，否则为 `high_confidence`；历史聚合强度不决定重新打开后的状态。 |
| F10 — 网络证据 | 候选样本在选择前合并，按作用域内事件 UUID 去重，再按实际 UTC 时刻和确定性同序规则保留最新十条。旧记录不会仅因最后到达就挤掉较新证据。 | 检查乱序、亚秒/时区表示和重复输入。样本选择不改变聚合活动计数、回执幂等性或证据限制。 |

这些变更不会虚构 IP 与主机之间的连接、员工归属、已完成的 AI 请求、提示词、模型、词元数量或来源文件位置。关系图继续区分网络观测与主机报告的安装。分析员决策和备注与自动发现状态分开保留。

## 2. 兼容性、隐私与来源时钟

F01 影响新准备的 Entra 批次；启用假名化不会重写历史 Redis 流、AOF/备份、已经保留的待投递载荷、事件存储或导出。保留配套密钥及现有保留控制。识别与清理历史数据需要另行批准、范围受限的维护计划，事先审查备份/恢复和重放影响。不要为使验证通过而删除保留数据或轮换加密密钥。

F08 有意拒绝没有时间戳的记录。配置导出器报告有效时间，不要用采集时间替代以使旧记录看起来是新数据。RFC5424 标头要求受支持的日历式 RFC3339 时间戳及有效偏移。现有显式本地格式使用配置的来源时区。旧 BSD 时间戳不含年份，由处理时钟推断，不适用于要求无歧义的历史重放；这种场景应使用包含年份的时间戳。保留规则仍依据报告的观测时间。

F02 将已知的繁忙/不可用响应以英语、法语和简体中文显示，不暴露原始服务器错误。四个名额按 API 进程计算，不是整个集群的密码配额。合理容量仍需实测；增加 API 进程会改变原生工作接纳总量。保留现有来源限流和可信代理配置。

bootstrap 修复仅为新创建的机密文件写入 LF 换行；Windows 的 CRLF 输出可能引入 ClickHouse 拒绝的回车符。现有文件的字节保持不变，因此不会修复此前生成的 CRLF 机密。不要直接删改或替换正在使用的密码文件：受影响的现有安装需要协调轮换凭据，确保与存储凭据和备份一致。现有隐私和安全检查继续生效。

## 3. 准备与验证源码

使用可信的已审查修订及一次性开发环境。以下 Bash 示例安装已提交并校验哈希的依赖闭包和本地项目；Windows PowerShell 中将激活命令替换为 `./tmp/audit-remediation-env/Scripts/Activate.ps1`。不要将此环境作为生产运行时。

```bash
python -m venv tmp/audit-remediation-env
source tmp/audit-remediation-env/bin/activate
python -m pip install --only-binary=:all: --require-hashes -r requirements/build.txt
python -m pip install --only-binary=:all: --require-hashes -r requirements/development.txt
python -m pip install --no-deps --no-build-isolation . ./agent
git rev-parse HEAD
```

在仓库根目录运行针对性回归组与现有源码检查。这些命令是验证流程，不表示某个当前提交已经通过：

```bash
python -m pytest -q tests/test_entra_privacy.py tests/test_password_work.py tests/test_kubernetes_worker_probes.py tests/test_repository_governance.py tests/test_canonical_utc_bounds.py tests/test_syslog_record_isolation.py tests/test_paloalto_timestamps.py tests/test_detection_reactivation.py tests/test_network_evidence_ordering.py
python -m pytest -q tests/test_service_builds.py tests/test_image_scan_layout.py tests/test_monitoring_alerts.py
python -m ruff check src tests agent/shadai_agent migrations scripts
python scripts/lock-dependencies.py --check
python scripts/verify-image-pins.py
```

使用受支持的 Node.js 22.x 工具链验证本地化前端：

```bash
cd frontend
npm ci
npm test
npm run build
cd ..
```

检查完整结果，包括跳过项和环境拒绝；不要累加相互重叠的测试数量。本地源码测试或交叉编译二进制不能替代原生 OCI 构建、扫描证据、实际存储验证或 Windows ACL 检查。

治理测试夹具仅在相应测试执行时加载，使筛选后的运行时测试能够在缺少仓库专属文件时完成收集，同时保留全部治理断言。请针对已审查的准确提交，通过相关原生运行时和 Windows 作业验证这两项修复。

验证步骤失败后，工作流中显示的诊断步骤名称可提供固定代码，供故障排查使用。状态 unavailable 表示诊断未知，不能据此确定失败原因。查阅这些元数据时，不要下载私有报告、原始日志或混合制品。这些代码不授予批准或验收权限，也不改变原始失败结果或验收要求。

新生成的验证负载将 UTC 来源时间基准与紧接其后采样的单调时钟节奏基准配对。准备时间仍计入原有预算、截止期限和测量时长。已保留的清单和重试载荷保持相同字节及事件 ID，配置的事件速率不变。验证器继续拒绝负延迟，不会将其归零。

## 4. 受控重建与重新部署

维护窗口前，备份存储、配置及配套密钥，演练恢复，并暂停采集器/远程生产者和应用写入。保留私有卷和凭据。从旧结构升级时，先完成[现有升级流程，英文参考](../deployment.md#updates)；下列命令不能替代 ClickHouse/PostgreSQL/Redis 迁移顺序。

对已经采用审计时结构的安装，使用现有私有配置重建并重启已审查的基础服务：

```bash
docker compose config --quiet
docker compose build
docker compose up -d
docker compose up -d --wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend
docker compose ps --all
curl --fail http://127.0.0.1:8443/health
curl --fail http://127.0.0.1:8443/ready
```

SSO/监控应使用与原安装相同的可选 Compose 文件；按相应流程重建/重建容器，覆盖启用的采集器及两个监控配置。仅重启基础服务不会更新可选 Prometheus/node-exporter 或远程代理。核对每个部署镜像与已审查配方/源码和构建证据。替换文件不会删除下层中的旧字节，也不会自动修复此前运行的容器。项目 CI 不发布或部署这些镜像。

Kubernetes 应准备私有 overlay，使用经批准的不可变镜像、外部存储路由和现有机密。遵循 [Kubernetes 指南，英文参考](../../deploy/kubernetes/README.md)，应用前渲染并执行服务器端校验。对于已经准备好的基础配置：

```bash
kubectl kustomize deploy/kubernetes/base > rendered.yaml
kubectl apply --dry-run=server -k deploy/kubernetes/base
kubectl -n open-shadow-ai get pods
kubectl -n open-shadow-ai rollout status deployment/api
```

在实际集群验证各工作阶段探针及依赖、入口/TLS、NetworkPolicy、中断和恢复。启动/存活检查保持本地；就绪检查通过 `/app/entrypoint.py` 解析已挂载机密文件。保留 6 秒超时、启动每 5 秒/60 次失败、存活/就绪每 10 秒/3 次失败，以及 64 MiB 可写 `/tmp`。渲染后的清单或健康 API 不构成集群验收。

## 5. 重新验证与 CI 证据

在资源充足、专用且可丢弃的 Docker 环境演练。每次运行使用新的私有目录，执行前审查计划，并保留与源码绑定的报告。这些命令仅用于隔离实验室，不能针对生产数据：

```bash
python scripts/qualification-lab.py plan --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
python scripts/qualification-lab.py run --execute --docker-context default --profile deploy/qualification/profiles/lab-smoke.json --run-dir "$HOME/qualification-new"
```

有关期限、恢复和经过验证的清理，遵循[验证与恢复，英文参考](../production-qualification.md)。原生构建/扫描/来源证据必须覆盖两种受支持 Linux 架构；真实 AD/Entra/SSO 行为和安装容量/RPO/RTO 需要各自的证据。不要为了得到绿色结果而隐藏问题或放宽探针、文件系统、保留或扫描保护。

将 CI 元数据与已审查的准确提交核对：

```bash
git rev-parse HEAD
gh run list --workflow ci.yml --limit 10 --json databaseId,headSha,event,status,conclusion
```

选择匹配的运行、提交和事件，验证全部 32 项必需 PR 检查及每个矩阵项。合并后另行核对该源码 main 推送的签名证据；此前的绿色运行不能证明新提交。只检查作业/步骤状态元数据，不下载原始日志、批注或可能包含敏感内容的混合制品。

## 6. 应用并验证仓库治理

准确的已审查请求、前提及回读字段见[仓库治理](repository-governance.md)。F05 需要当前提交 CI 通过后执行经授权的外部应用，不能仅提交 `.github/main-protection.json`。同时检查 ruleset 与分支保护。单维护者配置要求管理员使用 PR 并满足检查，但有意不要求人工批准；提高批准数需审查人员与访问安排。本指南不隐含授予仓库权限、合并、发布、生产部署或清理历史数据的授权。
