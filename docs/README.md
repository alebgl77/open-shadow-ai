# Documentation / Documentation / 文档

[English](en/README.md) | [Français](fr/README.md) | [简体中文](zh-CN/README.md)

| Language / Langue / 语言 | Implementation handbook / Guide de mise en œuvre / 实施手册 | Project introduction / Présentation / 项目介绍 |
|---|---|---|
| English | [Expert implementation handbook](en/README.md) | [README](../README.md) |
| Français | [Guide de mise en œuvre pour experts](fr/README.md) | [README français](../README.fr.md) |
| 简体中文 | [专家实施手册](zh-CN/README.md) | [中文 README](../README.zh-CN.md) |

## Source and release / Code source et préversion / 源代码与预发行版

Documentation alignment / Alignement documentaire / 文档对齐日期: **2026-10-15**.

| Baseline / Référence / 基线 | Exact source / Source exacte / 准确源代码 | Availability / Disponibilité / 可用性 |
|---|---|---|
| Maintained source / Code maintenu / 维护中的源代码 | `d159ed68012281a2c9e887e1281d44f0fb75112c` — merged [PR #17](https://github.com/alebgl77/open-shadow-ai/pull/17); backend `0.3.0`, agent `0.3.0` | Extension inventory, three-language console and handbooks, cartography and 15 October corrections / Inventaire des extensions, console et guides en trois langues, cartographie et corrections du 15 octobre / 扩展清单、三语言控制台与手册、关系图及 10 月 15 日修复 |
| Published prerelease / Préversion publiée / 已发布的预发行版 | `v0.3.0` — **2026-10-07**, `49a58d778d3014879e30a3ac5334df45cd426dbf`; backend `0.3.0`, agent `0.1.0` | Earlier preview; none of the additions above / Préversion antérieure ; aucun des ajouts ci-dessus / 较早的预览版本，不含上述新增功能 |

These guides apply to the maintained source baseline above. The latest published release remains `v0.3.0`; component version `0.3.0` alone cannot identify the available features or security corrections. Record the exact deployed commit, configuration revision, image digests and CI/build evidence. Source changes and successful CI do not publish or deploy images and do not certify a target environment. Later revisions need their own qualification.

Ces guides s'appliquent au code maintenu indiqué ci-dessus. La dernière préversion publiée reste `v0.3.0` ; le seul numéro de composant `0.3.0` ne permet pas d'identifier les fonctionnalités ou corrections de sécurité disponibles. Consignez le commit exact déployé, la révision de configuration, les digests d'images et les preuves CI/de construction. Les changements de code et une CI réussie ne publient ni ne déploient des images et ne certifient aucun environnement cible. Toute révision ultérieure exige sa propre qualification.

这些手册适用于上表所列的维护中源代码基线。最新发布版本仍为 `v0.3.0`；仅凭组件版本号 `0.3.0` 无法确定可用功能或安全修复。应记录实际部署的准确提交、配置修订、镜像摘要以及 CI/构建证据。源代码变更和 CI 成功不会发布或部署镜像，也不能认证目标环境。后续修订需要各自的验收验证。

## Reading order / Parcours de lecture / 阅读顺序

Start with your language's handbook, then use these references in order. The handbooks cover equivalent installation, identity, collection, recovery, privacy and qualification procedures. Detailed references marked English remain in English; the current cartography, roadmap, audit remediation and governance guides have the three language versions linked below.

Commencez par le guide dans votre langue, puis suivez ces références dans l'ordre. Les guides couvrent les mêmes procédures d'installation, d'identité, de collecte, de reprise, de confidentialité et de qualification. Les références signalées en anglais restent en anglais ; les guides actuels de cartographie, de roadmap, de correction d'audit et de gouvernance sont disponibles dans les trois langues ci-dessous.

先阅读所选语言的实施手册，再按顺序查阅以下资料。三份手册涵盖等效的安装、身份管理、采集、恢复、隐私和验收验证流程。标为英文参考的详细资料仍使用英文；当前关系图、路线图、审计修复及治理指南提供下列三种语言版本。

| Order / Ordre / 顺序 | English | Français | 简体中文 |
|---|---|---|---|
| 1 | [Deployment and topology (English reference)](deployment.md) · [Architecture (English reference)](architecture.md) | [Déploiement et topologie (référence en anglais)](deployment.md) · [Architecture (référence en anglais)](architecture.md) | [部署与拓扑（英文参考）](deployment.md) · [架构（英文参考）](architecture.md) |
| 2 | [AD/Entra inventory (English reference)](microsoft.md) · [SSO/SCIM (English reference)](sso-scim.md) | [Inventaire AD/Entra (référence en anglais)](microsoft.md) · [SSO/SCIM (référence en anglais)](sso-scim.md) | [AD/Entra 清单（英文参考）](microsoft.md) · [SSO/SCIM（英文参考）](sso-scim.md) |
| 3 | [Source coverage (English reference)](collectors.md) · [Network limits (English reference)](network-analysis.md) · [Cartography and radars](cartography.md) | [Couverture des sources (référence en anglais)](collectors.md) · [Limites réseau (référence en anglais)](network-analysis.md) · [Cartographie et radars](fr/cartography.md) | [来源覆盖范围（英文参考）](collectors.md) · [网络边界（英文参考）](network-analysis.md) · [关系图与雷达图](zh-CN/cartography.md) |
| 4 | [Collector operations (English reference)](collector-operations.md) · [Queue retention (English reference)](queue-retention.md) · [Recovery (English reference)](deployment.md#backup-and-restore) | [Exploitation des collecteurs (référence en anglais)](collector-operations.md) · [Rétention des files (référence en anglais)](queue-retention.md) · [Reprise (référence en anglais)](deployment.md#backup-and-restore) | [采集器运维（英文参考）](collector-operations.md) · [队列保留（英文参考）](queue-retention.md) · [恢复（英文参考）](deployment.md#backup-and-restore) |
| 5 | [Qualification (English reference)](production-qualification.md) · [Validation record (English reference)](validation.md) · [Delivery evidence (English reference)](production-delivery.md) | [Qualification (référence en anglais)](production-qualification.md) · [Compte rendu de validation (référence en anglais)](validation.md) · [Preuves de livraison (référence en anglais)](production-delivery.md) | [验收验证（英文参考）](production-qualification.md) · [验证记录（英文参考）](validation.md) · [交付证据（英文参考）](production-delivery.md) |
| 6 | [15 October remediation and operator checks](audit-remediation-2026-10-15.md) · [Repository governance](repository-governance.md) | [Corrections du 15 octobre et contrôles d'exploitation](fr/audit-remediation-2026-10-15.md) · [Gouvernance du dépôt](fr/repository-governance.md) | [10 月 15 日修复与运维检查](zh-CN/audit-remediation-2026-10-15.md) · [仓库治理](zh-CN/repository-governance.md) |
| 7 | [Roadmap and future delivery gates](roadmap.md) | [Roadmap et critères des étapes futures](fr/roadmap.md) | [路线图与后续交付条件](zh-CN/roadmap.md) |

## Language coverage / Couverture linguistique / 语言覆盖范围

Technical commands, configuration keys, raw source values and machine/API identifiers remain literal. The console offers English, French and Simplified Chinese before and after sign-in. Its validated browser-local preference is independent of authentication; absent or blocked storage defaults to English. Historical audits, validation records and changelogs retain their stated language and source-specific scope. Existing motion diagrams contain illustrative French labels and synthetic data.

Les commandes, clés de configuration, données brutes des sources et identifiants techniques/API restent littéraux. La console propose l'anglais, le français et le chinois simplifié avant et après connexion. Sa préférence locale au navigateur, validée, est indépendante de l'authentification ; sans préférence disponible ou si le stockage est bloqué, l'anglais est utilisé. Les audits historiques, comptes rendus de validation et journaux de modifications conservent leur langue indiquée et leur portée propre. Les schémas animés existants contiennent des libellés illustratifs en français et des données synthétiques.

技术命令、配置键、原始来源值和机器/API 标识符保留原文。控制台在登录前后均提供英语、法语和简体中文。经验证的浏览器本地语言偏好独立于身份验证；没有可用偏好或存储受限时默认使用英语。历史审计、验证记录和变更日志保留其声明的语言与各自来源的范围。现有动画图使用法语说明文字和合成数据。
