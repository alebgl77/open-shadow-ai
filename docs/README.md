# Documentation / Documentation / 文档

[English](en/README.md) | [Français](fr/README.md) | [简体中文](zh-CN/README.md)

| Language / Langue / 语言 | Complete implementation handbook / Guide complet / 完整实施手册 | Project introduction / Présentation / 项目介绍 |
|---|---|---|
| English | [Expert implementation handbook](en/README.md) | [README](../README.md) |
| Français | [Guide de mise en œuvre pour experts](fr/README.md) | [README français](../README.fr.md) |
| 简体中文 | [专家实施手册](zh-CN/README.md) | [中文 README](../README.zh-CN.md) |

The three handbooks cover equivalent installation, identity, collection, recovery, security and qualification procedures. Technical commands, configuration keys and machine identifiers remain literal. Detailed operational documents at this level are English references; historical audits, validation records and changelogs are not claimed to have complete translations. Existing motion diagrams contain illustrative French labels and synthetic data.

Les trois guides couvrent les mêmes procédures d'installation, d'identité, de collecte, de reprise, de sécurité et de qualification. Les commandes, clés de configuration et identifiants techniques restent littéraux. Les documents opérationnels détaillés de ce répertoire sont des références en anglais ; les audits historiques, comptes rendus de validation et journaux de modifications ne sont pas présentés comme intégralement traduits. Les schémas animés existants contiennent des libellés illustratifs en français et des données synthétiques.

三份手册涵盖等效的安装、身份管理、采集、恢复、安全和资格验证流程。技术命令、配置键和机器标识符保留原文。本目录中的详细操作文档为英文参考资料；历史审计、验证记录和变更日志并未宣称已全部翻译。现有动画图使用法语说明文字和合成数据。

The console offers English, French and Simplified Chinese before and after sign-in. Its validated browser-local preference is independent of authentication; absent or blocked storage defaults to English. Raw source data and machine/API identifiers retain their original values.

La console propose l'anglais, le français et le chinois simplifié avant et après connexion. Sa préférence locale au navigateur, validée, est indépendante de l'authentification ; sans stockage disponible ou si celui-ci est bloqué, l'anglais est utilisé. Les données brutes et identifiants techniques/API gardent leurs valeurs originales.

控制台在登录前后均提供英语、法语和简体中文。经验证的浏览器本地语言偏好独立于身份验证；没有可用偏好或存储受限时默认使用英语。原始来源数据和机器/API 标识符保留原值。

Documentation alignment: **2026-10-08**; backend preview **0.3.0**, standalone agent **0.1.0**. The operational procedures use source commit `49a58d778d3014879e30a3ac5334df45cd426dbf` as their baseline. The three-language console and handbooks were merged into `main` in [commit `7a12513eb1e1e3a800ba8d71f4726a3b5045b669`](https://github.com/alebgl77/open-shadow-ai/commit/7a12513eb1e1e3a800ba8d71f4726a3b5045b669). The published `v0.3.0` prerelease at `49a58d7` predates localization; both source revisions declare `0.3.0`. Use the exact deployed commit to verify availability. Later source changes require their own operational and CI evidence. These guides do not certify production readiness or replace the exact deployed commit's qualification.

Alignement documentaire : **8 octobre 2026** ; backend en préversion **0.3.0**, agent autonome **0.1.0**. Les procédures opérationnelles prennent pour socle le commit source `49a58d778d3014879e30a3ac5334df45cd426dbf`. La console et les guides en trois langues ont été fusionnés dans `main` au [commit `7a12513eb1e1e3a800ba8d71f4726a3b5045b669`](https://github.com/alebgl77/open-shadow-ai/commit/7a12513eb1e1e3a800ba8d71f4726a3b5045b669). La préversion publiée `v0.3.0`, au commit `49a58d7`, précède la localisation ; les deux révisions sources déclarent `0.3.0`. Vérifiez les fonctionnalités disponibles à partir du commit exact déployé. Toute évolution ultérieure exige ses propres preuves opérationnelles et CI. Ces guides ne certifient pas l'aptitude à la production et ne remplacent pas la qualification du commit déployé.

文档对齐日期：**2026 年 10 月 8 日**；后端预览版 **0.3.0**，独立代理 **0.1.0**。操作流程以源代码提交 `49a58d778d3014879e30a3ac5334df45cd426dbf` 为基线。三语言控制台与手册通过[提交 `7a12513eb1e1e3a800ba8d71f4726a3b5045b669`](https://github.com/alebgl77/open-shadow-ai/commit/7a12513eb1e1e3a800ba8d71f4726a3b5045b669)合并到 `main`。已发布的 `v0.3.0` 预发行版位于提交 `49a58d7`，早于本地化功能；两个源代码修订均声明版本 `0.3.0`。应根据实际部署的准确提交核对功能可用性。后续代码变更需要各自的操作验证和 CI 证据。这些手册不构成生产就绪认证，也不能替代对实际部署提交的资格验证。

Detailed procedures: [Deployment (English reference)](deployment.md), [Microsoft (English reference)](microsoft.md), [OIDC/SCIM (English reference)](sso-scim.md), [Collector operations (English reference)](collector-operations.md), [Queue retention (English reference)](queue-retention.md), [Qualification (English reference)](production-qualification.md), [Security (English reference)](../SECURITY.md).
