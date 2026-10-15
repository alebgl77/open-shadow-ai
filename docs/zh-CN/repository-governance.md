# 仓库治理

[English](../repository-governance.md) | [Français](../fr/repository-governance.md) | [简体中文](repository-governance.md)

`alebgl77/open-shadow-ai` 经审查的期望策略位于 [`.github/main-protection.json`](../../.github/main-protection.json)。提交此文件不会启用 GitHub 分支保护。必须由获授权的仓库管理员单独应用，并通过新的 API 回读验证。该文件是 `main` 分支的完整更新请求，不是实际生效设置的记录。

## 单维护者策略

策略要求使用 pull request、分支保持最新，并满足 [CI](../../.github/workflows/ci.yml) 的全部 32 项必需 PR 检查上下文。每项上下文绑定至 GitHub Actions 应用，ID 为 `15368`；其他应用发出的同名检查不能满足要求。管理员也受这些要求约束。禁用强制推送和分支删除，要求解决讨论，且不配置绕过 PR 的例外。

仓库仅有一名维护者时，`required_approving_review_count` 有意设为 `0`。非空的 PR 审查配置保留 PR 要求，同时不要求作者批准自己的 PR。本配置不强制人工批准，也不能替代独立代码/安全审查。推送新提交时会使过时审查失效。如果通过另行授权的访问变更任命第二名维护者，应审查策略，并将批准数提高至至少 `1`，以要求独立人工审查。此模板不授予仓库访问权限。

必需检查覆盖 Python 3.12/3.13、前端、网络元数据、PowerShell、Compose 集成、依赖安全、离线代理、应用镜像、维护服务构建和生产验证。签名矩阵仅在推送至 `main` 后执行，不是 PR 前提。如果在 PR 中要求这 20 项 main 专属执行，会导致永久无法合并。

## 审查与应用

从仓库根目录，使用项目经过哈希校验的开发环境运行离线契约测试：

```sh
python -m pytest -q tests/test_repository_governance.py
python -m ruff check tests/test_repository_governance.py
```

测试通过安全 YAML 加载器解析真实工作流，展开字面矩阵，不执行 GitHub 表达式。它们拒绝缺失或重复检查、错误应用绑定、不受支持的命名/条件变更，以及偏离已审查单维护者配置的设置。它们不会查询 GitHub，也不能证明实际保护已生效。

应用前审查准确策略和源码提交，确认当前仓库管理权限，检查现有分支保护与 ruleset，并验证当前 PR 提交的所有必需检查均成功。如果作业名称或矩阵维度变化，更新并重新测试模板。规则冲突或策略并发变更需要再次审查，不应盲目覆盖。

获授权的管理员可以用 GitHub CLI 检查当前状态：

```sh
gh api repos/alebgl77/open-shadow-ai/branches/main
gh api repos/alebgl77/open-shadow-ai/branches/main/protection
gh api repos/alebgl77/open-shadow-ai/rulesets
```

保护端点返回 `404` 时，必须结合仓库访问权限及分支/ruleset 响应解释；它本身不能证明分支未受保护。经审查的前提满足后，从仓库根目录应用以下准确请求：

```sh
gh api --method PUT repos/alebgl77/open-shadow-ai/branches/main/protection --input .github/main-protection.json
gh api repos/alebgl77/open-shadow-ai/branches/main/protection
gh api repos/alebgl77/open-shadow-ai/branches/main
```

检查返回状态，不要假定请求成功就代表所有设置均已安装：

- `required_status_checks.strict` 为 `true`；其 `checks` 恰好包含模板中的 32 组不同上下文/应用组合。请求仅使用 `checks`，省略已弃用的 `contexts` 字段；不要同时发送这两种表示。GitHub 仍可能在响应中填充 `contexts` 列表。
- `enforce_admins.enabled` 为 `true`；分支响应显示 `protected: true`。
- `required_pull_request_reviews` 非空，必需批准数为 `0`，启用过时审查失效，禁用代码所有者审查及最后推送批准。不存在绕过用户、团队或应用。
- 启用讨论解决要求，禁用强制推送和删除。GitHub 在响应中使用含 `enabled` 的对象表示这些字段，而不是请求中的布尔值。
- 未出现推送限制或未审查例外。在声称有效策略已经验证前，结合分支保护检查仓库 ruleset。

保存带日期、绑定源码的已审查请求与有界回读元数据记录。不要包含认证 token、原始 CI 日志或无关仓库数据。工作流或治理变更后重新检查。管理员之后仍能修改保护，因此此配置并非不可变的安全边界。

API 契约，包括单维护者零批准的有效设置及应用绑定检查，参见 [GitHub 分支保护 REST API](https://docs.github.com/en/rest/branches/branch-protection?apiVersion=2022-11-28#update-branch-protection)。
