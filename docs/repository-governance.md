# Repository governance

[English](repository-governance.md) | [Français](fr/repository-governance.md) | [简体中文](zh-CN/repository-governance.md)

The reviewed desired policy for `alebgl77/open-shadow-ai` is [`.github/main-protection.json`](../.github/main-protection.json). Committing this file does not enable GitHub branch protection. Enforcement must be applied separately by an authorized repository administrator and verified through a fresh API readback. The file is a complete update request for the `main` branch, not a record of its live settings.

## Single-maintainer policy

The policy requires pull requests, an up-to-date branch and all 32 mandatory pull-request check contexts from [CI](../.github/workflows/ci.yml). Each context is bound to the GitHub Actions application, ID `15368`; another application's identically named check cannot satisfy it. The requirements also apply to administrators. Force pushes and branch deletion are disabled, conversations must be resolved, and no pull-request bypass allowance is configured.

`required_approving_review_count` is deliberately `0` while the repository has one maintainer. The non-null pull-request review configuration retains the pull-request requirement without requiring an approval the author cannot provide to their own pull request. This profile does not require human approval or replace independent code/security review. It dismisses stale reviews when new commits are pushed. If a second maintainer is appointed through a separately authorized access change, review this policy and raise the approval count to at least `1` before requiring an independent human reviewer. This template does not grant repository access.

The required checks cover Python 3.12/3.13, frontend, network metadata, PowerShell, Compose integration, dependency security, offline agents, application images, maintained service builds and production qualification. The signing matrix runs only after a push to `main`; it is not a pull-request prerequisite. Requiring its 20 main-only executions on pull requests would block merging indefinitely.

## Review and application

Run the offline contract tests from the repository root using the project's hash-locked development environment:

```sh
python -m pytest -q tests/test_repository_governance.py
python -m ruff check tests/test_repository_governance.py
```

These tests parse the real workflow using a safe YAML loader and expand its literal matrices without evaluating GitHub expressions. They reject missing or duplicate checks, incorrect application bindings, unsupported naming/conditional changes and deviations from the reviewed single-maintainer profile. They do not query GitHub or prove live enforcement.

Before application, review the exact policy and source commit, confirm current repository administration rights, inspect existing branch protection and repository rulesets, and verify that every mandatory check has succeeded for the current pull-request head. Update/retest the template if workflow job names or matrix dimensions change. A conflicting rule or a concurrent policy change requires another review; do not overwrite it blindly.

An authorized administrator can inspect current settings with GitHub CLI:

```sh
gh api repos/alebgl77/open-shadow-ai/branches/main
gh api repos/alebgl77/open-shadow-ai/branches/main/protection
gh api repos/alebgl77/open-shadow-ai/rulesets
```

A `404` for the protection endpoint must be interpreted alongside repository access and the branch/ruleset responses; it is not independently proof of an unprotected branch. After the reviewed preconditions hold, apply this exact request from the repository root:

```sh
gh api --method PUT repos/alebgl77/open-shadow-ai/branches/main/protection --input .github/main-protection.json
gh api repos/alebgl77/open-shadow-ai/branches/main/protection
gh api repos/alebgl77/open-shadow-ai/branches/main
```

Check the returned state rather than assuming a successful request installed every setting:

- `required_status_checks.strict` is `true`; its `checks` contains exactly the 32 distinct context/application pairs in the template. The request uses only `checks` and omits the deprecated `contexts` field; do not send both representations. GitHub may still populate `contexts` in its response.
- `enforce_admins.enabled` is `true`; the branch response reports `protected: true`.
- `required_pull_request_reviews` is non-null, with approval count `0`, stale-review dismissal enabled, code-owner review disabled and last-push approval disabled. No bypass users, teams or applications are present.
- Conversation resolution is enabled; force pushes and deletions are disabled. GitHub represents these response fields as objects containing `enabled` rather than the request's booleans.
- No push restrictions or unreviewed exceptions have appeared. Inspect any repository rulesets together with branch protection before declaring the effective policy verified.

Keep a dated, source-bound record of the reviewed request and bounded readback metadata. Do not include authentication tokens, raw CI logs or unrelated repository data. Recheck after workflow or governance changes. Repository administrators can later edit protection, so this configuration does not provide an immutable security boundary.

The API contract, including the valid zero-approval single-maintainer setting and application-bound checks, is documented in [GitHub's branch protection REST API](https://docs.github.com/en/rest/branches/branch-protection?apiVersion=2022-11-28#update-branch-protection).
