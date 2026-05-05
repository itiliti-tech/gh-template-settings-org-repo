# Repository Policy Template

**Recommended settings for any new repository under a compliant organization**  
Companion to: [org-policy-template.md](org-policy-template.md)

This document is organized into three tiers:

| Tier                       | Meaning                                                                |
| -------------------------- | ---------------------------------------------------------------------- |
| **Inherited**              | Set by the org policy template — no action needed at the repo level    |
| **Required (repo)**        | Must be configured on every repository at creation time                |
| **Optional / Conditional** | Configure based on the repository's purpose, risk level, or tech stack |

---

## 1. Settings Inherited from the Organization

These are covered by the org policy template and require no per-repository action. They are documented here so repository owners understand what governance is already in place.

### 1.1 Branch Protection (Default Branch)

Enforced by the **Master Ruleset** (org-level, active on all repos except `lifecycle = experimental`).

| Protection                         | Value                 | Notes                                                  |
| ---------------------------------- | --------------------- | ------------------------------------------------------ |
| Pull request required before merge | Yes                   | Direct push to default branch blocked                  |
| Required approving reviews         | 1                     | Minimum peer review                                    |
| Dismiss stale reviews on push      | No                    | Approvals persist across new commits                   |
| Require code owner review          | No                    | —                                                      |
| Require last-push approval         | No                    | —                                                      |
| Require conversation resolution    | No                    | —                                                      |
| Allowed merge methods              | Merge, Squash, Rebase | All standard strategies                                |
| Signed commits required            | Yes                   | GPG/SSH signing enforced                               |
| Force push to default branch       | Blocked               | —                                                      |
| Deletion of default branch         | Blocked               | —                                                      |
| Admin bypass                       | PR only               | Org admins must still open a PR; no direct push bypass |

> Repos tagged `lifecycle = experimental` are **excluded** from this ruleset and have no inherited branch protection. Experimental repos must either accept that risk explicitly or configure their own protection rules.

### 1.2 Tag Enforcement

Enforced by the **Tags Ruleset** (org-level, applies to all tags in all repositories, no exceptions).

| Protection                   | Value                                             |
| ---------------------------- | ------------------------------------------------- |
| Tag deletion                 | Blocked                                           |
| Tag force-push (retargeting) | Blocked                                           |
| Tag name pattern             | SemVer 2.0.0 required                             |
| Bypass                       | None — applies to all actors including org admins |

Valid tag formats: `1.0.0`, `2.3.1`, `1.0.0-alpha.1`, `1.0.0+build.42`

### 1.3 Actions (CI/CD)

| Setting                          | Inherited Value                                              |
| -------------------------------- | ------------------------------------------------------------ |
| Actions enabled                  | Yes — all repositories                                       |
| Allowed actions                  | GitHub-owned + Marketplace verified creators + org allowlist |
| SHA pinning required             | Yes — enforced for non-GitHub actions                        |
| Default GITHUB_TOKEN permissions | Read-only (repo contents)                                    |
| Actions can create PRs           | No (must be opted in per workflow)                           |

> Any action outside the GitHub-owned or Marketplace-verified-creator tiers must be added to the org allowlist as an explicit `owner/repo@SHA` pattern before it can be used in a workflow. Workflows using an action not on the allowlist will fail at runtime.

### 1.4 Dependabot

| Setting                                  | Inherited Value |
| ---------------------------------------- | --------------- |
| Dependabot alerts on new repos           | Enabled         |
| Dependabot security updates on new repos | Enabled         |

---

## 2. Required Repository Settings

These must be configured on every repository at creation time. They are not inherited from the org.

### 2.1 Repository Custom Property — `lifecycle`

Every repository must have the `lifecycle` property set. This controls whether the Master Ruleset applies.

| Value                | When to Use                                                         |
| -------------------- | ------------------------------------------------------------------- |
| `active` _(default)_ | Normal production or maintained repos — full org ruleset applies    |
| `experimental`       | Proof-of-concept or exploratory repos — org branch ruleset excluded |
| `archived`           | Read-only, no active development                                    |
| `deprecated`         | Functionally replaced; pending archival or deletion                 |

> **Action:** Set via **Repository Settings → Custom properties** after creation.

### 2.2 General Settings

| Setting             | Required Value         | Notes                                           |
| ------------------- | ---------------------- | ----------------------------------------------- |
| Visibility          | Private (default)      | Use public only with explicit approval          |
| Default branch name | `main`                 | Consistent across all repositories              |
| Fork allowed        | No                     | Set to Yes only for open-source repos           |
| Wiki                | Disabled               | Use the repo's README or a docs site            |
| Discussions         | Disabled unless needed | Enable only if the repo has an active community |

### 2.3 Merge Settings

| Setting                | Required Value | Notes                                                          |
| ---------------------- | -------------- | -------------------------------------------------------------- |
| Merge commits          | Enabled        | —                                                              |
| Squash merge           | Enabled        | —                                                              |
| Rebase merge           | Enabled        | —                                                              |
| Auto-merge             | **Enabled**    | Allows PRs to merge automatically once all checks pass         |
| Delete branch on merge | **Enabled**    | Keeps the repository clean; prevents stale branch accumulation |
| Allow branch updates   | Optional       | Enable to allow maintainers to keep PR branches current        |

### 2.4 Security and Analysis

These are not fully covered by org defaults and must be verified/configured per repository.

> **Cost note — GitHub Advanced Security (GHAS):**  
> Secret scanning, push protection, and CodeQL are **free for public repositories**.  
> For **private and internal repositories** all three require a **GHAS license**, billed per unique active committer. Dependabot alerts and security updates are **free on all plans**. Confirm GHAS licensing with your GitHub account team before enabling on private repos.

| Setting                             | Required Value        | Notes                                                                                                           |
| ----------------------------------- | --------------------- | --------------------------------------------------------------------------------------------------------------- |
| Dependabot alerts                   | Enabled               | Org default — verify it is on, especially for repos created before the org default was set. **Free.**           |
| Dependabot security updates         | Enabled               | Org default — verify. **Free.**                                                                                 |
| **Secret scanning**                 | **Recommended**       | **Not inherited — must be enabled per repo. Free for public repos. Requires GHAS for private repos.**           |
| **Secret scanning push protection** | **Recommended**       | **Blocks commits containing detected secrets. Free for public repos. Requires GHAS for private repos.**         |
| Code security (GHAS)                | Enabled (if licensed) | Required to unlock secret scanning and CodeQL on private repos. **Billed per active committer — confirm cost.** |

### 2.5 Code Scanning

> **Cost note:** CodeQL is free for public repositories. For private/internal repos it requires a GHAS license (same per-committer billing as secret scanning above). The `actions` language scanner (used to scan workflow files) is free regardless of visibility.

| Setting              | Required Value         | Notes                                                                     |
| -------------------- | ---------------------- | ------------------------------------------------------------------------- |
| CodeQL default setup | **Recommended**        | Configure under Security → Code scanning. **Free for public repos only.** |
| Languages            | Auto-detect or specify | At minimum include the repo's primary language and `actions`              |
| Query suite          | Default                | Upgrade to `extended` for higher-risk repositories                        |
| Schedule             | Weekly                 | —                                                                         |

---

## 3. Conditional / Optional Settings

Configure these based on the repository's purpose.

### 3.1 Environments

Required for any repository that deploys to a named target (staging, production, a named platform, etc.).

| Setting               | Recommended Value                                         | Notes                                                |
| --------------------- | --------------------------------------------------------- | ---------------------------------------------------- |
| Required reviewers    | 1+ for production environments                            | Prevents automated deployment without human approval |
| Wait timer            | Optional (e.g., 5 min)                                    | Provides a window to cancel an accidental trigger    |
| Deployment branches   | Restrict to `main` for production                         | Prevents unintended branch deploys                   |
| Environment secrets   | Store target-specific credentials here, not at repo level | Scoped to the environment only                       |
| Environment variables | Store target-specific config here                         | —                                                    |

> **Gap:** Environments with no protection rules (no required reviewers, no wait timer, no branch restrictions) provide no deployment governance. Any workflow can deploy to any environment without approval.

**Minimum configuration per environment type:**

| Environment Type                          | Required Reviewers | Branch Restriction | Wait Timer |
| ----------------------------------------- | ------------------ | ------------------ | ---------- |
| Development / sandbox                     | 0                  | None               | None       |
| Staging / QA                              | 0                  | `main` only        | None       |
| Production                                | **1**              | `main` only        | Optional   |
| External platform (e.g., API integration) | 1                  | `main` only        | None       |

### 3.2 Branch Strategy for Feature Branches

The org Master Ruleset only protects the **default branch**. Feature branches have no inherited protection.

| Recommendation      | Detail                                                                                                                 |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Naming convention   | Use prefixed names: `feat/`, `fix/`, `chore/`, `wa/`, `copilot/`                                                       |
| Stale branch policy | Delete merged branches automatically (enabled via merge settings above)                                                |
| Long-lived branches | If additional protected branches are needed (e.g., `release/*`), configure repo-level branch protection rules manually |

### 3.3 Actions Secrets

| Recommendation                                 | Detail                                                                                                  |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Scope secrets to environment where possible    | Use environment secrets rather than repo-level secrets for deployment credentials                       |
| Rotation cadence                               | Review and rotate secrets at least annually; rotate immediately on suspected exposure                   |
| Naming convention                              | Use descriptive names identifying the target system and purpose (e.g., `AZURE_FUNCTION_PROD_CLIENT_ID`) |
| Never store at repo level if org-level will do | If the same secret is needed across many repos, define it at the org level                              |

### 3.4 Webhooks

| Recommendation              | Detail                                                            |
| --------------------------- | ----------------------------------------------------------------- |
| Use a secret                | Always configure a webhook secret to validate payloads            |
| TLS only                    | `insecure_ssl` must be `0`                                        |
| Subscribe to minimum events | Only subscribe to events the consuming service actually processes |
| Audit annually              | Remove webhooks for decommissioned integrations                   |

### 3.5 Topics

Add topics to all repositories for discoverability and governance filtering.

| Recommended Topics                             | When                                               |
| ---------------------------------------------- | -------------------------------------------------- |
| `python`, `typescript`, `go`, etc.             | Language of the primary codebase                   |
| `azure-functions`, `docker`, `terraform`, etc. | Primary deployment platform                        |
| `internal`, `open-source`                      | Visibility intent                                  |
| `deprecated`                                   | When lifecycle = deprecated (mirrors the property) |

### 3.6 CODEOWNERS

Create a `CODEOWNERS` file in `.github/` for repositories with defined ownership areas. This allows the org Master Ruleset to optionally enforce code owner review in the future without requiring a ruleset change.

```text
# .github/CODEOWNERS
# Default owners for all files
* @org/team-name

# Specific path overrides
/src/auth/  @org/security-team
```

---

## 4. Settings NOT Covered by the Org Policy (Gaps)

These are the settings that **will not be configured or inherited** even in a fully compliant org. They require deliberate action on each repository.

| Gap                                           | Impact                                                                     | Required Action                                                                                                       |
| --------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **Secret scanning**                           | Credentials committed to the repo will not be detected                     | Enable per-repo under Security → Secret scanning. **Free for public repos; GHAS license required for private repos.** |
| **Secret scanning push protection**           | Secrets can be pushed without being blocked                                | Enable alongside secret scanning. **Same GHAS cost.**                                                                 |
| **Code scanning (CodeQL)**                    | Vulnerable code patterns not detected                                      | Configure CodeQL default setup. **Free for public repos; GHAS license required for private repos.**                   |
| **Environment protection rules**              | Deployments can run without human approval                                 | Add required reviewers to staging/production environments                                                             |
| **`lifecycle` property**                      | Without it set, a repo may unexpectedly inherit or miss the Master Ruleset | Set immediately after repository creation                                                                             |
| **Tag ruleset has no exceptions**             | All tags in all repos must be SemVer — there is no opt-out                 | Pre-plan tagging strategy before creating the first tag                                                               |
| **Branch protection on non-default branches** | Feature/release branches have no protection                                | Configure manually if long-lived protected branches are needed                                                        |
| **Secret rotation**                           | Stale secrets increase blast radius if exposed                             | Establish and enforce a rotation schedule                                                                             |
| **Webhook secrets**                           | Unsigned webhook payloads can be spoofed                                   | Always set a webhook secret at creation time                                                                          |

---

## 5. Repository Creation Checklist

Use this checklist when creating a new repository under a compliant organization.

### Immediate (at creation)

- [ ] Set `lifecycle` custom property (`active`, `experimental`, `archived`, or `deprecated`)
- [ ] Set visibility to `private` (or document the reason for `public`)
- [ ] Set default branch to `main`
- [ ] Disable Wiki
- [ ] Enable auto-merge
- [ ] Enable delete branch on merge
- [ ] If **public repo** or GHAS licensed: Enable secret scanning
- [ ] If **public repo** or GHAS licensed: Enable secret scanning push protection
- [ ] If **public repo** or GHAS licensed: Configure CodeQL default setup (Security → Code scanning)
- [ ] If **private repo without GHAS**: Verify Dependabot alerts are active (free on all plans)

### Within first sprint

- [ ] Configure environments with appropriate protection rules
   - [ ] Production: 1+ required reviewer, branch restricted to `main`
   - [ ] Staging: branch restricted to `main`
- [ ] Move deployment credentials to environment secrets (not repo-level)
- [ ] Add topics
- [ ] Create `.github/CODEOWNERS` if the repo has defined ownership areas
- [ ] Verify Dependabot alerts and security updates are active (inherit from org default)

### Ongoing

- [ ] Review and rotate secrets annually (or on personnel change)
- [ ] Audit outside collaborator access quarterly
- [ ] Remove stale feature branches
- [ ] Remove webhooks for decommissioned integrations
- [ ] Update `lifecycle` property when the repository status changes
