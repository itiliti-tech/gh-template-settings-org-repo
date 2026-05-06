# GitHub Organization Policy Template

Recommended baseline settings for any new GitHub organization

---

## 1. Security Defaults for New Repositories

These settings apply automatically to every repository created in the organization. Configure under **Organization Settings → Code security and analysis**.

| Setting                         | Recommended Value               | Rationale                                                                            |
| ------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------ |
| Dependabot alerts               | **Enabled**                     | Automatically alerts on known vulnerable dependencies in every new repo from day one |
| Dependabot security updates     | **Enabled**                     | Automatically opens PRs to remediate vulnerable dependencies without manual triage   |
| Dependency graph                | Enabled                         | Required for Dependabot to function                                                  |
| Secret scanning                 | **Recommended — see cost note** | Detects accidentally committed credentials across all repos                          |
| Secret scanning push protection | **Recommended — see cost note** | Blocks pushes containing detected secrets before they land in history                |
| Code scanning (CodeQL)          | **Recommended — see cost note** | Static analysis for vulnerable code patterns                                         |

> **Cost note — GitHub Advanced Security (GHAS):**  
> Secret scanning, secret scanning push protection, and CodeQL are **free for public repositories**.  
> For **private and internal repositories** these features require a **GitHub Advanced Security license**, billed per unique active committer per month (GitHub Enterprise Cloud). Evaluate cost against the number of active committers before enabling org-wide. Dependabot alerts and security updates are **free on all plans** including private repos.

---

## 2. Member Permissions

Configure under **Organization Settings → Member privileges**.

| Setting                                  | Recommended Value | Rationale                                                                    |
| ---------------------------------------- | ----------------- | ---------------------------------------------------------------------------- |
| Base permissions                         | Read              | Least-privilege default; explicit access granted per repo or team            |
| Members can create public repositories   | No                | Prevents accidental public exposure of internal code                         |
| Members can create private repositories  | Yes               | Allows self-service repo creation without admin bottleneck                   |
| Members can create internal repositories | No                | Internal repos have broader implicit access; admin oversight preferred       |
| Members can fork private repositories    | No                | Prevent code leaving the org via forks without approval                      |
| Members can invite outside collaborators | **No**            | Only org admins should add external users; prevents ungoverned access grants |
| Members can create teams                 | **No**            | Team management should be admin-controlled to maintain a clean access model  |

> **API note:** `members_can_invite_outside_collaborators` and `members_can_create_teams` are readable via `GET /orgs/{org}` but are **not writable** via `PATCH /orgs/{org}`. Configure these under **Organization Settings → Member privileges** in the GitHub UI.

---

## 3. Actions (CI/CD) Permissions

Configure under **Organization Settings → Actions → General**.

| Setting                              | Recommended Value                                       | Rationale                                                                            |
| ------------------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Actions enabled for                  | All repositories                                        | Enables CI/CD org-wide                                                               |
| Allowed actions                      | **GitHub-owned + select non-GitHub** (see detail below) | Scopes the action supply chain; prevents arbitrary third-party code execution        |
| SHA pinning required                 | **Yes** for non-GitHub actions                          | Pins third-party actions to a specific commit SHA; prevents mutable tag hijacking    |
| Fork pull request workflows          | Require approval for first-time contributors            | Prevents untrusted code execution from forks                                         |
| Workflow permissions (default token) | Read repository contents                                | Least-privilege GITHUB_TOKEN default; workflows must explicitly request write scopes |
| Allow GitHub Actions to create PRs   | No (opt-in per workflow)                                | Prevents unintended automated PR creation                                            |

### Allowed Actions — Detail

Set via **Organization Settings → Actions → General → Allowed actions and reusable workflows**. Select **"Allow GitHub Actions and reusable workflows created by GitHub"** and enable **"Allow actions created by Marketplace verified creators"** for a safe baseline, then extend with an explicit allowlist for any additional third-party actions required.

| Tier                                      | Examples                                                           | How to Allow                                                                                                       | SHA Pin?                                           |
| ----------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------- |
| **GitHub-owned (enterprise/first-party)** | `actions/checkout`, `actions/setup-python`, `github/codeql-action` | Included automatically when "GitHub-owned" is selected                                                             | Not required — GitHub controls these               |
| **Marketplace Verified Creators**         | `azure/webapps-deploy`, `aws-actions/configure-aws-credentials`    | Enable "Allow actions from Marketplace verified creators" — these publishers have been identity-verified by GitHub | Strongly recommended                               |
| **Unverified third-party (specific)**     | Any action outside the above                                       | Add explicit `owner/repo@SHA` pattern to the allowlist                                                             | **Required** — pin to a full commit SHA, not a tag |
| **Internal / reusable workflows**         | `.github/workflows/*.yml` within the org                           | Enabled automatically for same-org workflows                                                                       | N/A                                                |

> **Safe marketplace guidance:** "Marketplace Verified Creator" status means GitHub has verified the publisher's identity — it does **not** guarantee the action's code is free of vulnerabilities. Always review action source code, pin to a SHA, and monitor for new releases before unpinning.

---

## 4. Organization-Level Rulesets

Org rulesets enforce consistent governance across all repositories without requiring per-repo branch protection configuration. Two rulesets are recommended.

### 4.1 — Master Ruleset (Branch Protection)

**Purpose:** Protect default branches across all active repositories.

| Property        | Value                                                                         |
| --------------- | ----------------------------------------------------------------------------- |
| **Target**      | Branch                                                                        |
| **Applies to**  | Default branch (`~DEFAULT_BRANCH`)                                            |
| **Scope**       | All repositories except those with custom property `lifecycle = experimental` |
| **Enforcement** | Active                                                                        |

#### Rules

| Rule                              | Setting               | Notes                                                                                  |
| --------------------------------- | --------------------- | -------------------------------------------------------------------------------------- |
| **Deletion**                      | Blocked               | Default branch cannot be deleted                                                       |
| **Force push**                    | Blocked               | Non-fast-forward pushes disallowed; history is linear and auditable                    |
| **Required signatures**           | Required              | All commits must be GPG/SSH signed                                                     |
| **Pull request required**         | Yes                   | Direct pushes to default branch are disallowed                                         |
| — Required approving reviews      | **1**                 | Minimum peer review before merge                                                       |
| — Dismiss stale reviews on push   | No                    | Reviews persist unless explicitly dismissed                                            |
| — Require code owner review       | No                    | Code owner review not enforced (enable if CODEOWNERS files are maintained)             |
| — Require last-push approval      | No                    | Author's final push does not require a fresh approval                                  |
| — Require conversation resolution | No                    | Threads do not need to be resolved before merge (consider enabling for stricter teams) |
| — Allowed merge methods           | Merge, Squash, Rebase | All standard merge strategies permitted                                                |

#### Bypass Actors

| Actor               | Bypass Mode    | Notes                                                                                             |
| ------------------- | -------------- | ------------------------------------------------------------------------------------------------- |
| Organization Admins | `pull_request` | Admins may bypass via a PR only — **not** via direct push. Overrides still create an audit trail. |

> **No bypass exists for direct push** — even org admins must go through a PR to merge to the default branch.

---

### 4.2 — Tags Ruleset (Semantic Versioning Enforcement)

**Purpose:** Ensure all tags across all repositories follow Semantic Versioning (SemVer).

| Property        | Value                     |
| --------------- | ------------------------- |
| **Target**      | Tag                       |
| **Applies to**  | All tags (`~ALL`)         |
| **Scope**       | All repositories (`~ALL`) |
| **Enforcement** | Active                    |

#### Rules

| Rule                 | Setting        | Notes                                                                   |
| -------------------- | -------------- | ----------------------------------------------------------------------- |
| **Deletion**         | Blocked        | Tags are immutable once created                                         |
| **Force push**       | Blocked        | Tag targets cannot be moved                                             |
| **Tag name pattern** | Regex — SemVer | Tag names must match the SemVer 2.0.0 specification (see pattern below) |

#### Tag Name Pattern

```text
^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$
```

Valid examples: `1.0.0`, `2.3.1`, `1.0.0-alpha.1`, `1.0.0+build.42`  
Invalid examples: `v1.0.0` _(leading v)_, `latest`, `release-20260505`

#### Bypass Actors

None — **no bypasses**. Tag naming rules are universally enforced, including for org admins.

---

## 5. Repository Custom Properties

Define these properties at the org level. They must exist before the Master Ruleset references them.

### 5.1 — `lifecycle`

Indicates the current stage of the repository.

| Property              | Value         |
| --------------------- | ------------- |
| Type                  | Single select |
| Required              | Yes           |
| Default               | `active`      |
| Actor can set values  | No            |

| Value          | When to Use                                                         |
| -------------- | ------------------------------------------------------------------- |
| `active`       | Normal production or maintained repos — full org ruleset applies    |
| `experimental` | Proof-of-concept or exploratory repos — org branch ruleset excluded |
| `maintenance`  | Receiving fixes only; no new feature development                    |
| `deprecated`   | Functionally replaced; pending archival or deletion                 |
| `archived`     | Read-only, no active development                                    |

Repositories tagged `lifecycle = experimental` are excluded from the Master Ruleset, allowing faster iteration without governance overhead. All other repos receive full protection by default.

### 5.2 — `repo_type`

Identifies the primary role of the repository within the codebase.

| Property              | Value                  |
| --------------------- | ---------------------- |
| Type                  | Single select          |
| Required              | Yes                    |
| Default               | `unclassified`         |
| Actor can set values  | No                     |

| Value             | When to Use                                              |
| ----------------- | -------------------------------------------------------- |
| `unclassified`    | Default — not yet categorised                            |
| `service`         | A deployed service or API                                |
| `library`         | A reusable package or SDK                                |
| `integration`     | Connector, adapter, or third-party integration           |
| `infrastructure`  | IaC, platform config, cloud resources                    |
| `tooling`         | Internal developer tools, scripts, CI/CD infrastructure  |
| `assembly`        | Application that composes multiple components            |
| `configuration`   | Shared configuration or policy definitions               |
| `documentation`   | Repos whose primary output is documentation content      |
| `prototype`       | Experimental proof-of-concept, not production            |
| `example`         | Reference or sample code                                 |
| `archive`         | Preserved for reference; no active development           |

### 5.3 — `sensitivity`

Indicates the sensitivity of the repository's contents to guide access, sharing, and security controls.

| Property              | Value         |
| --------------------- | ------------- |
| Type                  | Single select |
| Required              | Yes           |
| Default               | `normal`      |
| Actor can set values  | No            |

| Value    | When to Use                                             |
| -------- | ------------------------------------------------------- |
| `low`    | Public or non-sensitive content                         |
| `normal` | Internal content with standard access controls          |
| `high`   | Sensitive data, secrets adjacent, or regulated content  |

---

## 6. Security Managers

Assign a **security manager team** to the organization. Security managers can manage security alerts and policies across all repositories without requiring org admin rights.

| Recommendation                      | Detail                                                    |
| ----------------------------------- | --------------------------------------------------------- |
| Create a team                       | e.g., `security-team` or `platform-security`              |
| Assign the team as Security Manager | Organization Settings → Code security → Security managers |
| Minimum team size                   | 2 members (avoid single point of failure)                 |

---

## 7. Authentication and Access Security

Configure under **Organization Settings → Authentication security** and **Organization Settings → Member privileges**.

### 7.1 Two-Factor Authentication

| Setting                           | Recommended Value | Notes                                                                                                |
| --------------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------- |
| Require two-factor authentication | **Yes**           | Members and outside collaborators who do not have 2FA enabled are removed from the org automatically |

> **API note:** 2FA enforcement is readable via `two_factor_requirement_enabled` in `GET /orgs/{org}` but **cannot be set via the REST API**. Enable under **Organization Settings → Authentication security**. The `github_policy_apply.py` script scans this field and flags non-compliance but will not attempt to patch it.
>
> This is the single most impactful authentication control available at the org level.

### 7.2 Commit Signoff and Identity

| Setting                                               | Recommended Value                     | Notes                                                                                           |
| ----------------------------------------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Require contributors to sign off on web-based commits | **Yes**                               | Adds a `Signed-off-by` trailer to commits made via the GitHub web UI, supporting DCO compliance |
| Require signed commits (GPG/SSH)                      | **Yes** — enforced via Master Ruleset | Cryptographically verifies commit author identity on the default branch                         |

### 7.3 Repository Management Controls

Restrict destructive repository operations to org admins only.

| Setting                                     | Recommended Value | Risk if Left Enabled                                                      |
| ------------------------------------------- | ----------------- | ------------------------------------------------------------------------- |
| Members can delete or transfer repositories | **No**            | Any member can permanently destroy a repository or move it out of the org |
| Members can change repository visibility    | **No**            | Any member can make a private repository public, exposing internal code   |
| Members can create public repositories      | No                | Accidental public exposure of internal code                               |
| Members can create public Pages sites       | No                | Accidental public exposure of internal content                            |

> **API note:** `members_can_delete_repositories` and `members_can_change_repo_visibility` appear in the `GET /orgs/{org}` response but are **not writable** via `PATCH /orgs/{org}` on any plan. Configure these under **Organization Settings → Member privileges** in the GitHub UI. The `github_policy_apply.py` script scans these fields and flags non-compliance but will not attempt to patch them.
>
> **Action:** Restricting these settings to admins-only closes a significant data-loss and exposure risk with no day-to-day workflow impact for most contributors.

### 7.4 Deploy Keys

| Setting                              | Recommended Value   | Notes                                                                                                               |
| ------------------------------------ | ------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Deploy keys enabled for repositories | Yes (with controls) | Deploy keys are useful for automated read-only access; restrict to read-only keys where possible and audit annually |

### 7.5 OAuth App and GitHub App Access

| Recommendation                       | Detail                                                                                |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| Enable OAuth app access restrictions | Requires members to request approval before authorizing OAuth apps to access org data |
| Review installed GitHub Apps         | Audit quarterly — remove apps that are no longer actively used                        |
| Limit app permissions                | Apps should be granted the minimum scopes required for their function                 |

---

## 8. Outside Collaborators

| Setting                              | Recommended Value                                                     |
| ------------------------------------ | --------------------------------------------------------------------- |
| Who can invite outside collaborators | Org admins only                                                       |
| Review cadence                       | Quarterly — audit outside collaborator access and remove stale grants |
| Preferred access pattern             | Grant repo-level access with an expiry date if the plan supports it   |

---

## Summary Checklist

Use this checklist when provisioning a new organization:

- [ ] Enable Dependabot alerts for new repositories
- [ ] Enable Dependabot security updates for new repositories
- [ ] Enable secret scanning for new repositories _(requires GHAS license for private repos — verify licensing before enabling)_
- [ ] Enable secret scanning push protection _(same GHAS requirement)_
- [ ] **Require two-factor authentication** for all members and outside collaborators
- [ ] Disable member ability to delete or transfer repositories
- [ ] Disable member ability to change repository visibility
- [ ] Enable web-based commit signoff requirement
- [ ] Enable OAuth app access restrictions
- [ ] Disable member ability to invite outside collaborators
- [ ] Disable member ability to create teams
- [ ] Disable member ability to create internal or public repositories
- [ ] Set allowed actions to: GitHub-owned + Marketplace verified creators + explicit allowlist
- [ ] Set default workflow token permissions to read-only
- [ ] Create org custom property: `lifecycle` (single select: active / experimental / archived / deprecated)
- [ ] Create **Master Ruleset** targeting `~DEFAULT_BRANCH`, excluding `lifecycle = experimental`
   - [ ] Block deletion
   - [ ] Block force push
   - [ ] Require pull request with 1 approving review
   - [ ] Require signed commits
   - [ ] Bypass: Org Admins via pull_request only
- [ ] Create **Tags Ruleset** targeting all tags in all repositories
   - [ ] Block deletion
   - [ ] Block force push
   - [ ] Enforce SemVer name pattern
   - [ ] No bypasses
- [ ] Assign a security manager team (minimum 2 members)
