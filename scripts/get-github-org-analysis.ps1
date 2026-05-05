<#
.SYNOPSIS
    Collects GitHub organization settings, rulesets, and repository settings for analysis.

.DESCRIPTION
    Fetches:
      - Organization settings for itiliti and itiliti-tech
      - Organization-level repository rulesets for both orgs
      - Full repository settings for itiliti/itio-opsgenie-autotask

    Outputs multiple JSON files to a timestamped subfolder for further analysis.

.PARAMETER Token
    GitHub Personal Access Token. If not provided, falls back to the GITHUB_TOKEN
    environment variable. The token needs these scopes:
      read:org, admin:org (for webhooks/billing), repo, security_events

.PARAMETER OutputPath
    Root directory for output files. Defaults to a 'github-analysis' folder next
    to this script. A timestamped subdirectory is created on each run.

.EXAMPLE
    .\Get-GitHubOrgAnalysis.ps1 -Token ghp_xxxxx

.EXAMPLE
    $env:GITHUB_TOKEN = 'ghp_xxxxx'
    .\Get-GitHubOrgAnalysis.ps1
#>
[CmdletBinding()]
param(
    [string]$Token = $env:GITHUB_TOKEN,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'github-analysis')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Token) {
    throw "A GitHub token is required. Pass -Token or set the GITHUB_TOKEN environment variable."
}

# ── Timestamped run directory ─────────────────────────────────────────────────
$runDir = Join-Path $OutputPath (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
Write-Host "Output directory: $runDir" -ForegroundColor Cyan

# ── HTTP headers ──────────────────────────────────────────────────────────────
$Headers = @{
    Authorization          = "Bearer $Token"
    Accept                 = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
}

# ── Helper: single GitHub API call ───────────────────────────────────────────
function Invoke-GHApi {
    param(
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Query = @{}
    )
    $uri = "https://api.github.com$Path"
    if ($Query.Count) {
        $qs = ($Query.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
        $uri = "$uri`?$qs"
    }
    try {
        return Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get -ErrorAction Stop
    } catch {
        $code = $null
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        if ($code -in 403, 404, 409, 410, 422, 451) {
            Write-Warning "  SKIP $Path  (HTTP $code)"
            return $null
        }
        Write-Warning "  ERROR $Path  $_"
        return $null
    }
}

# ── Helper: paginated list endpoint (returns an array) ───────────────────────
function Invoke-GHApiList {
    param(
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$ExtraQuery = @{}
    )
    $all = [System.Collections.Generic.List[object]]::new()
    $page = 1
    $batch = 100
    do {
        $q = @{ per_page = $batch; page = $page } + $ExtraQuery
        $resp = Invoke-GHApi -Path $Path -Query $q
        if ($null -eq $resp) { break }
        # Endpoints that wrap the array in an object (e.g. secrets, variables, runner-groups)
        # return a PSCustomObject; unwrap the first array-valued property.
        if ($resp -is [System.Management.Automation.PSCustomObject]) {
            $arrayProp = $resp.PSObject.Properties |
                Where-Object { $_.Value -is [System.Object[]] -or $_.Value -is [System.Collections.ArrayList] } |
                Select-Object -First 1
            if ($arrayProp) {
                $items = @($arrayProp.Value)
                $all.AddRange($items)
                if ($items.Count -lt $batch) { break }
            } else { $all.Add($resp); break }   # single-object response
        } elseif ($resp -is [System.Object[]]) {
            $all.AddRange([object[]]$resp)
            if ($resp.Count -lt $batch) { break }
        } else { $all.Add($resp); break }
        $page++
    } while ($true)
    return $all.ToArray()
}

# ── Helper: save a hashtable as formatted JSON ───────────────────────────────
function Save-Json {
    param(
        [Parameter(Mandatory)][object]$Data,
        [Parameter(Mandatory)][string]$FileName
    )
    $path = Join-Path $runDir $FileName
    $Data | ConvertTo-Json -Depth 20 | Set-Content -Path $path -Encoding UTF8
    $kb = [math]::Round((Get-Item $path).Length / 1KB, 1)
    Write-Host "  Saved: $FileName  ($kb KB)" -ForegroundColor Green
    return $path
}

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 – Organization Settings
# ═════════════════════════════════════════════════════════════════════════════
function Get-OrgSettings {
    param([string]$Org)

    Write-Host "`n━━ Organization settings: $Org" -ForegroundColor Yellow

    $out = [ordered]@{
        _metadata = [ordered]@{
            type         = 'org-settings'
            organization = $Org
            fetched_at   = (Get-Date -Format 'o')
        }
    }

    Write-Host "  organization details"
    $out.organization = Invoke-GHApi "/orgs/$Org"

    Write-Host "  members"
    $out.members = Invoke-GHApiList "/orgs/$Org/members" -ExtraQuery @{ filter = 'all' }

    Write-Host "  outside collaborators"
    $out.outside_collaborators = Invoke-GHApiList "/orgs/$Org/outside_collaborators"

    Write-Host "  teams"
    $teams = Invoke-GHApiList "/orgs/$Org/teams"
    $out.teams = $teams

    # Per-team: members and repos
    Write-Host "  team members and repos"
    $teamDetails = [ordered]@{}
    foreach ($team in $teams) {
        $slug = $team.slug
        $teamDetails[$slug] = [ordered]@{
            members = Invoke-GHApiList "/orgs/$Org/teams/$slug/members"
            repos   = Invoke-GHApiList "/orgs/$Org/teams/$slug/repos"
        }
    }
    $out.team_details = $teamDetails

    Write-Host "  repositories (all)"
    $out.repositories = Invoke-GHApiList "/orgs/$Org/repos" -ExtraQuery @{ type = 'all'; sort = 'full_name' }

    Write-Host "  org webhooks"
    $out.webhooks = Invoke-GHApiList "/orgs/$Org/hooks"

    Write-Host "  actions permissions"
    $out.actions_permissions = Invoke-GHApi "/orgs/$Org/actions/permissions"

    Write-Host "  actions allowed actions"
    $out.actions_allowed = Invoke-GHApi "/orgs/$Org/actions/permissions/selected-actions"

    Write-Host "  actions secrets (names only)"
    $out.actions_secrets = Invoke-GHApiList "/orgs/$Org/actions/secrets"

    Write-Host "  actions variables"
    $out.actions_variables = Invoke-GHApiList "/orgs/$Org/actions/variables"

    Write-Host "  runner groups"
    $out.runner_groups = Invoke-GHApiList "/orgs/$Org/actions/runner-groups"

    Write-Host "  Dependabot secrets (names only)"
    $out.dependabot_secrets = Invoke-GHApiList "/orgs/$Org/dependabot/secrets"

    Write-Host "  Codespaces secrets (names only)"
    $out.codespaces_secrets = Invoke-GHApiList "/orgs/$Org/codespaces/secrets"

    Write-Host "  security managers"
    $out.security_managers = Invoke-GHApi "/orgs/$Org/security-managers"

    Write-Host "  custom org roles"
    $out.custom_roles = Invoke-GHApi "/orgs/$Org/organization-roles"

    Write-Host "  audit log (last 100 events)"
    $out.audit_log_recent = Invoke-GHApi "/orgs/$Org/audit-log" -Query @{ per_page = 100 }

    return $out
}

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 – Organization Rulesets
# ═════════════════════════════════════════════════════════════════════════════
function Get-OrgRulesets {
    param([string]$Org)

    Write-Host "`n━━ Organization rulesets: $Org" -ForegroundColor Yellow

    $out = [ordered]@{
        _metadata = [ordered]@{
            type         = 'org-rulesets'
            organization = $Org
            fetched_at   = (Get-Date -Format 'o')
        }
    }

    $list = @(Invoke-GHApiList "/orgs/$Org/rulesets")
    Write-Host "  found $($list.Count) ruleset(s)"

    $detailed = foreach ($rs in $list) {
        Write-Host "    ruleset: '$($rs.name)' (id $($rs.id))"
        Invoke-GHApi "/orgs/$Org/rulesets/$($rs.id)"
    }
    $out.rulesets = @($detailed | Where-Object { $_ })
    $out.ruleset_count = $out.rulesets.Count

    return $out
}

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 – Repository Settings
# ═════════════════════════════════════════════════════════════════════════════
function Get-RepoSettings {
    param(
        [string]$Owner,
        [string]$Repo
    )

    $full = "$Owner/$Repo"
    Write-Host "`n━━ Repository settings: $full" -ForegroundColor Yellow

    $out = [ordered]@{
        _metadata = [ordered]@{
            type       = 'repo-settings'
            repository = $full
            fetched_at = (Get-Date -Format 'o')
        }
    }

    Write-Host "  repository details"
    $out.repository = Invoke-GHApi "/repos/$full"

    Write-Host "  topics"
    $out.topics = Invoke-GHApi "/repos/$full/topics"

    Write-Host "  branches"
    $branches = Invoke-GHApiList "/repos/$full/branches"
    $out.branches = $branches

    Write-Host "  branch protection rules"
    $bp = [ordered]@{}
    foreach ($b in $branches) {
        $protection = Invoke-GHApi "/repos/$full/branches/$($b.name)/protection"
        if ($protection) { $bp[$b.name] = $protection }
    }
    $out.branch_protection = $bp

    Write-Host "  repository rulesets"
    $rsList = @(Invoke-GHApiList "/repos/$full/rulesets")
    $rsDetailed = foreach ($rs in $rsList) {
        Write-Host "    ruleset: '$($rs.name)' (id $($rs.id))"
        Invoke-GHApi "/repos/$full/rulesets/$($rs.id)"
    }
    $out.rulesets = @($rsDetailed | Where-Object { $_ })

    Write-Host "  collaborators (direct)"
    $out.collaborators = Invoke-GHApiList "/repos/$full/collaborators" -ExtraQuery @{ affiliation = 'direct' }

    Write-Host "  deploy keys"
    $out.deploy_keys = Invoke-GHApiList "/repos/$full/keys"

    Write-Host "  autolinks"
    $out.autolinks = Invoke-GHApiList "/repos/$full/autolinks"

    Write-Host "  labels"
    $out.labels = Invoke-GHApiList "/repos/$full/labels"

    Write-Host "  webhooks"
    $out.webhooks = Invoke-GHApiList "/repos/$full/hooks"

    Write-Host "  actions permissions"
    $out.actions_permissions = Invoke-GHApi "/repos/$full/actions/permissions"

    Write-Host "  actions allowed actions"
    $out.actions_allowed = Invoke-GHApi "/repos/$full/actions/permissions/selected-actions"

    Write-Host "  actions secrets (names only)"
    $out.actions_secrets = Invoke-GHApiList "/repos/$full/actions/secrets"

    Write-Host "  actions variables"
    $out.actions_variables = Invoke-GHApiList "/repos/$full/actions/variables"

    Write-Host "  workflows"
    $out.workflows = Invoke-GHApiList "/repos/$full/actions/workflows"

    Write-Host "  environments"
    $envResp = Invoke-GHApi "/repos/$full/environments"
    $out.environments = $envResp

    $envDetails = [ordered]@{}
    if ($envResp -and $envResp.environments) {
        foreach ($env in $envResp.environments) {
            $envName = $env.name
            Write-Host "    environment: $envName"
            $envDetails[$envName] = [ordered]@{
                details            = $env
                protection_rules   = $env.protection_rules
                deployment_secrets = Invoke-GHApiList "/repos/$full/environments/$envName/secrets"
                deployment_vars    = Invoke-GHApiList "/repos/$full/environments/$envName/variables"
            }
        }
    }
    $out.environment_details = $envDetails

    Write-Host "  pages"
    $out.pages = Invoke-GHApi "/repos/$full/pages"

    Write-Host "  Dependabot secrets (names only)"
    $out.dependabot_secrets = Invoke-GHApiList "/repos/$full/dependabot/secrets"

    Write-Host "  Dependabot alerts (open, up to 100)"
    # Dependabot alerts uses cursor-based pagination; fetch a single page of 100
    $out.dependabot_alerts_open = Invoke-GHApi "/repos/$full/dependabot/alerts" `
        -Query @{ state = 'open'; per_page = 100 }

    Write-Host "  code scanning default setup"
    $out.code_scanning_default_setup = Invoke-GHApi "/repos/$full/code-scanning/default-setup"

    Write-Host "  code scanning analyses (latest 10)"
    $out.code_scanning_analyses = Invoke-GHApi "/repos/$full/code-scanning/analyses" `
        -Query @{ per_page = 10 }

    Write-Host "  secret scanning alerts (open)"
    $out.secret_scanning_alerts_open = Invoke-GHApiList "/repos/$full/secret-scanning/alerts" `
        -ExtraQuery @{ state = 'open' }

    Write-Host "  security and analysis settings"
    # Already embedded in repository details; surface explicitly for clarity
    if ($out.repository) {
        $out.security_and_analysis = $out.repository.security_and_analysis
    }

    Write-Host "  workflows (latest 20 runs)"
    $out.recent_workflow_runs = Invoke-GHApi "/repos/$full/actions/runs" -Query @{ per_page = 20 }

    return $out
}

# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

$orgs = @('itiliti', 'itiliti-tech')
$files = [ordered]@{}

# 1. Org settings
foreach ($org in $orgs) {
    $data = Get-OrgSettings -Org $org
    $files["org-settings-$org.json"] = Save-Json -Data $data -FileName "org-settings-$org.json"
}

# 2. Org rulesets
foreach ($org in $orgs) {
    $data = Get-OrgRulesets -Org $org
    $files["org-rulesets-$org.json"] = Save-Json -Data $data -FileName "org-rulesets-$org.json"
}

# 3. Repository settings
$repoData = Get-RepoSettings -Owner 'itiliti' -Repo 'itio-opsgenie-autotask'
$files['repo-settings-itio-opsgenie-autotask.json'] = Save-Json -Data $repoData `
    -FileName 'repo-settings-itio-opsgenie-autotask.json'

# 4. Summary manifest
$summary = [ordered]@{
    run_at           = (Get-Date -Format 'o')
    output_directory = $runDir
    organizations    = $orgs
    repository       = 'itiliti/itio-opsgenie-autotask'
    files_created    = @(
        $files.Keys | ForEach-Object {
            [ordered]@{
                file    = $_
                path    = $files[$_]
                size_kb = [math]::Round((Get-Item $files[$_]).Length / 1KB, 1)
            }
        }
    )
}
Save-Json -Data $summary -FileName '_summary.json' | Out-Null

Write-Host "`n✓ Done. All files written to: $runDir" -ForegroundColor Cyan
Write-Host "  Run the following to inspect:" -ForegroundColor DarkGray
Write-Host "    Get-Content '$runDir\_summary.json' | ConvertFrom-Json" -ForegroundColor DarkGray
