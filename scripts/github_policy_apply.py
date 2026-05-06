# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests>=2.31",
# ]
# ///
"""
github_policy_apply.py - Idempotent GitHub Organization & Repository Policy Configurator

Scans current GitHub settings, compares against the recommended policy baseline
(org-policy-template.md), shows a diff of proposed changes, prompts for approval,
and applies changes idempotently via the GitHub REST API.

Usage:
    # Interactive scan + apply (org only):
    uv run scripts/github_policy_apply.py --org ORG_NAME

    # Org + specific repo:
    uv run scripts/github_policy_apply.py --org ORG_NAME --repo REPO_NAME

    # Export proposed changes to JSON for manual editing, then apply:
    uv run scripts/github_policy_apply.py --org ORG_NAME --export proposed.json
    uv run scripts/github_policy_apply.py --org ORG_NAME --settings-file proposed.json

    # Dry run (scan only, no changes):
    uv run scripts/github_policy_apply.py --org ORG_NAME --dry-run

    # Non-interactive (auto-approve all pending changes):
    uv run scripts/github_policy_apply.py --org ORG_NAME --yes

    # Set allowed_actions mode (all / none / selected; prompted interactively if omitted):
    uv run scripts/github_policy_apply.py --org ORG_NAME --allowed-actions selected

Token (required scopes: admin:org, repo):
    Set GITHUB_TOKEN env var  OR  pass --token ghp_...
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from datetime import datetime, timezone
from typing import Any

import requests


# ─────────────────────────────────────────────────────────────────────────────
# Policy Baseline  (org-policy-template.md)
# ─────────────────────────────────────────────────────────────────────────────

TEMPLATE_VERSION = "org-policy-template.md"

SEMVER_PATTERN = (
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))"
    r"?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

# Settings patchable via  PATCH /orgs/{org}
# "ghas_required": True flags settings that need a GitHub Advanced Security license
#   for private/internal repos — the script warns but does not skip automatically.
ORG_PATCH_SETTINGS: dict[str, dict[str, Any]] = {
    # ── Security defaults for new repos ──────────────────────────────────────
    "dependabot_alerts_enabled_for_new_repositories": {
        "desired": True,
        "section": "Security Defaults",
        "label": "Dependabot alerts for new repos",
        "note": "Free on all plans",
    },
    "dependabot_security_updates_enabled_for_new_repositories": {
        "desired": True,
        "section": "Security Defaults",
        "label": "Dependabot security updates for new repos",
        "note": "Free on all plans",
    },
    "dependency_graph_enabled_for_new_repositories": {
        "desired": True,
        "section": "Security Defaults",
        "label": "Dependency graph for new repos",
        "note": "Required for Dependabot to function",
    },
    "secret_scanning_enabled_for_new_repositories": {
        "desired": True,
        "section": "Security Defaults",
        "label": "Secret scanning for new repos",
        "note": "GHAS license required for private repos — verify licensing before enabling",
        "ghas_required": True,
    },
    "secret_scanning_push_protection_enabled_for_new_repositories": {
        "desired": True,
        "section": "Security Defaults",
        "label": "Secret scanning push protection for new repos",
        "note": "GHAS license required for private repos",
        "ghas_required": True,
    },
    # ── Member permissions ────────────────────────────────────────────────────
    "default_repository_permission": {
        "desired": "read",
        "section": "Member Permissions",
        "label": "Base permissions for members",
        "note": "Least-privilege default; explicit access granted per repo or team",
    },
    "members_can_create_public_repositories": {
        "desired": False,
        "section": "Member Permissions",
        "label": "Members can create public repos",
        "note": "Prevents accidental public exposure of internal code",
    },
    "members_can_create_private_repositories": {
        "desired": True,
        "section": "Member Permissions",
        "label": "Members can create private repos",
        "note": "Allows self-service without admin bottleneck",
    },
    "members_can_create_internal_repositories": {
        "desired": False,
        "section": "Member Permissions",
        "label": "Members can create internal repos",
        "note": "Admin oversight preferred; internal repos have broad implicit access",
    },
    "members_can_fork_private_repositories": {
        "desired": False,
        "section": "Member Permissions",
        "label": "Members can fork private repos",
        "note": "Prevent code leaving org via forks without approval",
    },
    # ── Authentication & access ───────────────────────────────────────────────
    "web_commit_signoff_required": {
        "desired": True,
        "section": "Auth & Access",
        "label": "Require web-based commit signoff",
        "note": "Adds Signed-off-by trailer to web UI commits (DCO compliance)",
    },
}

# Settings that appear in GET /orgs/{org} but are silently ignored by
# PATCH /orgs/{org} — must be configured manually in the GitHub UI.
# The script scans and reports on these but does NOT attempt to apply them.
ORG_MANUAL_SETTINGS: dict[str, dict[str, Any]] = {
    # ── Member Permissions (UI-only) ─────────────────────────────────────────
    "members_can_invite_outside_collaborators": {
        "desired": False,
        "section": "Member Permissions",
        "label": "Members can invite outside collaborators",
        "note": "Org Settings → Member privileges — cannot be set via REST API",
    },
    "members_can_create_teams": {
        "desired": False,
        "section": "Member Permissions",
        "label": "Members can create teams",
        "note": "Org Settings → Member privileges — cannot be set via REST API",
    },
    # ── Auth & Access (UI-only) ──────────────────────────────────────────────
    "two_factor_requirement_enabled": {
        "desired": True,
        "section": "Auth & Access",
        "label": "Require two-factor authentication",
        "note": "Org Settings → Authentication security — cannot be set via REST API",
    },
    "members_can_delete_repositories": {
        "desired": False,
        "section": "Auth & Access",
        "label": "Members can delete repos",
        "note": "Org Settings → Member privileges — cannot be set via REST API",
    },
    "members_can_change_repo_visibility": {
        "desired": False,
        "section": "Auth & Access",
        "label": "Members can change repo visibility",
        "note": "Org Settings → Member privileges — cannot be set via REST API",
    },
}

# Settings for  PATCH /orgs/{org}/actions/permissions
ACTIONS_PERMISSION_SETTINGS: dict[str, Any] = {
    "enabled_repositories": "all",
    "allowed_actions": "selected",
}

# Settings for  PUT /orgs/{org}/actions/permissions/selected-actions
# (only meaningful when allowed_actions = "selected")
ACTIONS_SELECTED_SETTINGS: dict[str, Any] = {
    "github_owned_allowed": True,
    "verified_allowed": True,
    "patterns_allowed": [],
}

# Settings for  PUT /orgs/{org}/actions/permissions/workflow
WORKFLOW_PERMISSION_SETTINGS: dict[str, Any] = {
    "default_workflow_permissions": "read",
    "can_approve_pull_request_reviews": False,
}

# Custom property definitions.
LIFECYCLE_PROPERTY: dict[str, Any] = {
    "property_name": "lifecycle",
    "value_type": "single_select",
    "required": True,
    "description": "Indicates the current stage of the repository, such as active, experimental, or archived.",
    "allowed_values": ["active", "experimental", "maintenance", "deprecated", "archived"],
    "default_value": "active",
}

REPO_TYPE_PROPERTY: dict[str, Any] = {
    "property_name": "repo_type",
    "value_type": "single_select",
    "required": True,
    "description": "Identifies the primary role of the repository within the codebase.",
    "allowed_values": [
        "service", "library", "integration", "infrastructure",
        "tooling", "assembly", "configuration", "documentation",
        "prototype", "example", "archive", "unclassified",
    ],
    "default_value": "unclassified",
}

SENSITIVITY_PROPERTY: dict[str, Any] = {
    "property_name": "sensitivity",
    "value_type": "single_select",
    "required": True,
    "description": "Indicates the sensitivity of the repository's contents to guide access, sharing, and security controls.",
    "allowed_values": ["low", "normal", "high"],
    "default_value": "normal",
}

# Master Ruleset — branch protection for all default branches
MASTER_RULESET: dict[str, Any] = {
    "name": "Master Ruleset",
    "target": "branch",
    "enforcement": "active",
    "conditions": {
        "ref_name": {
            "include": ["~DEFAULT_BRANCH"],
            "exclude": [],
        },
        "repository_property": {
            "include": [],
            "exclude": [
                {
                    "name": "lifecycle",
                    "source": "custom",
                    "property_values": ["experimental"],
                }
            ],
        },
    },
    "rules": [
        {"type": "deletion"},
        {"type": "non_fast_forward"},
        {
            "type": "pull_request",
            "parameters": {
                "required_approving_review_count": 1,
                "dismiss_stale_reviews_on_push": False,
                "require_code_owner_review": False,
                "require_last_push_approval": False,
                "required_review_thread_resolution": False,
                "allowed_merge_methods": ["merge", "squash", "rebase"],
            },
        },
        {"type": "required_signatures"},
    ],
    "bypass_actors": [
        {
            # GitHub requires actor_id=1 for OrganizationAdmin (placeholder value).
            # The API rejects null even though GET responses may return null.
            "actor_id": 1,
            "actor_type": "OrganizationAdmin",
            "bypass_mode": "pull_request",
        }
    ],
}

# Tags Ruleset — SemVer enforcement across all repos
TAGS_RULESET: dict[str, Any] = {
    "name": "Tags",
    "target": "tag",
    "enforcement": "active",
    "conditions": {
        "ref_name": {
            "include": ["~ALL"],
            "exclude": [],
        },
        "repository_name": {
            "include": ["~ALL"],
            "exclude": [],
        },
    },
    "rules": [
        {"type": "deletion"},
        {"type": "non_fast_forward"},
        {
            "type": "tag_name_pattern",
            "parameters": {
                "name": "SemVer",
                "negate": False,
                "operator": "regex",
                "pattern": SEMVER_PATTERN,
            },
        },
    ],
    "bypass_actors": [],
}

# Repository settings — PATCH /repos/{owner}/{repo}
REPO_PATCH_SETTINGS: dict[str, dict[str, Any]] = {
    "has_issues": {
        "desired": True,
        "section": "Features",
        "label": "Issues enabled",
        "note": "",
    },
    "has_projects": {
        "desired": True,
        "section": "Features",
        "label": "Projects enabled",
        "note": "",
    },
    "has_wiki": {
        "desired": False,
        "section": "Features",
        "label": "Wiki disabled",
        "note": "Prefer docs-in-repo over undocumented wikis",
    },
    "allow_squash_merge": {
        "desired": True,
        "section": "Merge Settings",
        "label": "Squash merge allowed",
        "note": "",
    },
    "allow_merge_commit": {
        "desired": True,
        "section": "Merge Settings",
        "label": "Merge commits allowed",
        "note": "",
    },
    "allow_rebase_merge": {
        "desired": True,
        "section": "Merge Settings",
        "label": "Rebase merge allowed",
        "note": "",
    },
    "allow_auto_merge": {
        "desired": True,
        "section": "Merge Settings",
        "label": "Auto-merge allowed",
        "note": "PRs auto-merge once all requirements pass",
    },
    "delete_branch_on_merge": {
        "desired": True,
        "section": "Merge Settings",
        "label": "Delete branch on merge",
        "note": "Auto-cleanup stale branches",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# GitHub API Client
# ─────────────────────────────────────────────────────────────────────────────

class GitHubClient:
    API = "https://api.github.com"
    _BASE_HEADERS = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    def __init__(self, token: str) -> None:
        self._session = requests.Session()
        self._session.headers.update(self._BASE_HEADERS)
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _call(self, method: str, path: str, payload: dict | None = None) -> tuple[int, Any]:
        url = f"{self.API}{path}"
        resp = self._session.request(method, url, json=payload)
        body: Any = {}
        if resp.content:
            try:
                body = resp.json()
            except ValueError:
                body = resp.text
        return resp.status_code, body

    def get_raw(self, path: str) -> requests.Response:
        """Return the raw Response object (needed to read headers)."""
        return self._session.get(f"{self.API}{path}")

    def get(self, path: str) -> tuple[int, Any]:
        return self._call("GET", path)

    def patch(self, path: str, payload: dict) -> tuple[int, Any]:
        return self._call("PATCH", path, payload)

    def put(self, path: str, payload: dict) -> tuple[int, Any]:
        return self._call("PUT", path, payload)

    def post(self, path: str, payload: dict) -> tuple[int, Any]:
        return self._call("POST", path, payload)


# ─────────────────────────────────────────────────────────────────────────────
# Token Validation
# ─────────────────────────────────────────────────────────────────────────────

_REQUIRED_SCOPES = {"admin:org", "repo"}


def check_token(client: GitHubClient) -> set[str]:
    """Verify the token is valid and has the required OAuth scopes.

    Returns the set of missing required scopes (empty = all good).
    Calls _die() on auth failure (401/non-200).
    """
    resp = client.get_raw("/user")
    if resp.status_code == 401:
        return {"__invalid__"}   # sentinel: token rejected
    if resp.status_code != 200:
        _die(f"Could not verify token: HTTP {resp.status_code}")

    user = resp.json()
    login = user.get("login", "(unknown)")

    # GitHub returns granted scopes in X-OAuth-Scopes (comma-separated)
    scope_header = resp.headers.get("X-OAuth-Scopes", "")
    granted: set[str] = {s.strip() for s in scope_header.split(",") if s.strip()}

    print(f"\n  Token      : authenticated as {_c(login, _CYAN)}")
    print(f"  Scopes     : {_c(', '.join(sorted(granted)) or '(none)', _CYAN)}")

    missing = _REQUIRED_SCOPES - granted
    if missing:
        print()
        for s in sorted(missing):
            print(_c(f"  ✗  Missing required scope: {s}", _RED))
    else:
        print(_c("  ✓  Required scopes present (admin:org, repo)", _GREEN))

    return missing


# ─────────────────────────────────────────────────────────────────────────────
# Scanning
# ─────────────────────────────────────────────────────────────────────────────

def scan_org(client: GitHubClient, org: str) -> dict[str, Any]:
    """Fetch all settings relevant to the policy baseline for the given org."""
    result: dict[str, Any] = {}

    print(f"\n  Scanning org '{org}'...")

    code, data = client.get(f"/orgs/{org}")
    if code != 200:
        _die(f"Cannot fetch org '{org}': HTTP {code} — {data.get('message', data)}")
    result["org"] = data

    code, data = client.get(f"/orgs/{org}/actions/permissions")
    result["actions_permissions"] = data if code == 200 else {}
    if code != 200:
        _warn(f"  Could not fetch Actions permissions (HTTP {code})")

    code, data = client.get(f"/orgs/{org}/actions/permissions/selected-actions")
    result["actions_selected"] = data if code == 200 else {}

    code, data = client.get(f"/orgs/{org}/actions/permissions/workflow")
    result["workflow_permissions"] = data if code == 200 else {}
    if code != 200:
        _warn(f"  Could not fetch workflow permissions (HTTP {code})")

    code, data = client.get(f"/orgs/{org}/rulesets")
    if code == 200:
        full_rulesets = []
        for rs in (data or []):
            rs_code, rs_full = client.get(f"/orgs/{org}/rulesets/{rs['id']}")
            full_rulesets.append(rs_full if rs_code == 200 else rs)
        result["rulesets"] = full_rulesets
    else:
        result["rulesets"] = []
        _warn(f"  Could not fetch rulesets (HTTP {code})")

    code, data = client.get(f"/orgs/{org}/properties/schema")
    result["custom_properties"] = data if code == 200 else []
    if code != 200:
        _warn(f"  Could not fetch custom properties (HTTP {code})")

    return result


def scan_repo(client: GitHubClient, org: str, repo: str) -> dict[str, Any]:
    """Fetch all repo settings relevant to the policy baseline."""
    full = f"{org}/{repo}"
    print(f"\n  Scanning repo '{full}'...")

    code, data = client.get(f"/repos/{full}")
    if code != 200:
        _die(f"Cannot fetch repo '{full}': HTTP {code} — {data.get('message', data)}")

    return {"repo": data}


# ─────────────────────────────────────────────────────────────────────────────
# Change Computation
# ─────────────────────────────────────────────────────────────────────────────

# Type alias — a single proposed change record
ChangeRecord = dict[str, Any]


def compute_org_changes(
    current: dict[str, Any],
    allowed_actions: str = "none",
) -> list[ChangeRecord]:
    """Compare current org state against the baseline; return a list of changes.

    Args:
        current:         Output of scan_org().
        allowed_actions: One of 'all', 'none', 'selected'.  Controls which
                         Actions permission records are included.  The
                         selected-actions sub-settings are only included (and
                         applied) when this is 'selected'.
    """
    changes: list[ChangeRecord] = []
    org_data = current.get("org", {})

    # ── PATCH /orgs/{org} ────────────────────────────────────────────────────
    for field, meta in ORG_PATCH_SETTINGS.items():
        curr_val = org_data.get(field)
        desired_val = meta["desired"]
        changes.append({
            "section": meta["section"],
            "label": meta["label"],
            "setting": field,
            "api_endpoint": "PATCH /orgs/{org}",
            "current": curr_val,
            "desired": desired_val,
            "note": meta.get("note", ""),
            "ghas_required": meta.get("ghas_required", False),
            # GHAS settings are always skipped at org level by default —
            # they require a license for private repos and should be enabled
            # per-repo as needed. Non-GHAS settings skip when already correct.
            "skip": curr_val == desired_val or meta.get("ghas_required", False),
            "_apply_group": "org_patch",
        })

    # ── Manual-only settings (scanned for display; never patched via API) ─────
    for field, meta in ORG_MANUAL_SETTINGS.items():
        curr_val = org_data.get(field)
        desired_val = meta["desired"]
        changes.append({
            "section": meta["section"],
            "label": meta["label"],
            "setting": field,
            "api_endpoint": "UI only",
            "current": curr_val,
            "desired": desired_val,
            "note": meta.get("note", ""),
            "ghas_required": False,
            "manual_only": True,
            "skip": curr_val == desired_val,
            "_apply_group": "manual",
        })

    # ── PUT /orgs/{org}/actions/permissions ──────────────────────────────────
    # allowed_actions='none' is the script sentinel meaning "leave as-is" —
    # it is NOT a valid API value. Only generate change records when a real
    # mode (all / local_only / selected) was explicitly requested.
    ap = current.get("actions_permissions", {})
    if allowed_actions != "none":
        effective_ap_settings = {**ACTIONS_PERMISSION_SETTINGS, "allowed_actions": allowed_actions}
        for field, desired_val in effective_ap_settings.items():
            curr_val = ap.get(field)
            changes.append({
                "section": "Actions",
                "label": f"Actions: {field.replace('_', ' ')}",
                "setting": field,
                "api_endpoint": "PUT /orgs/{org}/actions/permissions",
                "current": curr_val,
                "desired": desired_val,
                "note": "",
                "ghas_required": False,
                "skip": curr_val == desired_val,
                "_apply_group": "actions_permissions",
            })

    # ── PUT /orgs/{org}/actions/permissions/selected-actions ─────────────────
    # Only meaningful (and applicable) when allowed_actions = 'selected'
    sa = current.get("actions_selected", {})
    for field, desired_val in ACTIONS_SELECTED_SETTINGS.items():
        curr_val = sa.get(field)
        not_selected_mode = allowed_actions != "selected"
        changes.append({
            "section": "Actions",
            "label": f"Allowed actions: {field.replace('_', ' ')}",
            "setting": field,
            "api_endpoint": "PUT /orgs/{org}/actions/permissions/selected-actions",
            "current": curr_val,
            "desired": desired_val,
            "note": (
                f"Skipped — only applies when --allowed-actions=selected (current: {allowed_actions})"
                if not_selected_mode
                else ""
            ),
            "ghas_required": False,
            "skip": not_selected_mode or curr_val == desired_val,
            "_apply_group": "actions_selected",
        })

    # ── PUT /orgs/{org}/actions/permissions/workflow ──────────────────────────
    wp = current.get("workflow_permissions", {})
    for field, desired_val in WORKFLOW_PERMISSION_SETTINGS.items():
        curr_val = wp.get(field)
        changes.append({
            "section": "Actions",
            "label": f"Workflow token: {field.replace('_', ' ')}",
            "setting": field,
            "api_endpoint": "PUT /orgs/{org}/actions/permissions/workflow",
            "current": curr_val,
            "desired": desired_val,
            "note": "",
            "ghas_required": False,
            "skip": curr_val == desired_val,
            "_apply_group": "workflow_permissions",
        })

    # ── Custom properties (must exist before Master Ruleset) ─────────────────
    existing_props = {p.get("property_name"): p for p in (current.get("custom_properties") or [])}

    for prop_def, note_suffix in [
        (LIFECYCLE_PROPERTY, "required by Master Ruleset"),
        (REPO_TYPE_PROPERTY, "classifies repository purpose"),
        (SENSITIVITY_PROPERTY, "classifies data sensitivity"),
    ]:
        name = prop_def["property_name"]
        prop_exists = name in existing_props
        match = _property_matches(existing_props.get(name), prop_def)
        changes.append({
            "section": "Custom Properties",
            "label": f"Custom property: {name}",
            "setting": f"property:{name}",
            "api_endpoint": "PATCH /orgs/{org}/properties/schema",
            "current": existing_props.get(name),
            "desired": prop_def,
            "note": ("Update if values differ" if prop_exists else f"Create — {note_suffix}"),
            "ghas_required": False,
            "skip": match,
            "_apply_group": "custom_properties",
        })

    # ── Org rulesets ──────────────────────────────────────────────────────────
    existing_rulesets = {r.get("name"): r for r in (current.get("rulesets") or [])}
    for desired_rs in [MASTER_RULESET, TAGS_RULESET]:
        name = desired_rs["name"]
        existing = existing_rulesets.get(name)
        match = _ruleset_matches(existing, desired_rs)
        changes.append({
            "section": "Org Rulesets",
            "label": f"Ruleset: {name}",
            "setting": f"ruleset:{name}",
            "api_endpoint": (
                f"PUT /orgs/{{org}}/rulesets/{existing['id']}"
                if existing else
                "POST /orgs/{org}/rulesets"
            ),
            "current": f"exists (id={existing['id']})" if existing else None,
            "desired": desired_rs,
            "note": ("Rules match baseline" if match else ("Update rules" if existing else "Create")),
            "ghas_required": False,
            "skip": match,
            "_apply_group": "rulesets",
            "_existing_id": existing["id"] if existing else None,
        })

    return changes


def compute_repo_changes(current: dict[str, Any]) -> list[ChangeRecord]:
    """Compare current repo state against the baseline; return a list of changes."""
    changes: list[ChangeRecord] = []
    repo_data = current.get("repo", {})

    for field, meta in REPO_PATCH_SETTINGS.items():
        curr_val = repo_data.get(field)
        desired_val = meta["desired"]
        changes.append({
            "section": meta["section"],
            "label": meta["label"],
            "setting": field,
            "api_endpoint": "PATCH /repos/{owner}/{repo}",
            "current": curr_val,
            "desired": desired_val,
            "note": meta.get("note", ""),
            "ghas_required": False,
            "skip": curr_val == desired_val,
            "_apply_group": "repo_patch",
        })

    return changes


def _ruleset_matches(existing: dict | None, desired: dict) -> bool:
    """Deep comparison: target, enforcement, rules, and conditions.

    Rules: exact set of types required; parameters compared only on keys present
    in the desired rule (GitHub may add its own defaults — we don't flag those).
    List-valued parameters are sorted before comparison.

    Conditions: ref_name / repository_name include/exclude lists are sorted.
    repository_property include/exclude objects are normalised (sorted property_values).
    Only condition keys present in the desired definition are checked.
    """
    if not existing:
        return False
    if existing.get("target") != desired["target"]:
        return False
    if existing.get("enforcement") != desired["enforcement"]:
        return False

    # ── Rules ──────────────────────────────────────────────────────────────
    existing_by_type = {r["type"]: r for r in (existing.get("rules") or [])}
    desired_by_type = {r["type"]: r for r in (desired.get("rules") or [])}

    if set(existing_by_type.keys()) != set(desired_by_type.keys()):
        return False

    def _norm_val(v: Any) -> Any:
        return sorted(v) if isinstance(v, list) else v

    for rtype, drule in desired_by_type.items():
        erule = existing_by_type[rtype]
        dparams = drule.get("parameters") or {}
        eparams = erule.get("parameters") or {}
        # Only compare keys we explicitly set in desired
        for key, dval in dparams.items():
            if _norm_val(dval) != _norm_val(eparams.get(key)):
                return False

    # ── Conditions ─────────────────────────────────────────────────────────
    def _norm_ref(ref: dict) -> dict:
        return {
            "include": sorted(ref.get("include") or []),
            "exclude": sorted(ref.get("exclude") or []),
        }

    def _norm_prop_list(items: list) -> list:
        return sorted(
            [
                {
                    "name": p["name"],
                    "source": p.get("source", ""),
                    "property_values": sorted(p.get("property_values") or []),
                }
                for p in items
            ],
            key=lambda p: p["name"],
        )

    def _norm_conditions(cond: dict | None) -> dict:
        if not cond:
            return {}
        out: dict = {}
        if "ref_name" in cond:
            out["ref_name"] = _norm_ref(cond["ref_name"])
        if "repository_name" in cond:
            out["repository_name"] = _norm_ref(cond["repository_name"])
        if "repository_property" in cond:
            rp = cond["repository_property"]
            out["repository_property"] = {
                "include": _norm_prop_list(rp.get("include") or []),
                "exclude": _norm_prop_list(rp.get("exclude") or []),
            }
        return out

    desired_conds = _norm_conditions(desired.get("conditions"))
    existing_conds = _norm_conditions(existing.get("conditions"))
    # Only check condition keys present in desired
    for key, dval in desired_conds.items():
        if existing_conds.get(key) != dval:
            return False

    return True


def _property_matches(existing: dict | None, desired: dict) -> bool:
    if not existing:
        return False
    return (
        existing.get("value_type") == desired["value_type"]
        and set(existing.get("allowed_values") or []) == set(desired.get("allowed_values") or [])
        and existing.get("default_value") == desired.get("default_value")
        and existing.get("required") == desired.get("required")
        and existing.get("description") == desired.get("description")
    )


# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

_USE_COLOR = sys.stdout.isatty()

_R = "\033[0m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_R}" if _USE_COLOR else text


def _fmt(val: Any) -> str:
    if val is None:
        return "(not set)"
    if isinstance(val, bool):
        return str(val).lower()
    if isinstance(val, dict):
        return "{...}"
    return str(val)


_SEP = "─" * 100


def display_changes(changes: list[ChangeRecord], title: str) -> None:
    # GHAS advisory: setting differs but is intentionally skipped at org level
    ghas_advisory = [
        c for c in changes
        if c.get("ghas_required") and c["current"] != c["desired"]
    ]
    # Manual-only items that need attention (differ from desired)
    manual_needed = [
        c for c in changes
        if c.get("manual_only") and c["current"] != c["desired"]
    ]
    # Pending API-writable changes (excludes manual-only regardless of skip flag)
    pending = [c for c in changes if not c["skip"] and not c.get("manual_only")]
    ok_count = sum(
        1 for c in changes
        if c["skip"]
        and not (c.get("ghas_required") and c["current"] != c["desired"])
        and not c.get("manual_only")
    )

    print(f"\n{_SEP}")
    print(_c(f"  {title}", _BOLD))
    print(_SEP)

    col = {"s": 22, "l": 44, "c": 16, "d": 16}
    header = (
        f"  {'SECTION':<{col['s']}}  {'SETTING':<{col['l']}}  "
        f"{'CURRENT':<{col['c']}}  {'DESIRED':<{col['d']}}  NOTE"
    )
    print(_c(header, _DIM))
    print(_c(_SEP, _DIM))

    if not pending and not ghas_advisory and not manual_needed:
        print(_c(f"  ✓  All {len(changes)} settings already match the baseline.", _GREEN))
        return

    for c in pending:
        curr_s = f"{_fmt(c['current']):<{col['c']}}"
        des_s = f"{_fmt(c['desired'] if not isinstance(c['desired'], dict) else '{...}'):<{col['d']}}"
        note = (c.get("note") or "")[:50]
        row = (
            f"  {c['section']:<{col['s']}}  {c['label']:<{col['l']}}  "
            f"{_c(curr_s, _RED)}  {_c(des_s, _GREEN)}  {note}"
        )
        print(row)

    if ghas_advisory:
        if pending:
            print()
        advisory_label = f"{'SKIPPED — GHAS REQUIRED':<{col['d']}}"
        for c in ghas_advisory:
            curr_s = f"{_fmt(c['current']):<{col['c']}}"
            row = (
                f"  {c['section']:<{col['s']}}  {c['label']:<{col['l']}}  "
                f"{_c(curr_s, _DIM)}  "
                f"{_c(advisory_label, _RED)}  "
                f"{_c('Not applied at org level — enable per-repo as needed', _RED)}"
            )
            print(row)

    if manual_needed:
        if pending or ghas_advisory:
            print()
        print(_c("  ── Manual configuration required (not settable via REST API) ──", _YELLOW))
        for c in manual_needed:
            curr_s = f"{_fmt(c['current']):<{col['c']}}"
            des_s = f"{_fmt(c['desired']):<{col['d']}}"
            row = (
                f"  {c['section']:<{col['s']}}  {c['label']:<{col['l']}}  "
                f"{_c(curr_s, _RED)}  {_c(des_s, _GREEN)}  "
                f"{_c(c.get('note', ''), _YELLOW)}"
            )
            print(row)

    print()
    if ok_count:
        print(_c(f"  ✓  {ok_count} setting(s) already match — no change needed.", _GREEN))
    if ghas_advisory:
        print(_c(
            f"  ⚠  {len(ghas_advisory)} GHAS setting(s) skipped — "
            "require Advanced Security license for private repos. "
            "Enable per-repo under Settings → Code security.",
            _RED,
        ))
    if manual_needed:
        print(_c(
            f"  ⚠  {len(manual_needed)} setting(s) require manual configuration in the GitHub UI "
            "(not writable via REST API).",
            _YELLOW,
        ))
    if pending:
        print(_c(f"  {len(pending)} change(s) required.", _YELLOW))


# ─────────────────────────────────────────────────────────────────────────────
# Export / Import
# ─────────────────────────────────────────────────────────────────────────────

def export_settings(
    org: str,
    repo: str | None,
    org_changes: list[ChangeRecord],
    repo_changes: list[ChangeRecord],
    path: str,
) -> None:
    """Write proposed changes to a JSON file for manual editing."""

    def _clean(c: ChangeRecord) -> dict:
        # Strip internal keys (prefixed with _) before serialising
        return {k: v for k, v in c.items() if not k.startswith("_")}

    payload = {
        "_metadata": {
            "org": org,
            "repo": repo,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "template_version": TEMPLATE_VERSION,
            "instructions": (
                "Set 'skip': true to exclude a change from being applied. "
                "Modify 'desired' to override the target value. "
                "All other fields are informational only."
            ),
        },
        "org_changes": [_clean(c) for c in org_changes],
        "repo_changes": [_clean(c) for c in repo_changes],
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)

    print(f"\n  Exported to: {_c(path, _CYAN)}")
    print("  Edit the file (set 'skip': true to exclude, modify 'desired' to override),")
    print(f"  then re-run with:  {_c(f'--settings-file {path}', _BOLD)}")


def import_settings(path: str) -> tuple[list[ChangeRecord], list[ChangeRecord]]:
    """Load changes from a previously exported (and optionally edited) JSON file."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    org_changes = data.get("org_changes", [])
    repo_changes = data.get("repo_changes", [])

    # Re-hydrate internal _apply_group from api_endpoint when missing
    for c in org_changes + repo_changes:
        if "_apply_group" not in c:
            c["_apply_group"] = _infer_apply_group(c.get("api_endpoint", ""))

    return org_changes, repo_changes


def _infer_apply_group(endpoint: str) -> str:
    if "selected-actions" in endpoint:
        return "actions_selected"
    if "permissions/workflow" in endpoint:
        return "workflow_permissions"
    if "actions/permissions" in endpoint and "selected" not in endpoint and "workflow" not in endpoint:
        return "actions_permissions"
    if "rulesets" in endpoint:
        return "rulesets"
    if "properties/schema" in endpoint:
        return "custom_properties"
    if "/repos/" in endpoint:
        return "repo_patch"
    return "org_patch"


# ─────────────────────────────────────────────────────────────────────────────
# Interactive Prompting
# ─────────────────────────────────────────────────────────────────────────────

def prompt_changes(
    changes: list[ChangeRecord],
    title: str,
    yes_all: bool = False,
) -> list[ChangeRecord]:
    """Walk the user through each pending API-writable change and collect approvals.

    Manual-only items are excluded from the interactive prompt — they are only
    shown in the summary display.
    """
    pending = [c for c in changes if not c["skip"] and not c.get("manual_only")]
    if not pending:
        print(f"\n  {title}: all settings already match — nothing to apply.")
        return []

    print(f"\n{'═' * 100}")
    print(_c(f"  Review changes — {title}", _BOLD))
    print(f"{'═' * 100}")

    approved: list[ChangeRecord] = []
    for i, c in enumerate(pending, 1):
        curr_s = _fmt(c["current"])
        des_s = _fmt(c["desired"] if not isinstance(c["desired"], dict) else c["setting"])
        note_line = f"\n  Note: {c['note']}" if c.get("note") else ""

        print(
            f"\n  [{i}/{len(pending)}] {_c(c['label'], _BOLD)}\n"
            f"  Section:  {c['section']}\n"
            f"  Current:  {_c(curr_s, _RED)}\n"
            f"  Desired:  {_c(des_s, _GREEN)}"
            f"{note_line}"
        )

        if yes_all:
            print("  → Auto-approved (--yes)")
            approved.append(c)
            continue

        while True:
            try:
                ans = input("  Apply? [y=yes / n=skip / a=approve all / q=quit]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n\n  Interrupted — no changes applied.")
                sys.exit(130)

            if ans in ("y", "yes"):
                approved.append(c)
                break
            elif ans in ("n", "no", ""):
                print("  Skipped.")
                break
            elif ans in ("a", "all"):
                approved.append(c)
                yes_all = True
                break
            elif ans in ("q", "quit"):
                print("\n  Aborted — no changes applied.")
                sys.exit(0)
            else:
                print("  Please enter y, n, a, or q.")

    return approved


# ─────────────────────────────────────────────────────────────────────────────
# Applying Changes
# ─────────────────────────────────────────────────────────────────────────────

def apply_org_changes(client: GitHubClient, org: str, approved: list[ChangeRecord]) -> None:
    if not approved:
        return

    print(f"\n{_SEP}")
    print(_c(f"  Applying {len(approved)} org change(s) to '{org}'...", _CYAN))

    # Group by apply_group — order matters (custom_properties before rulesets)
    groups: dict[str, list[ChangeRecord]] = {}
    for c in approved:
        groups.setdefault(c.get("_apply_group", "org_patch"), []).append(c)

    # 1. Basic org settings
    if "org_patch" in groups:
        payload = {c["setting"]: c["desired"] for c in groups["org_patch"]}
        code, resp = client.patch(f"/orgs/{org}", payload)
        _report("PATCH /orgs/{org}", list(payload.keys()), code, resp)
        # Verify each field actually round-tripped — some require Enterprise plan
        if code in (200, 201, 204):
            vcode, vdata = client.get(f"/orgs/{org}")
            if vcode == 200:
                for field, desired_val in payload.items():
                    actual_val = vdata.get(field)
                    if actual_val != desired_val:
                        print(_c(
                            f"  ⚠  {field}: value unchanged after PATCH "
                            f"(still: {_fmt(actual_val)}) — "
                            "field may require additional permissions; "
                            "check token scopes and org plan",
                            _YELLOW,
                        ))

    # 2. Actions permissions (sets allowed_actions = "selected")
    # GitHub API: PUT /orgs/{org}/actions/permissions (not PATCH)
    if "actions_permissions" in groups:
        payload = {c["setting"]: c["desired"] for c in groups["actions_permissions"]}
        code, resp = client.put(f"/orgs/{org}/actions/permissions", payload)
        _report("PUT actions/permissions", list(payload.keys()), code, resp)

    # 3. Selected-actions allowlist (requires allowed_actions = "selected")
    if "actions_selected" in groups:
        payload = {c["setting"]: c["desired"] for c in groups["actions_selected"]}
        code, resp = client.put(f"/orgs/{org}/actions/permissions/selected-actions", payload)
        _report("PUT selected-actions", list(payload.keys()), code, resp)

    # 4. Default workflow token permissions
    if "workflow_permissions" in groups:
        payload = {c["setting"]: c["desired"] for c in groups["workflow_permissions"]}
        code, resp = client.put(f"/orgs/{org}/actions/permissions/workflow", payload)
        _report("PUT workflow permissions", list(payload.keys()), code, resp)

    # 5. Custom property (must exist before Master Ruleset references it)
    if "custom_properties" in groups:
        for c in groups["custom_properties"]:
            prop_name = c["desired"]["property_name"]
            payload = {"properties": [c["desired"]]}
            code, resp = client.patch(f"/orgs/{org}/properties/schema", payload)
            if code in (200, 201):
                print(f"  ✓  Custom property '{prop_name}' configured")
            else:
                _report_error(f"PATCH properties/schema ({c['label']})", code, resp)

    # 6. Rulesets (after lifecycle property is available)
    if "rulesets" in groups:
        for c in groups["rulesets"]:
            rs_name = c["setting"].removeprefix("ruleset:")
            existing_id = c.get("_existing_id")
            rs_payload = c["desired"]

            if existing_id:
                code, resp = client.put(f"/orgs/{org}/rulesets/{existing_id}", rs_payload)
                action = "Updated"
            else:
                code, resp = client.post(f"/orgs/{org}/rulesets", rs_payload)
                action = "Created"

            if code in (200, 201):
                print(f"  ✓  {action} ruleset '{rs_name}' (id={resp.get('id', existing_id)})")
            else:
                _report_error(f"{action} ruleset '{rs_name}'", code, resp)

    # 7. Manual-only reminders (never sent to API)
    if "manual" in groups:
        manual_items = [c for c in groups["manual"] if c["current"] != c["desired"]]
        if manual_items:
            print(f"\n{_SEP}")
            print(_c("  ⚠  Manual configuration required in GitHub UI:", _YELLOW))
            for c in manual_items:
                print(_c(
                    f"     • {c['label']}: set to {_fmt(c['desired'])}  —  {c.get('note', '')}",
                    _YELLOW,
                ))


def apply_repo_changes(
    client: GitHubClient, org: str, repo: str, approved: list[ChangeRecord]
) -> None:
    if not approved:
        return

    print(f"\n{_SEP}")
    print(_c(f"  Applying {len(approved)} repo change(s) to '{org}/{repo}'...", _CYAN))

    payload = {c["setting"]: c["desired"] for c in approved if c.get("_apply_group") == "repo_patch"}
    if payload:
        code, resp = client.patch(f"/repos/{org}/{repo}", payload)
        _report(f"PATCH /repos/{org}/{repo}", list(payload.keys()), code, resp)


def _report(label: str, fields: list[str], code: int, resp: Any) -> None:
    if code in (200, 201, 204):
        print(f"  ✓  {label}: applied [{', '.join(fields)}]")
    else:
        _report_error(label, code, resp)
        print(f"     Fields attempted: {', '.join(fields)}")
        print("     Some fields may not be writable via API for your plan/token scope.")


def _report_error(label: str, code: int, resp: Any) -> None:
    if isinstance(resp, dict):
        msg = resp.get("message", str(resp))
        errors = resp.get("errors") or []
        print(f"  ✗  {label}: HTTP {code} — {msg}")
        for e in errors:
            detail = e if isinstance(e, str) else json.dumps(e)
            print(f"     • {detail}")
    else:
        print(f"  ✗  {label}: HTTP {code} — {resp}")


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _die(msg: str) -> None:
    print(f"\n  ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def _warn(msg: str) -> None:
    print(_c(f"  WARN: {msg}", _YELLOW))


def _prompt_allowed_actions(non_interactive: bool = False) -> str:
    """Prompt the user to choose an allowed_actions mode, or return 'none' silently."""
    if non_interactive:
        print(_c("  allowed_actions  : none (default — use --allowed-actions to override)", _DIM))
        return "none"

    print(f"\n  {'─' * 60}")
    print(_c("  GitHub Actions — allowed_actions setting", _BOLD))
    print(f"  {'─' * 60}")
    print("  Controls which Actions are permitted to run in the org.\n")
    print("    [1] none     — Disable all Actions org-wide")
    print("    [2] all      — Allow all Actions (GitHub-owned and third-party)")
    print("    [3] selected — Allow GitHub-owned + verified + explicit allowlist")
    print()

    _LABELS = {"1": "none", "2": "all", "3": "selected",
               "none": "none", "all": "all", "selected": "selected"}

    while True:
        try:
            ans = input("  Choice [1/2/3 or none/all/selected] (default: none): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n\n  Interrupted — defaulting to 'none'.")
            return "none"

        if ans == "" or ans not in _LABELS:
            if ans == "":
                print(_c("  → none (default)", _CYAN))
                return "none"
            print("  Please enter 1, 2, 3, none, all, or selected.")
            continue

        choice = _LABELS[ans]
        print(_c(f"  → {choice}", _CYAN))
        return choice


def _gh_cli_token() -> str:
    """Try to obtain a token from the `gh` CLI. Returns empty string on failure."""
    import shutil
    import subprocess
    if not shutil.which("gh"):
        return ""
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def _get_token(arg_token: str | None, use_gh_cli: bool = False) -> str:
    """Resolve the GitHub token using a priority chain:

    1. --token flag
    2. GITHUB_TOKEN env var
    3. ``gh auth token`` (silent) — only when --use-gh-cli is set
    4. Interactive prompt: offer gh auth login or manual paste
    """
    # 1 & 2: explicit sources
    token = (arg_token or os.environ.get("GITHUB_TOKEN", "")).strip()
    if token:
        return token

    # 3: gh CLI silent — only when caller opted in
    if use_gh_cli:
        token = _gh_cli_token()
        if token:
            print(_c("  Token source : gh CLI (gh auth token)", _DIM))
            return token
        _die("--use-gh-cli specified but 'gh auth token' returned no token. "
             "Run 'gh auth login' first.")

    # 4: interactive
    import getpass
    import shutil
    import subprocess
    gh_available = bool(shutil.which("gh"))
    print()
    print(_c("  No GitHub token found in --token or GITHUB_TOKEN.", _YELLOW))
    print("  Options:")
    if gh_available:
        print("    [1] Use 'gh auth token' (gh CLI)  (recommended)")
        print("    [2] Paste a personal access token manually")
        print("    [3] Abort")
        labels = {"1": "gh", "2": "paste", "3": "abort"}
    else:
        print("    [1] Paste a personal access token manually")
        print("    [2] Abort")
        labels = {"1": "paste", "2": "abort"}
    print()
    while True:
        try:
            choice = input(f"  Choice [{'/' .join(labels)}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            _die("Aborted.")
        action = labels.get(choice)
        if action == "gh":
            token = _gh_cli_token()
            if token:
                print(_c("  Token acquired from gh CLI.", _GREEN))
                return token
            print()
            print(_c("  No active gh session. Running 'gh auth login'...", _YELLOW))
            print()
            ret = subprocess.run(["gh", "auth", "login"]).returncode
            if ret != 0:
                print(_c("  gh auth login failed.", _RED))
                continue
            token = _gh_cli_token()
            if not token:
                print(_c("  Could not retrieve token from gh CLI after login.", _RED))
                continue
            print(_c("  Token acquired from gh CLI.", _GREEN))
            return token
        elif action == "paste":
            token = getpass.getpass("  Paste token: ").strip()
            if token:
                return token
            print(_c("  No token entered.", _RED))
        elif action == "abort":
            _die("Aborted.")
        else:
            print(f"  Please enter {', '.join(labels)}.")


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Apply the GitHub organization policy baseline (org-policy-template.md).\n"
            "Scans current settings, diffs against the baseline, prompts for approval, "
            "and applies changes idempotently."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Scan + apply interactively:
              uv run scripts/github_policy_apply.py --org myorg

              # Include a specific repo:
              uv run scripts/github_policy_apply.py --org myorg --repo myrepo

              # Export proposed changes for manual review, then apply:
              uv run scripts/github_policy_apply.py --org myorg --export proposed.json
              uv run scripts/github_policy_apply.py --org myorg --settings-file proposed.json

              # Dry run (no writes):
              uv run scripts/github_policy_apply.py --org myorg --dry-run

              # Auto-approve all changes (CI/automation):
              uv run scripts/github_policy_apply.py --org myorg --yes

            Required token scopes: admin:org, repo
            Set GITHUB_TOKEN env var or pass --token.
        """),
    )
    parser.add_argument("--org", required=True, help="GitHub organization name")
    parser.add_argument(
        "--repo",
        metavar="REPO",
        help="Repository name (without org prefix) — scans and applies repo-level settings",
    )
    parser.add_argument(
        "--token",
        metavar="TOKEN",
        help="GitHub personal access token (default: $GITHUB_TOKEN)",
    )
    parser.add_argument(
        "--use-gh-cli",
        action="store_true",
        help="Acquire the token silently from the gh CLI ('gh auth token') without prompting",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Export proposed changes to a JSON file and exit (edit, then use --settings-file)",
    )
    parser.add_argument(
        "--settings-file",
        metavar="FILE",
        help="Load settings from a previously exported (and optionally edited) JSON file",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Auto-approve all pending changes (non-interactive)",
    )
    parser.add_argument(
        "--allowed-actions",
        choices=["all", "none", "selected"],
        default=None,
        metavar="MODE",
        help=(
            "Set the org allowed_actions value: 'all', 'none', or 'selected'. "
            "Prompted interactively when not specified (unless --yes or --dry-run, "
            "which default to 'none').  The selected-actions allowlist sub-settings "
            "are only evaluated and applied when this is 'selected'."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and display proposed changes but do not apply anything",
    )
    args = parser.parse_args()

    token = _get_token(args.token, use_gh_cli=args.use_gh_cli)
    client = GitHubClient(token)

    print(f"\n{'═' * 100}")
    print(_c("  GitHub Organization Policy Configurator", _BOLD))
    print(_c("  Baseline: org-policy-template.md", _DIM))
    print(f"{'═' * 100}")
    print(f"\n  Organization : {_c(args.org, _CYAN)}")
    if args.repo:
        print(f"  Repository   : {_c(args.repo, _CYAN)}")
    if args.dry_run:
        print(_c("  Mode         : DRY RUN — no changes will be written", _YELLOW))

    # ── Token validation (with retry if scopes missing) ──────────────────────
    while True:
        missing_scopes = check_token(client)
        if not missing_scopes:
            break

        invalid = "__invalid__" in missing_scopes
        if invalid:
            print(_c("  Token is invalid or expired (HTTP 401).", _RED))
        else:
            print()
            print(_c(
                "  WARNING: One or more required scopes are missing.\n"
                "  Some API calls will fail with 403 or 404.",
                _YELLOW,
            ))

        # Non-interactive modes: hard-fail
        if args.yes or args.dry_run:
            _die("Token is missing required scopes (admin:org, repo). "
                 "Re-run with a valid token.")

        gh_available = bool(_gh_cli_token() or __import__('shutil').which('gh'))
        print()
        print("  Options:")
        if gh_available:
            print("    [1] Re-authenticate via 'gh auth login' and retry")
            print("    [2] Paste a new personal access token")
        else:
            print("    [1] Paste a new personal access token")
        print("    [q] Abort")
        print()
        try:
            ans = input("  Choice: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            _die("Aborted.")

        if ans == "q":
            _die("Aborted — token does not have required scopes.")

        if gh_available and ans == "1":
            import subprocess as _sp
            _sp.run(["gh", "auth", "login"])
            new_token = _gh_cli_token()
            if not new_token:
                print(_c("  Could not retrieve token from gh CLI.", _RED))
                continue
        elif (gh_available and ans == "2") or (not gh_available and ans == "1"):
            import getpass as _gp
            new_token = _gp.getpass("  Paste token: ").strip()
            if not new_token:
                print(_c("  No token entered.", _RED))
                continue
        else:
            print("  Invalid choice.")
            continue

        client = GitHubClient(new_token)
        print()

    # ── Load settings: from file or by scanning live API ─────────────────────
    if args.settings_file:
        print(f"\n  Loading settings from: {_c(args.settings_file, _CYAN)}")
        org_changes, repo_changes = import_settings(args.settings_file)
    else:
        # Resolve --allowed-actions: prompt interactively if not supplied on CLI
        allowed_actions = args.allowed_actions or _prompt_allowed_actions(
            non_interactive=args.yes or args.dry_run
        )
        current_org = scan_org(client, args.org)
        org_changes = compute_org_changes(current_org, allowed_actions)

        repo_changes: list[ChangeRecord] = []
        if args.repo:
            current_repo = scan_repo(client, args.org, args.repo)
            repo_changes = compute_repo_changes(current_repo)

    # ── Display proposed changes ──────────────────────────────────────────────
    display_changes(org_changes, f"Organization — {args.org}")
    if repo_changes:
        display_changes(repo_changes, f"Repository — {args.org}/{args.repo}")

    # ── Export and exit ───────────────────────────────────────────────────────
    if args.export:
        export_settings(args.org, args.repo, org_changes, repo_changes, args.export)
        print("\n  Edit the file, then re-run with --settings-file to apply.")
        sys.exit(0)

    # ── Count pending changes ─────────────────────────────────────────────────
    all_changes = org_changes + repo_changes
    pending_count = sum(1 for c in all_changes if not c["skip"] and not c.get("manual_only"))

    if pending_count == 0:
        print(_c("\n  ✓  All settings already match the baseline. Nothing to do.", _GREEN))
        sys.exit(0)

    if args.dry_run:
        print(_c(f"\n  Dry run complete — {pending_count} change(s) pending.", _YELLOW))
        sys.exit(0)

    # ── Offer export before interactive approval ──────────────────────────────
    if not args.yes and not args.settings_file:
        print(f"\n  {pending_count} change(s) pending.")
        print("    [1] Review and apply interactively  (default)")
        print("    [2] Export to JSON first, then apply later")
        print("    [3] Abort")
        try:
            choice = input("\n  Choice [1/2/3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.")
            sys.exit(0)

        if choice == "2":
            default_path = "proposed-settings.json"
            try:
                export_path = input(f"  Export filename [{default_path}]: ").strip() or default_path
            except (EOFError, KeyboardInterrupt):
                export_path = default_path
            export_settings(args.org, args.repo, org_changes, repo_changes, export_path)
            print("\n  Edit the file and re-run with --settings-file to apply.")
            sys.exit(0)
        elif choice == "3":
            print("  Aborted.")
            sys.exit(0)
        # choice "1" (or Enter) falls through to interactive prompting

    # ── Interactive approval ──────────────────────────────────────────────────
    approved_org = prompt_changes(org_changes, f"Org: {args.org}", yes_all=args.yes)
    approved_repo: list[ChangeRecord] = []
    if repo_changes:
        approved_repo = prompt_changes(
            repo_changes, f"Repo: {args.org}/{args.repo}", yes_all=args.yes
        )

    total_approved = len(approved_org) + len(approved_repo)
    if total_approved == 0:
        print("\n  No changes approved — nothing applied.")
        sys.exit(0)

    # ── Apply ─────────────────────────────────────────────────────────────────
    apply_org_changes(client, args.org, approved_org)
    if approved_repo and args.repo:
        apply_repo_changes(client, args.org, args.repo, approved_repo)

    print(f"\n{'═' * 100}")
    print(_c(f"  Done — {total_approved} change(s) applied.", _GREEN))
    print(f"{'═' * 100}\n")


if __name__ == "__main__":
    main()
