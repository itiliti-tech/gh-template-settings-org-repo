# GitHub Policy Templates

[![Generate PDFs](https://github.com/itiliti-tech/gh-template-settings-org-repo/actions/workflows/generate-pdfs.yml/badge.svg)](https://github.com/itiliti-tech/gh-template-settings-org-repo/actions/workflows/generate-pdfs.yml)
[![Latest Release](https://img.shields.io/github/v/release/itiliti-tech/gh-template-settings-org-repo?label=release)](https://github.com/itiliti-tech/gh-template-settings-org-repo/releases/latest)
[![Commits since release](https://img.shields.io/github/commits-since/itiliti-tech/gh-template-settings-org-repo/latest?label=unreleased+commits)](https://github.com/itiliti-tech/gh-template-settings-org-repo/compare/latest...main)
[![Release needed](https://img.shields.io/github/issues/itiliti-tech/gh-template-settings-org-repo/release-needed?label=release+needed&color=yellow)](https://github.com/itiliti-tech/gh-template-settings-org-repo/issues?q=is%3Aopen+label%3Arelease-needed)

Best-practices documentation and tooling for configuring GitHub organizations and
repositories to a consistent, secure baseline.

> **PDF downloads:** Pre-built PDFs of both policy templates are attached to every
> [GitHub Release](../../releases). Each PDF is versioned and includes the generation date.

---

## Contents

| File / Directory          | Purpose                                                    |
| ------------------------- | ---------------------------------------------------------- |
| `org-policy-template.md`  | Recommended GitHub organization settings and rationale     |
| `repo-policy-template.md` | Recommended per-repository settings and creation checklist |
| `scripts/`                | Python and shell tooling                                   |
| `images/`                 | Assets used in generated PDFs                              |
| `.github/workflows/`      | CI: lint on push/PR, generate PDFs on tag                  |

---

## Scripts

### `scripts/convert_templates_to_pdf.py`

Converts the policy markdown templates to PDFs using Microsoft Edge headless.
PDFs include the version and generation date in the document header.

### Options

| Flag           | Description                                | Default            |
| -------------- | ------------------------------------------ | ------------------ |
| `--version`    | SemVer string embedded in the PDF filename | _(empty)_          |
| `--date`       | Generation date embedded in the PDF        | Today's date       |
| `--output-dir` | Directory to write PDFs into               | Next to each `.md` |

#### Using `uv` (recommended)

```bash
# Generate with version and date
uv run scripts/convert_templates_to_pdf.py --version 1.0.0 --output-dir dist

# Generate without a version tag
uv run scripts/convert_templates_to_pdf.py --output-dir dist
```

#### Using a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r scripts/requirements.txt
python scripts/convert_templates_to_pdf.py --version 1.0.0 --output-dir dist
```

#### Using global Python

```bash
pip install markdown
python scripts/convert_templates_to_pdf.py --version 1.0.0 --output-dir dist
```

---

### `scripts/github_policy_apply.py`

Scans a GitHub organization's current settings, diffs them against the policy baseline,
prompts for approval, and applies changes idempotently via the GitHub REST API.

**Requires:** a GitHub personal access token with `admin:org` and `repo` scopes.  
Set as `GITHUB_TOKEN` env var, pass `--token`, or use `--use-gh-cli` to pull the token
from an active [`gh` CLI](https://cli.github.com/) session automatically.

#### Using `uv` (recommended)

```bash
# Interactive scan + apply (prompts for token source if not set)
uv run scripts/github_policy_apply.py --org YOUR_ORG

# Use token from active gh CLI session (no prompt)
uv run scripts/github_policy_apply.py --org YOUR_ORG --use-gh-cli

# Include repo-level settings
uv run scripts/github_policy_apply.py --org YOUR_ORG --repo YOUR_REPO

# Dry run (scan only, no changes)
uv run scripts/github_policy_apply.py --org YOUR_ORG --dry-run

# Export proposed changes to JSON, edit, then apply
uv run scripts/github_policy_apply.py --org YOUR_ORG --export proposed.json
uv run scripts/github_policy_apply.py --org YOUR_ORG --settings-file proposed.json

# Auto-approve all changes (CI/automation)
uv run scripts/github_policy_apply.py --org YOUR_ORG --yes
```

#### Using a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r scripts/requirements.txt
python scripts/github_policy_apply.py --org YOUR_ORG
```

#### Using global Python

```bash
pip install requests
python scripts/github_policy_apply.py --org YOUR_ORG
```

---

## Linting

### Markdown

Requires [`markdownlint-cli2`](https://github.com/DavidAnson/markdownlint-cli2):

```bash
npm install -g markdownlint-cli2
bash scripts/lint-markdown.sh
```

### Python

Requires [`ruff`](https://docs.astral.sh/ruff/):

```bash
# via uv
uv tool install ruff
ruff check scripts/

# or via pip
pip install ruff
bash scripts/lint-python.sh
```

---

## CI / GitHub Actions

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `.github/workflows/lint.yml` | Push / PR to `main` | Lints all markdown and Python files |
| `.github/workflows/generate-pdfs.yml` | Push a SemVer tag or manual run | Generates PDFs, attaches to release, closes any open `release-needed` issue |
| `.github/workflows/notify-release-needed.yml` | Push to `main` touching `*.md` templates | Opens (or updates) a `release-needed` issue as a reminder to publish |

### Creating a release

```bash
git tag 1.0.0
git push origin 1.0.0
```

The `generate-pdfs` workflow will run automatically, generate versioned PDFs
(e.g. `org-policy-template-v1.0.0.pdf`), and attach them to the GitHub Release.

---

## Versioning

This project uses [Semantic Versioning](https://semver.org/).
All tags must match the SemVer pattern — enforced by the org-level Tags Ruleset
described in `org-policy-template.md`.
