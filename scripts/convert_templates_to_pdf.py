# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "markdown>=3.6",
#   "weasyprint>=62",
# ]
# ///
"""
Convert GitHub policy template markdown files to PDFs.
Uses the markdown package to produce HTML, then WeasyPrint to render PDFs.

Usage:
    uv run scripts/convert_templates_to_pdf.py
    uv run scripts/convert_templates_to_pdf.py --version 1.2.0 --date 2026-05-05
    uv run scripts/convert_templates_to_pdf.py --output-dir dist
"""

import argparse
import base64
import pathlib
import sys
from datetime import date as _date
import markdown
import weasyprint

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR = pathlib.Path(__file__).parent
REPO_ROOT   = SCRIPT_DIR.parent
LOGO_PATH   = REPO_ROOT / "images" / "logo.png"

TEMPLATES = [
    REPO_ROOT / "org-policy-template.md",
    REPO_ROOT / "repo-policy-template.md",
]

# ── Logo (embedded as base64 data URI) ───────────────────────────────────────
def logo_data_uri(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    data = base64.b64encode(path.read_bytes()).decode()
    return f"data:image/png;base64,{data}"

# ── CSS ───────────────────────────────────────────────────────────────────────
CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

/* ── Page layout ── */
@page {
    size: letter;
    margin: 22mm 18mm 22mm 18mm;
    @top-right {
        content: string(doc-title);
        font-family: Inter, sans-serif;
        font-size: 8pt;
        color: #6b7280;
    }
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-family: Inter, sans-serif;
        font-size: 8pt;
        color: #9ca3af;
    }
}

@page :first {
    @top-right { content: none; }
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-family: Inter, sans-serif;
        font-size: 8pt;
        color: #9ca3af;
    }
}

/* ── Base ── */
html, body {
    font-family: Inter, 'Segoe UI', Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.55;
    color: #111827;
    margin: 0;
    padding: 0;
}

/* ── Cover header (first page) ── */
.cover-header {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 28px;
    padding-bottom: 16px;
    border-bottom: 3px solid #2563eb;
}
.cover-logo {
    height: 52px;
    width: 52px;
    object-fit: contain;
    flex-shrink: 0;
}
.doc-meta {
    font-size: 9pt;
    color: #6b7280;
    margin-bottom: 20px;
    display: flex;
    gap: 16px;
}
.doc-meta span::before {
    color: #9ca3af;
}

/* ── Headings ── */
h1 {
    font-size: 20pt;
    font-weight: 700;
    color: #1e3a5f;
    margin: 0 0 4px 0;
    line-height: 1.2;
    string-set: doc-title content();
}
h2 {
    font-size: 13pt;
    font-weight: 700;
    color: #1e40af;
    margin: 20px 0 6px 0;
    padding-bottom: 4px;
    border-bottom: 1.5px solid #bfdbfe;
    page-break-after: avoid;
}
h3 {
    font-size: 11pt;
    font-weight: 600;
    color: #1d4ed8;
    margin: 14px 0 4px 0;
    page-break-after: avoid;
}
h4 {
    font-size: 10pt;
    font-weight: 600;
    color: #374151;
    margin: 10px 0 3px 0;
    page-break-after: avoid;
}

/* ── Paragraph / subtitle ── */
p { margin: 0 0 8px 0; }
strong { font-weight: 600; }
em { font-style: italic; }

/* Date / subtitle line directly under h1 */
h1 + p {
    color: #6b7280;
    font-size: 9pt;
    margin-bottom: 16px;
}

/* ── Horizontal rule ── */
hr {
    border: none;
    border-top: 1px solid #e5e7eb;
    margin: 14px 0;
}

/* ── Tables ── */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 9pt;
    margin: 8px 0 12px 0;
    page-break-inside: auto;
}
thead tr {
    background-color: #1e40af;
    color: #ffffff;
}
thead th {
    padding: 6px 9px;
    text-align: left;
    font-weight: 600;
    font-size: 8.5pt;
    letter-spacing: 0.02em;
}
tbody tr:nth-child(even) { background-color: #f0f7ff; }
tbody tr:nth-child(odd)  { background-color: #ffffff; }
tbody td {
    padding: 5px 9px;
    border-bottom: 1px solid #e5e7eb;
    vertical-align: top;
}
tr { page-break-inside: avoid; }

/* ── Blockquotes (notes/callouts) ── */
blockquote {
    margin: 6px 0 10px 0;
    padding: 8px 12px;
    background-color: #eff6ff;
    border-left: 4px solid #2563eb;
    border-radius: 0 4px 4px 0;
    font-size: 9pt;
    color: #1e3a5f;
    page-break-inside: avoid;
}
blockquote p { margin: 0; }

/* ── Code ── */
code {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8.5pt;
    background-color: #f1f5f9;
    padding: 1px 4px;
    border-radius: 3px;
    color: #0f172a;
}
pre {
    background-color: #0f172a;
    color: #e2e8f0;
    padding: 10px 14px;
    border-radius: 5px;
    font-size: 8pt;
    overflow-x: auto;
    page-break-inside: avoid;
}
pre code {
    background: none;
    padding: 0;
    color: inherit;
    font-size: inherit;
}

/* ── Lists (checklist / bullets) ── */
ul, ol {
    margin: 4px 0 8px 0;
    padding-left: 20px;
}
li {
    margin-bottom: 3px;
    font-size: 9.5pt;
}
li > ul, li > ol { margin-top: 2px; }

/* Checkboxes rendered as ☐ / ☑ */
li input[type=checkbox] { display: none; }
li input[type=checkbox] + * { display: inline; }
li:has(input[type=checkbox])::marker { content: "☐  "; color: #2563eb; }
li:has(input[type=checkbox]:checked)::marker { content: "☑  "; color: #16a34a; }
"""

# ── HTML template ─────────────────────────────────────────────────────────────
HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<style>{css}</style>
</head>
<body>
{cover_header}
{meta_block}
{body}
</body>
</html>
"""

# ── Markdown → HTML ───────────────────────────────────────────────────────────
MD_EXTENSIONS = [
    "tables",
    "fenced_code",
    "codehilite",
    "toc",
    "attr_list",
    "md_in_html",
    "sane_lists",
]


def _cover_header_html(logo_uri: str) -> str:
    if not logo_uri:
        return ""
    return (
        '<div class="cover-header">'
        f'<img class="cover-logo" src="{logo_uri}" alt=""/>'
        "</div>"
    )


def _meta_block_html(version: str, gen_date: str) -> str:
    parts = []
    if version:
        parts.append(f'<span>Version {version}</span>')
    if gen_date:
        parts.append(f'<span>Generated {gen_date}</span>')
    if not parts:
        return ""
    return '<div class="doc-meta">' + "".join(parts) + "</div>"


def md_to_html(md_text: str, logo_uri: str, version: str, gen_date: str) -> str:
    body = markdown.markdown(md_text, extensions=MD_EXTENSIONS)
    return HTML_TEMPLATE.format(
        css=CSS,
        cover_header=_cover_header_html(logo_uri),
        meta_block=_meta_block_html(version, gen_date),
        body=body,
    )


# ── Main ─────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert policy template markdown files to PDFs using Edge headless."
    )
    parser.add_argument(
        "--version",
        default="",
        help="Version string to embed in each PDF (e.g. 1.2.0)",
    )
    parser.add_argument(
        "--date",
        default=str(_date.today()),
        help="Generation date to embed in each PDF (default: today)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to write PDFs into (default: same directory as each template)",
    )
    return parser.parse_args()


def pdf_filename(template: pathlib.Path, version: str) -> str:
    stem = template.stem
    if version:
        return f"{stem}-v{version}.pdf"
    return f"{stem}.pdf"


def main() -> None:
    args = parse_args()

    logo_uri = logo_data_uri(LOGO_PATH)
    if not logo_uri:
        print(f"  Warning: logo not found at {LOGO_PATH}", file=sys.stderr)

    output_dir: pathlib.Path | None = None
    if args.output_dir:
        output_dir = pathlib.Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    for md_path in TEMPLATES:
        if not md_path.exists():
            print(f"  SKIP (not found): {md_path}")
            continue

        dest_dir = output_dir if output_dir else md_path.parent
        pdf_path = dest_dir / pdf_filename(md_path, args.version)

        print(f"  Converting: {md_path.name} → {pdf_path.name}")

        md_text  = md_path.read_text(encoding="utf-8")
        html_str = md_to_html(md_text, logo_uri, args.version, args.date)

        weasyprint.HTML(string=html_str).write_pdf(str(pdf_path))

        kb = round(pdf_path.stat().st_size / 1024, 1)
        print(f"    Saved: {pdf_path}  ({kb} KB)")

    print("\nDone.")


if __name__ == "__main__":
    main()
