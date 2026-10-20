# ruff: noqa: E501
"""Render the PBL report Markdown to HTML and PDF (headless Chromium) and DOCX in the v1.1.1 look.

python scripts/pbl_style/render.py reports/pbl/pbl_report.md --out reports/pbl
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).parent


def figure_captions(html: str) -> str:
    """Bold the 'Figure N.' label like the v1.1.1 captions."""
    return re.sub(
        r"(<figcaption[^>]*>)\s*(Figure [\d.]+\.)",
        r'\1<strong style="color:#1f5f99;font-family:Carlito,Segoe UI,sans-serif">\2</strong>',
        html,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("md", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reports/pbl"))
    a = ap.parse_args()
    html = a.out / "pbl_report.html"
    subprocess.run(
        [
            "pandoc",
            str(a.md),
            "-o",
            str(html),
            "--standalone",
            "--embed-resources",
            "--resource-path",
            str(a.out),
            "--css",
            str(HERE / "report.css"),
            "--from",
            "markdown+pipe_tables+implicit_figures",
            "--metadata",
            "pagetitle=PhishDrift",
        ],
        check=True,
    )
    html.write_text(figure_captions(html.read_text(encoding="utf-8")), encoding="utf-8")
    foot = '<div style="font:7pt Carlito,sans-serif;color:#666;width:100%;text-align:center">PhishDrift · <span class="pageNumber"></span></div>'
    with sync_playwright() as p:
        b = p.chromium.launch(
            executable_path=next(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux*/chrome"))
        )
        pg = b.new_page()
        pg.goto(html.resolve().as_uri())
        pg.pdf(
            path=str(a.out / "pbl_report.pdf"),
            format="A4",
            print_background=True,
            display_header_footer=True,
            header_template="<span></span>",
            footer_template=foot,
            margin={"top": "20mm", "bottom": "20mm", "left": "18mm", "right": "18mm"},
        )
        b.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
