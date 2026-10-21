# ruff: noqa: E501
"""Render the PBL report Markdown to HTML and PDF (headless Chromium) in the v1.1.1 look.

    python scripts/pbl_style/render.py reports/pbl/pbl_report.md --out reports/pbl

The PDF is rendered twice: the first pass finds the page of every chapter heading, the second prints
them in the contents list.
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


def page_numbers(pdf: Path, heads: list[str]) -> dict[str, int]:
    """Page on which each chapter heading is printed (searched after the contents page)."""
    info = subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True).stdout
    n = int(re.search(r"Pages:\s+(\d+)", info).group(1))
    out: dict[str, int] = {}
    start = 0
    for pg in range(1, n + 1):
        text = subprocess.run(
            ["pdftotext", "-f", str(pg), "-l", str(pg), "-layout", str(pdf), "-"],
            capture_output=True,
            text=True,
        ).stdout
        lines = {ln.strip() for ln in text.splitlines()}
        if not start and "Abstract" in lines:
            start = pg  # chapters begin after the contents and abstract page
        for h in heads:
            if h not in out and h in lines and start and pg > start:
                out[h] = pg
    return out


def contents_heads(html: str) -> list[str]:
    block = re.search(r'id="contents".*?<ul>(.*?)</ul>', html, flags=re.S)
    items = re.findall(r"<li>.*?</li>", block.group(1) if block else "", flags=re.S)
    return [re.sub(r"<[^>]+>", "", i).strip() for i in items]


def with_page_numbers(html: str, pages: dict[str, int]) -> str:
    def block(m: re.Match) -> str:
        def li(x: re.Match) -> str:
            text = re.sub(r"<[^>]+>", "", x.group(1)).strip()
            pg = pages.get(text)
            extra = f'<span class="dots"></span><span class="pg">{pg}</span>' if pg else ""
            return f"<li>{x.group(1)}{extra}</li>"

        return m.group(1) + re.sub(r"<li>(.*?)</li>", li, m.group(2), flags=re.S)

    return re.sub(r'(id="contents".*?)(<ul>.*?</ul>)', block, html, count=1, flags=re.S)


def make_pdf(html: Path, pdf: Path) -> None:
    foot = '<div style="font:7pt Carlito,sans-serif;color:#666;width:100%;text-align:center">PhishDrift · <span class="pageNumber"></span></div>'
    with sync_playwright() as p:
        b = p.chromium.launch(
            executable_path=next(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux*/chrome"))
        )
        pg = b.new_page()
        pg.goto(html.resolve().as_uri())
        pg.pdf(
            path=str(pdf),
            format="A4",
            print_background=True,
            display_header_footer=True,
            header_template="<span></span>",
            footer_template=foot,
            margin={"top": "20mm", "bottom": "20mm", "left": "18mm", "right": "18mm"},
        )
        b.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("md", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reports/pbl"))
    a = ap.parse_args()
    html, pdf = a.out / "pbl_report.html", a.out / "pbl_report.pdf"
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
        ],
        check=True,
    )
    base = figure_captions(html.read_text(encoding="utf-8"))
    html.write_text(base, encoding="utf-8")
    make_pdf(html, pdf)
    pages = page_numbers(pdf, contents_heads(base))
    html.write_text(with_page_numbers(base, pages), encoding="utf-8")
    make_pdf(html, pdf)
    print(f"{len(pages)} of {len(contents_heads(base))} contents entries numbered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
