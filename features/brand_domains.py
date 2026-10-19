"""Brand-to-official-domains map and the look-alike character table, built from data.

python -m features brand-domains [--wikidata] [--misp] [--confusables PATH]

Writes ``configs/lists/brand_domains.json`` ({"brands": {brand: [registrable domains]}, ...})
for the brands in ``configs/lists/brands.txt``, and ``configs/lists/confusables.json`` (each
non-ASCII character that Unicode lists as confusable with an ASCII letter or digit, mapped to it).

Sources (nothing typed by hand, nothing chosen by popularity):

- Wikidata official websites (P856) of the same organisations the brand list was scraped from:
  the same SPARQL query as ``features.scrape`` (``configs/features.yaml``), so on the collector PC
  the cached answers are reused. An organisation's English name and its site's label are its
  brand tokens; all its sites are its domains.
- MISP warning lists (CC0) of a vendor's own domains, e.g. ``microsoft`` (which lists
  microsoftonline.com, outlook.com, office365.com, live.com) and ``google``. Every brand token
  that is the label of one of a list's domains gets the whole list (a brand family).
- Unicode confusables, from the MIT-licensed ``confusable_homoglyphs`` package data
  (``confusables.json``, derived from Unicode's confusables.txt).

Hosting-platform domains (``configs/platforms.yaml``) are never official: a page on a platform
belongs to its tenant, not to the platform's brand.
"""

from __future__ import annotations

import argparse
import json
import logging
import string
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from features.brand_rules import BRAND_DOMAINS_FILE, CONFUSABLES_FILE, load_config
from features.lists import load_lists
from features.scrape import WIKIDATA_TIMEOUT_S, _clean_brand
from phishdrift.domains import registered_domain

log = logging.getLogger("features.brand_domains")
ASCII_ALNUM = set(string.ascii_letters + string.digits)


def _domain(site: str) -> str | None:
    host = site.strip().lower().lstrip("*").lstrip(".")
    if not host:
        return None
    if "://" not in host:
        host = "http://" + host
    try:
        dom = registered_domain(host)
    except Exception:  # noqa: BLE001 - malformed list entry
        return None
    return dom if dom and "." in dom else None


def families_from_wikidata_rows(rows: list[dict]) -> list[tuple[set[str], set[str]]]:
    """(brand tokens, domains) per organisation name in SPARQL rows with ``label`` and ``site``."""
    by_name: dict[str, tuple[set[str], set[str]]] = {}
    for r in rows:
        label = r.get("label", {}).get("value", "")
        site = r.get("site", {}).get("value", "")
        name = _clean_brand(label)
        dom = _domain(site) if site else None
        if not name or not dom:
            continue
        tokens, domains = by_name.setdefault(name, (set(), set()))
        tokens.add(name)
        tokens.add(_clean_brand(dom.split(".", 1)[0]) or name)
        domains.add(dom)
    return list(by_name.values())


def families_from_misp(lists: dict[str, list[str]]) -> list[tuple[set[str], set[str]]]:
    """(brand tokens, domains) per MISP vendor list: tokens are the labels of its domains."""
    out = []
    for name, entries in lists.items():
        domains = {d for d in map(_domain, entries) if d}
        tokens = {_clean_brand(d.split(".", 1)[0]) for d in domains} | {_clean_brand(name)}
        out.append(({t for t in tokens if t}, domains))
    return out


def build_map(
    brands, families, platforms=frozenset(), max_family=500
) -> dict[str, list[str]]:  # fmt: skip
    """Official domains of each brand in ``brands``: the union of every family that names it.

    Families with more than ``max_family`` domains are cut to the domains whose label is one of
    the family's brand tokens (keeps a vendor's product domains, drops CDN noise)."""
    wanted = set(brands)
    out: dict[str, set[str]] = {}
    for tokens, domains in families:
        doms = {d for d in domains if d not in platforms}
        if len(doms) > max_family:
            doms = {d for d in doms if d.split(".", 1)[0] in tokens & wanted}
        for t in tokens & wanted:
            out.setdefault(t, set()).update(doms)
    return {b: sorted(v) for b, v in sorted(out.items()) if v}


def confusables_map(table: dict) -> dict[str, str]:
    """Non-ASCII character -> the ASCII letter or digit Unicode says it can be confused with,
    from ``confusable_homoglyphs``' ``confusables.json`` ({char: [{"c": char, "n": name}]})."""
    found: dict[str, set[str]] = {}
    for key, entries in table.items():
        if len(key) != 1:
            continue
        for e in entries:
            c = e.get("c", "")
            if len(c) != 1:
                continue
            if key in ASCII_ALNUM and ord(c) > 127:
                found.setdefault(c, set()).add(key.lower())
            elif ord(key) > 127 and c in ASCII_ALNUM:
                found.setdefault(key, set()).add(c.lower())
    # a character confusable with several ASCII characters: prefer a letter, then the first
    return {
        k: sorted(v, key=lambda x: (x.isdigit(), x))[0]
        for k, v in sorted(found.items())
        if k.lower() == k or k.lower() not in found
    }


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=0, sort_keys=True) + "\n", "utf-8"
    )
    return path


def _wikidata_rows(client, cfg: dict) -> list[dict]:
    rows: list[dict] = []
    for qid in cfg["wikidata_types"]:
        sparql = cfg["wikidata_query"].format(type=qid, min_sitelinks=cfg["wikidata_min_sitelinks"])
        url = f"https://query.wikidata.org/sparql?format=json&query={quote(sparql)}"
        try:
            body = client.get(
                url,
                cache_ttl_s=365 * 86400,  # the brand list was built from these answers
                headers={"Accept": "application/sparql-results+json"},
                timeout_s=WIKIDATA_TIMEOUT_S,
            )
            rows += json.loads(body)["results"]["bindings"]
        except Exception as exc:  # noqa: BLE001 - one type failing must not lose the others
            log.warning("Wikidata type %s skipped: %s", qid, str(exc)[:200])
    return rows


def _misp_lists(client, cfg: dict) -> dict[str, list[str]]:
    out = {}
    for name in cfg["misp_lists"]:
        url = cfg["misp_url"].format(name=name)
        try:
            data = json.loads(client.get(url, cache_ttl_s=30 * 86400))
            out[name] = [str(x) for x in data.get("list", [])]
        except Exception as exc:  # noqa: BLE001
            log.warning("MISP list %s skipped: %s", name, str(exc)[:200])
    return out


def run(wikidata: bool, misp: bool, confusables: Path | None) -> dict[str, int]:
    from phishdrift.config import load_config as load_app_config
    from phishdrift.config import resolve
    from phishdrift.http import HttpClient

    cfg = load_config()["sources"]
    lists = load_lists()
    client = HttpClient.from_config(
        load_app_config("collector")["http"],
        resolve(load_app_config("collector")["paths"]["http_cache_dir"]),
    )
    families, used = [], []
    if wikidata:
        rows = _wikidata_rows(client, load_app_config("features")["lists"])
        families += families_from_wikidata_rows(rows)
        used.append(f"Wikidata P856 ({len(rows)} rows)")
    if misp:
        ml = _misp_lists(client, cfg)
        families += families_from_misp(ml)
        used.append("MISP warning lists: " + ", ".join(sorted(ml)))
    done: dict[str, int] = {}
    if families:
        mapping = build_map(lists.brands, families, lists.platforms, cfg["max_family"])
        write_json(
            BRAND_DOMAINS_FILE,
            {"source": "; ".join(used), "built": _stamp(), "brands": mapping},
        )
        done["brands_mapped"] = len(mapping)
    if confusables is not None:
        table = json.loads(Path(confusables).read_text(encoding="utf-8"))
        cmap = confusables_map(table)
        write_json(
            CONFUSABLES_FILE,
            {
                "source": "confusable_homoglyphs confusables.json (MIT; from Unicode confusables.txt)",  # noqa: E501
                "built": _stamp(),
                "map": cmap,
            },
        )
        done["confusables"] = len(cmap)
    return done


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--wikidata", action="store_true")
    ap.add_argument("--misp", action="store_true")
    ap.add_argument("--confusables", type=Path, default=None, help="confusables.json path")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    print(run(a.wikidata, a.misp, a.confusables))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
