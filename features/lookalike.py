"""Payload of the offline look-alike check (js/data/lookalike.json), built from data.

``python -m features lookalike``

The browser rule (``js/src/lookalike.js``) asks whether a site's name is a brand's name written with
look-alike characters (``paypa1``, ``аpple`` as punycode) or one edit away from it (``paypai``),
while the site is not one of the brand's own domains. Inputs, none typed by hand:

- brand names: ``configs/lists/brands.txt``;
- a brand's own domains: ``configs/lists/brand_domains.json`` (Wikidata official websites and MISP
  vendor lists, ``domains`` below is their flat union; a site whose name equals a brand name, such
  as ``paypal.de``, is also never a look-alike);
- look-alike characters: ``configs/lists/confusables.json`` (Unicode confusables).
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from features.lists import LISTS_DIR, ROOT, read_list

CONFIG_FILE = ROOT / "configs" / "lookalike.yaml"
OUT_FILE = ROOT / "js" / "data" / "lookalike.json"


def build_payload(lists_dir: Path = LISTS_DIR, config_file: Path = CONFIG_FILE) -> dict:
    cfg = yaml.safe_load(Path(config_file).read_text(encoding="utf-8"))
    brands = sorted(
        {b for b in read_list(lists_dir / "brands.txt") if len(b) >= cfg["min_brand_len"]}
    )
    owned = json.loads((lists_dir / "brand_domains.json").read_text(encoding="utf-8"))["brands"]
    confusables = json.loads((lists_dir / "confusables.json").read_text(encoding="utf-8"))["map"]
    return {
        "rules": cfg["rules"],
        "min_edit_len": cfg["min_edit_len"],
        "brands": brands,
        "domains": sorted({d for b in brands for d in owned.get(b, [])}),
        "skeleton_map": confusables,
    }


def write(out: Path = OUT_FILE) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(build_payload(), ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return out
