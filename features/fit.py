"""The few tier A numbers that are learned from data (training folds only).

``bigram_loglik_domain`` needs character-bigram log probabilities of benign domain labels and
``tld_risk`` needs the phishing rate per public suffix. Both are stored as a small JSON file
(``configs/lists/fitted.json``) that the JavaScript port can read. Until the file exists both
features are NaN. Fit on training folds only, never on test or calibration rows.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from features.lists import LISTS_DIR
from features.urlparts import parse

FITTED_FILE = LISTS_DIR / "fitted.json"


@dataclass(frozen=True)
class Fitted:
    bigram_logprob: dict[str, float] = field(default_factory=dict)
    bigram_floor: float = -20.0
    tld_risk: dict[str, float] = field(default_factory=dict)
    tld_default: float = 0.5


def load_fitted(path: Path = FITTED_FILE) -> Fitted:
    if not Path(path).exists():
        return Fitted()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Fitted(
        bigram_logprob=data["bigram_logprob"],
        bigram_floor=data["bigram_floor"],
        tld_risk=data["tld_risk"],
        tld_default=data["tld_default"],
    )


def fit(
    urls: list[str], labels: list[int], platforms: frozenset[str], smoothing: float = 1.0
) -> dict:
    """Fit from training rows: bigrams on benign domain labels, TLD risk on all labelled rows."""
    bigrams: Counter[str] = Counter()
    tld_total: Counter[str] = Counter()
    tld_phish: Counter[str] = Counter()
    for url, label in zip(urls, labels, strict=True):
        p = parse(url, platforms)
        if p is None or p.is_ip or not p.suffix:
            continue
        tld_total[p.suffix] += 1
        tld_phish[p.suffix] += label
        if label == 0 and not p.is_platform:
            bigrams.update(p.label[i : i + 2] for i in range(len(p.label) - 1))
    total = sum(bigrams.values())
    vocab = len(bigrams)
    denom = total + smoothing * (vocab + 1)
    logprob = {b: math.log((c + smoothing) / denom) for b, c in bigrams.items()}
    base = sum(tld_phish.values()) / max(sum(tld_total.values()), 1)
    risk = {t: (tld_phish[t] + smoothing * base) / (n + smoothing) for t, n in tld_total.items()}
    return {
        "bigram_logprob": {k: round(v, 5) for k, v in logprob.items()},
        "bigram_floor": round(math.log(smoothing / denom), 5),
        "tld_risk": {k: round(v, 5) for k, v in risk.items()},
        "tld_default": round(base, 5),
    }


def write_fitted(data: dict, path: Path = FITTED_FILE) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    return Path(path)
