"""The unified raw schema every source is converted to.

Columns
-------
url     str        original URL as given by the source
domain  str        registrable domain, public-suffix-only (U1), see phishdrift.domains
label   int8       1 = phishing, 0 = benign
date    datetime   UTC collection / first-seen date; NaT when the source has none
source  str        dataset name, e.g. "phreshphish", "phiusiil", "live"
html    str|None   page HTML when the source provides it
depth   int16      non-empty path segments (query and fragment excluded)

Bookkeeping columns (never model features): ``origin`` (sub-feed or split inside a source,
e.g. "openphish", "crawl", "hf_test") and ``domain_u2`` (private-suffix-aware domain).
"""

from __future__ import annotations

import pandas as pd

from phishdrift.domains import registered_domain, registered_domain_private, url_depth

COLUMNS = ["url", "domain", "label", "date", "source", "html", "depth"]
BOOKKEEPING = ["origin", "domain_u2"]
REQUIRED_NON_NULL = ["url", "domain", "label", "source", "depth"]


class SchemaError(ValueError):
    pass


def _series(value, n: int, dtype=object) -> pd.Series:
    if isinstance(value, pd.Series):
        return value.reset_index(drop=True)
    if value is None or isinstance(value, str):
        return pd.Series([value] * n, dtype=dtype)
    return pd.Series(list(value), dtype=dtype)


def to_schema(
    urls: pd.Series,
    labels: pd.Series,
    source: str | pd.Series,
    dates: pd.Series | None = None,
    html: pd.Series | None = None,
    origin: str | pd.Series | None = None,
) -> pd.DataFrame:
    """Build a schema-conformant frame; computes ``domain``, ``domain_u2`` and ``depth``."""
    urls = urls.astype(str).str.strip().reset_index(drop=True)
    n = len(urls)
    df = pd.DataFrame(
        {
            "url": urls,
            "domain": urls.map(registered_domain),
            "label": pd.Series(labels).reset_index(drop=True).astype("int8"),
            "date": (
                pd.to_datetime(_series(dates, n), utc=True, errors="coerce", format="mixed")
                if dates is not None
                else pd.Series(pd.NaT, index=range(n), dtype="datetime64[ns, UTC]")
            ),
            "source": _series(source, n, dtype=str).astype(str),
            "html": _series(html, n) if html is not None else pd.Series([None] * n, dtype=object),
            "depth": urls.map(url_depth).astype("int16"),
            "origin": _series(origin if origin is not None else "", n, dtype=str).astype(str),
            "domain_u2": urls.map(registered_domain_private),
        }
    )
    df["html"] = pd.Series(
        [h if isinstance(h, str) and h else None for h in df["html"]], dtype=object
    )
    return df


def validate(df: pd.DataFrame) -> pd.DataFrame:
    """Raise SchemaError if ``df`` does not match the unified schema; return it unchanged."""
    missing = [c for c in COLUMNS if c not in df.columns]
    if missing:
        raise SchemaError(f"missing columns: {missing}")
    for col in REQUIRED_NON_NULL:
        if df[col].isna().any():
            raise SchemaError(f"column {col!r} has nulls")
    if (df["url"].astype(str).str.len() == 0).any():
        raise SchemaError("empty url")
    if (df["domain"].astype(str).str.len() == 0).any():
        raise SchemaError("empty domain (unparsable url)")
    if not set(pd.unique(df["label"])) <= {0, 1}:
        raise SchemaError(f"labels must be 0/1, got {sorted(pd.unique(df['label']))}")
    if not isinstance(df["date"].dtype, pd.DatetimeTZDtype) or str(df["date"].dt.tz) != "UTC":
        raise SchemaError(f"date must be tz-aware UTC datetime, got {df['date'].dtype}")
    if (df["depth"] < 0).any():
        raise SchemaError("negative depth")
    return df


def drop_unparsable(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Drop rows whose URL yields no domain. Returns (frame, n_dropped)."""
    bad = df["domain"].astype(str).str.len() == 0
    return df.loc[~bad].reset_index(drop=True), int(bad.sum())
