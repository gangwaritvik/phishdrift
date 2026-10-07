"""The common schema every dataset is converted to.

Columns
-------
url     str        original URL as given by the source
domain  str        registered domain (eTLD+1), see phishdrift.domains
label   int8       1 = phishing (malicious), 0 = benign
date    datetime   UTC first-seen / collection date; NaT when the source has none
source  str        dataset or feed name, e.g. "phreshphish", "openphish", "tranco"
html    str|None   page HTML when the source provides it
"""

from __future__ import annotations

import pandas as pd

from phishdrift.domains import registered_domain

COLUMNS = ["url", "domain", "label", "date", "source", "html"]
REQUIRED_NON_NULL = ["url", "domain", "label", "source"]


class SchemaError(ValueError):
    pass


def to_schema(
    urls: pd.Series,
    labels: pd.Series,
    source: str | pd.Series,
    dates: pd.Series | None = None,
    html: pd.Series | None = None,
) -> pd.DataFrame:
    """Build a schema-conformant frame; computes ``domain`` from ``url``."""
    urls = urls.astype(str).str.strip().reset_index(drop=True)
    n = len(urls)
    df = pd.DataFrame(
        {
            "url": urls,
            "domain": urls.map(registered_domain),
            "label": pd.Series(labels).reset_index(drop=True).astype("int8"),
            "date": (
                pd.to_datetime(pd.Series(dates).reset_index(drop=True), utc=True, errors="coerce")
                if dates is not None
                else pd.Series(pd.NaT, index=range(n), dtype="datetime64[ns, UTC]")
            ),
            "source": (
                pd.Series(source).reset_index(drop=True).astype(str)
                if isinstance(source, pd.Series)
                else pd.Series([source] * n, dtype=str)
            ),
            "html": (
                pd.Series(html).reset_index(drop=True).astype(object)
                if html is not None
                else pd.Series([None] * n, dtype=object)
            ),
        }
    )
    df["html"] = df["html"].where(df["html"].notna(), None)
    return df


def validate(df: pd.DataFrame, require_html_column: bool = True) -> pd.DataFrame:
    """Raise SchemaError if ``df`` does not match the common schema; return it unchanged."""
    expected = COLUMNS if require_html_column else [c for c in COLUMNS if c != "html"]
    missing = [c for c in expected if c not in df.columns]
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
    return df


def drop_unparsable(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Drop rows whose URL yields no domain. Returns (frame, n_dropped)."""
    bad = df["domain"].astype(str).str.len() == 0
    return df.loc[~bad].reset_index(drop=True), int(bad.sum())
