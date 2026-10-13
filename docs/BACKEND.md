# Backend

FastAPI service plus the builder for the hashed lists the extension syncs. Code in `backend/`,
settings in `configs/backend.yaml` (RDAP URL and DNS/TLS timeouts are reused from
`configs/collector.yaml`).

**Status: placeholder.** The signals and risk levels come from hand-set threshold rules
(`backend/checks.py`, thresholds in `configs/backend.yaml` under `rules`). They are not a trained
tier C model (tier C is built offline in `experiments/tier_c.py` and is not wired into the
backend yet), and nothing here has been validated against labelled data. `/score` therefore always returns `"tier_c_model": false`.

## Run

    pip install -e ".[dev,backend]"
    uvicorn backend.app:create_app --factory
    python -m backend build-lists [--tranco-file PATH] [--out DIR]

Tests: `pytest tests/test_backend.py` (no network; the domain checker is injected).

## API

All bodies are JSON. `domain` must be a bare hostname: no scheme, path, port, `@`, spaces or
non-ASCII (send punycode). It is lowercased and one trailing dot is dropped; anything else is a
422. Unknown fields are rejected with 422, so a URL cannot be sent by accident.

| Route | Request | Response |
| --- | --- | --- |
| `GET /health` | | `{"ok": true}` |
| `POST /domain-info` | `{"domain"}` | `{"domain", "cached", "facts", "signals", "risk", "error"}` |
| `POST /score` | `{"domain", "local_verdict": 0\|1\|2}` | `{"domain", "risk", "signals", "tier_c_model": false, "cached"}` |
| `POST /feedback` | `{"domain", "kind": "false_positive"\|"missed_phish", "verdict": 0\|1\|2}` | `{"ok": true}` |
| `GET /lists/manifest` | | `{"version", "built_at", "prefix_bytes", "counts": {"blocklist_domains", "blocklist_urls", "allowlist_domains", "open_hosting_domains"}}` |
| `GET /lists/blocklist.json` | | `{"version", "prefix_bytes", "domains": [hex], "urls": [hex]}` |
| `GET /lists/allowlist.json` | | `{"version", "prefix_bytes", "domains": [hex], "open_hosting": [zone]}` |

`facts`: `age_days, registered, resolves, has_mx, has_spf, has_dmarc, tls_ok, tls_verified,
cert_age_days, cert_free_issuer, san_count`; each is `null` when unknown (a failed lookup is
unknown, never `false`). `signals`: `[{"id", "text", "severity": "info"|"warn"|"high"}]`.
`risk`: `low` | `elevated` | `high`. `/score` runs the same checks as `/domain-info` and shares its
cache; `local_verdict` is validated but not used by the placeholder rules (it is there for the
future combiner).

Fail soft: a failed or timed-out lookup answers HTTP 200 with `risk: "low"`, no signals, all facts
`null` and `error` set (`timeout` or `lookup_failed`). Failures are not cached. The only non-200
answers are 422 (invalid input), 404 (lists not built) and 429 (rate limit, with `Retry-After`).
`/feedback` returns `{"ok": false}` if the file cannot be written.

Per-domain cache: in memory, TTL and size in `cache`. Rate limit: token bucket per client address
(`rate_limit`), on every route except `/health`. Timeouts: DNS, TLS and RDAP use the collector
settings; the whole check is capped by `lookup.overall_timeout_s`. RDAP responses are also cached
on disk (`lookup.rdap_cache_ttl_s`). CORS is off: the extension's service worker uses
`host_permissions`.

## Privacy

- The backend receives a hostname only: never a full URL or page content. Fields other than the
  documented ones are rejected.
- `/feedback` appends one JSON line per report to `data/feedback/YYYY-MM-DD.jsonl` with exactly
  `domain`, `kind`, `verdict`, `timestamp` (UTC). No IP address, user agent or identifier is stored.
- Logs name the exception type only, never the domain or any request body.
- A TLS handshake is made only when every address the name resolves to is globally routable, so
  the service cannot be used to probe internal hosts. (A DNS rebinding race remains possible; the
  probe sends no data beyond the handshake.) If the resolver itself is down (a control lookup
  fails), DNS facts are `null`, not "does not resolve".

## Hashed lists

`python -m backend build-lists` writes `data/lists/{manifest,blocklist,allowlist}.json`
(`data/` is gitignored). Everything is sorted and deterministic; `version` is the first 12 hex
characters of sha256 over the prefix size and the sorted contents of all three lists.

Hash: `sha256(key.encode("utf-8")).hexdigest()[: 2 * prefix_bytes]`, `prefix_bytes = 6`
(`lists.prefix_bytes`). The extension mirrors two key functions exactly
(`backend/lists.py`, checked by `tests/fixtures/list_key_parity.json`, regenerate with
`python -m backend.make_fixture`):

`list_url_key(url)`: strip surrounding whitespace (space, tab, CR, LF, FF, VT only); drop the
fragment (from the first `#`); drop the scheme (`^[a-zA-Z][a-zA-Z0-9+.\-]*://`); the authority runs
to the first `/` or `?`; drop userinfo (up to the last `@` of the authority); lowercase ASCII A-Z in
the authority (nothing else); the host ends at the first `:` (or at the first `]` when the
authority starts with `[`), the port suffix keeps its colon; strip trailing dots from the host,
then one leading `www.`; keep the rest verbatim except that `/` characters at the end of the path
(before any `?`) are removed. Result: host + port suffix + path + query.

`list_domain_key(url)`: the host as above (no port). An IPv4 literal (four dotted decimal octets
0-255, no leading zeros) is returned as is; a host written `[...]` (IPv6) is returned without the
brackets; otherwise the public-suffix-only registrable domain (ICANN suffixes, tldextract's bundled
list), or the host itself when it has no registrable domain (`localhost`, a bare suffix).

Blocklist: phishing URLs (label 1 or threat `phishing`) from `data/raw/feeds/*/*.parquet`, plus all
URLs of `data/raw/blocklists/*/*.parquet` (blocklist-only feeds such as URLhaus), de-duplicated. A
URL goes to `urls` (hash of `list_url_key`) when its registrable domain is in
`configs/platforms.yaml`, is an allowlist candidate, or its host lies in an open-hosting zone;
every other URL adds its domain hash to `domains`.
Allowlist: the first `lists.allowlist_top_n` Tranco entries (from `--tranco-file`, one `domain` or
`rank,domain` per line, or the `tranco` package; with neither, the allowlist is empty and the build
continues), minus platform domains, minus whole-domain open-hosting zones, minus any blocklisted
domain. Rank only cuts the list; it is never a feature.

Open hosting (learned, `lists.open_hosting` in `configs/backend.yaml`): every phishing host below an
allowlist candidate marks the child of the registrable domain that contains it as a zone
(`x.swedencentral.cloudapp.azure.com` -> `cloudapp.azure.com`, `drive.google.com`). When phishing
sits under at least `min_tenant_children` different children with at least `min_children_per_url`
children per phishing URL (one tenant per subdomain, as on `weebly.com`), the whole registrable
domain is the zone. Inside a zone the allowlist does not apply and bad URLs are listed one by one,
so `www.google.com` stays allowlisted while `drive.google.com` is judged by the model. The phishing
URLs are the blocklist's plus any `--phishing-file` (for example the corpus's
`data/processed/meta_pool.parquet`, used only for this, never blocklisted). The zones are plain
public hosting names in `open_hosting`. A host nobody has abused yet in the data is not a zone.
The extension lets an exact `urls` hit override the allowlist (one bad download on `github.com`).
