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
| `POST /register` | (no body) | `{"token"}` |
| `POST /feedback` | `{"domain", "kind": "false_positive"\|"missed_phish", "verdict": 0\|1\|2}` + header `X-PhishDrift-Token` | `{"ok": true}` or `{"ok": true, "duplicate": true}` |
| `GET /config` | | remote config (below) |
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
answers are 422 (invalid input), 401 (feedback without a valid token), 404 (lists not built) and
429 (rate limit or daily feedback cap, with `Retry-After`).
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
  `domain`, `kind`, `verdict`, `timestamp` (UTC) and `reporter`. No IP address, user agent or token
  is stored; `reporter` is a one-way key per install (see below).
- Logs name the exception type only, never the domain or any request body.
- A TLS handshake is made only when every address the name resolves to is globally routable, so
  the service cannot be used to probe internal hosts. (A DNS rebinding race remains possible; the
  probe sends no data beyond the handshake.) If the resolver itself is down (a control lookup
  fails), DNS facts are `null`, not "does not resolve".

## Feedback tokens and limits

`POST /register` issues a per-install token with no user data (`backend/feedback_auth.py`):
`<install_id>.<mac>`, where `install_id` is 16 random bytes in urlsafe base64 without padding
(22 characters) and `mac` is HMAC-SHA256(secret, install_id) in urlsafe base64, first 22
characters. The server keeps no list of tokens; it checks the MAC (`hmac.compare_digest`). The
secret is the environment variable named by `feedback.secret_env` (default
`PHISHDRIFT_FEEDBACK_SECRET`, at least 16 characters); if that is unset, a random secret is created
once in `data/feedback/.secret` (mode 0600) so tokens survive restarts. Changing the secret
invalidates every token. The extension registers once and keeps the token.

`/feedback` needs the token in `X-PhishDrift-Token` (missing or invalid: 401). Limits, all in
`configs/backend.yaml` under `feedback`:

- `/register`: its own token bucket per client address (`register_rate`, 3 then one per hour).
- `/feedback`: the shared per-address bucket (`rate_limit`) plus at most
  `max_per_install_per_day` (20) stored reports per install per UTC day; after that 429 with
  `Retry-After` until 00:00 UTC.
- The same install + domain + kind within `dedupe_window_s` (one day) is answered
  `{"ok": true, "duplicate": true}` and not stored again; duplicates do not count towards the cap.
- Per-install counters live in memory, capped at `max_installs` entries (least recently used
  dropped), so they reset on restart.

Stored `reporter` = first 16 hex characters of sha256(install_id): reviewers can count distinct
reporters, but the key cannot be turned back into a token.

## Remote config

`GET /config` (rate-limited like the lists) serves `configs/remote_config.yaml`, so thresholds and
emergency false-positive fixes change without a new extension release (`backend/remote_config.py`;
the file path is `remote_config.path`). Keys:

- `version`: integer >= 1, bumped on every change.
- `thresholds`: `address` and `page`, each `suspicious` and `dangerous`: a float in
  `[remote_config.bounds.min, max]` (0.5, 0.9999) or `null` for the threshold bundled with the
  model; `suspicious < dangerous` when both are set.
- `never_warn`: registrable domains (public-suffix-only, no subdomains), never a hosting platform
  from `configs/platforms.yaml`, at most `remote_config.max_never_warn` (200), no duplicates. Only
  after a reviewed false-positive report.
- `list_sync_minutes`: integer in [15, 1440] (default 60).
- `notes`: ASCII text.

The file is validated as a whole when the app starts; any problem stops start-up with one
ValueError listing every problem, so a partly valid config is never served. Edits take effect on
restart. The body is canonical JSON (`json.dumps(sort_keys=True, separators=(",", ":"))`) with a
`sha256` field: the hex digest of the canonical JSON of the document without `sha256`. A client
verifies it by removing `sha256`, re-serialising with sorted keys and no spaces, and hashing.

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

## Safe list sync (signatures, hashes, deltas)

- **Hash sizes:** blocklist entries are 8-byte sha256 prefixes, allowlist entries 16 bytes
  (`lists.prefix_bytes`, `lists.allow_prefix_bytes`). With 6 bytes a domain whose hash collides
  with a trusted one could be found in about 2^48 tries and registered; 16 bytes rules that out.
- **Blocklist URL keys:** the extension looks up every expression of `list_url_expressions`
  (host and up to four parent suffixes, times no path, the first 1-3 path segments, the whole path
  and the path with query). The builder (`block_url_keys`) lists each bad URL on a shared host by
  its exact key, its tenant (a whole tenant host such as `x.web.app` only where the data shows one
  tenant per subdomain; `telegra.ph/<page>` or `sites.google.com/view/<site>` on learned
  path-tenant hosts) and, on a tenant or when a path segment is 16+ characters, without its query.
  So a changed per-victim token no longer dodges the list, and no allowlisted site, platform or
  zone is ever listed whole.
- **Integrity:** `manifest.json` carries the sha256 of the exact `blocklist.json` and
  `allowlist.json` bytes and, when a key exists, an ECDSA P-256 `signature` over the manifest
  without that field. `/config` is signed the same way. Create the key once on the backend
  machine with `python -m backend make-signing-key` (writes the private key to
  `lists.signing_key`, mode 0600, and the public key to `extension/src/lists_pubkey.js`), then
  rebuild the extension. While `LIST_PUBKEY` is null the extension still checks the hashes and the
  sanity limits but not signatures.
- **Sanity limits** (`extension/src/listsync.js`): a synced allowlist must keep at least 80% of the
  larger of the stored and bundled ones; a blocklist of 100+ entries may not lose more than half;
  none of the 1,000 most visited sites (the bundled allowlist's `top`) may be blocked by domain,
  and 95% of them must stay allowlisted. A rejected update leaves the stored lists in place; the
  outcome is in `chrome.storage.local.listSync`.
- **Hourly deltas:** each build is kept in `<out_dir>/history/` (48 builds). The extension syncs
  every 60 minutes (remote config `list_sync_minutes`, 15-1440) and asks
  `GET /lists/delta?from=<version>` first; it rebuilds the files, checks their sha256 against the
  signed manifest, and falls back to the full download on a 404 or mismatch. Cached verdicts are
  cleared after any list or config change.
- **Rate limits:** `/lists/*` and `/config` have their own bucket (`lists.rate`), so a burst on
  `/feedback` or `/score` cannot stop list syncs.
