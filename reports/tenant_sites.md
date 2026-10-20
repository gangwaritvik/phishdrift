# Popular tenant sites on hosting platforms (allowlist by exact host)

Problem: `stitch.withgoogle.com` (Google's own tool) was called suspicious. `withgoogle.com` is on the
hosting-platform list taken from the public suffix list (`configs/platforms.yaml`), so the allowlist is
skipped for every host under it, and the address model alone scored the long project id at 0.902
(warn line 0.850).

Fix (`backend/lists.py` `tenant_sites`, `lists.tenant_sites` in `configs/backend.yaml`): a platform's
registrable domain stays off the allowlist, but a tenant site that is itself popular is allowlisted by
its exact host. Popularity is host-level (CrUX top origins, 2026-09, rank <= 50,000). A host is left out
when phishing was seen on it or below it (Phishing.Database ACTIVE, the PC's feeds, the corpus), when it is
not its own private-suffix site (`s3.amazonaws.com`), when it lies in a learned open-hosting zone, or when
its domain is a shortener. The extension looks the host up when the address is on a platform
(`extension/src/lists.js`); an exact listed phishing URL still overrides it.

Measured on 2026-10-20 (`python -m backend build-lists`-equivalent applied to the bundled list; address
layer + bundled allowlist via `js/bench/verdicts.mjs`):

| check | before | after |
|---|---|---|
| popular tenant homepages (137 hosts, all legitimate) flagged | 60 (45 suspicious, 15 dangerous) | 0 |
| phishing URLs on platform hosts (3,000 random from 177,757 in ACTIVE) warned | 2,740 | 2,740 |
| natural legitimate pages (2,555, 562 sites) flagged | 72 | 72 |

Phishing let through, held out from the evidence that picks the hosts: OpenPhish (1,800 URLs) on kept
tenants 0; a random half of ACTIVE (394,527 URLs) vs hosts chosen from the other half 0. With no phishing
filter the only popular tenant that carries phishing is `storage.googleapis.com` (252 ACTIVE URLs), which
the filter drops. Limit: a popular tenant that is abused tomorrow stays trusted until the next list
build; an exact listed URL, the page model (login fields) and the shortener/zone rules still apply.
Rank only cuts the list; it is never a model feature.
