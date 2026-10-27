# Picture-only rule: false alarms and reach

Natural legitimate pages with stored HTML: 2,373; rendered offline: 2,335 (failed 38). Window 1280x720, images and styles never load, so picture sizes are a lower bound and picture counts an upper bound.

Definition: fewer than 100 readable characters, no input fields (the area rule needs a picture covering at least 10% of the window). Cells: pages that would be raised at each address-score gate (address layer: bundled allowlist, then the address model; shortener addresses are never raised).

| definition | allowlist | pages | matching | already warned | added >=0.3 | added >=0.4 | added >=0.5 | added >=0.6 | added >=0.7 | added >=0.8 |
|---|---|---|---|---|---|---|---|---|---|---|
| no text, no fields | on | 2335 | 52 | 0 | 4 | 1 | 0 | 0 | 0 | 0 |
| no text, no fields | off | 2335 | 84 | 0 | 4 | 1 | 0 | 0 | 0 | 0 |
| ... and a picture element | on | 2335 | 16 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| ... and a picture element | off | 2335 | 23 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| ... and a picture over 10% of the window (measurable offline) | on | 2335 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| ... and a picture over 10% of the window (measurable offline) | off | 2335 | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Phishing addresses (address side only; no phishing HTML in this environment)

Fixed-seed sample of 5,000 URLs from `active.txt`.
'not warned' = neither the address model nor the page path (for a page the page model cannot read) warns; the last columns are how many of those would be raised if their page were picture-only.

| urls | scored | address warns | page path warns an unreadable page | not warned | not warned and >=0.3 | not warned and >=0.4 | not warned and >=0.5 | not warned and >=0.6 | not warned and >=0.7 | not warned and >=0.8 |
|---|---|---|---|---|---|---|---|---|---|---|
| 5000 | 5000 | 3887 | 4115 | 885 | 684 | 615 | 531 | 418 | 300 | 132 |
