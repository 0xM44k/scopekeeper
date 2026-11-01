# Changelog

## 0.3.0 — 2026-11
- Optional HMAC-SHA256 sealing of log entries: `keygen`, `--key-file` / `SCOPEKEEPER_KEY_FILE` on `check --log`, `run`, `note`, `verify` and `report`. A whole-file rewrite by someone without the key now fails verification.
- `verify` reports how many entries are sealed and whether the seals were checked.
- 9 new tests (33 total).

## 0.2.0 — 2026-10
Added `--json` output to `check` and `verify`, and `--format json` to `report`, so results can feed a CI gate without scraping text.

## 0.1.0 — 2026-10
Initial release. See the README for features and limits.
