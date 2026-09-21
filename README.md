# reconfirm

Attack-surface recon that grades its own findings.

Most recon tools report in two states: found, or not found. That collapses "I
proved this" and "I saw something that might be this" into one word, and the
person reading the output has to pull them apart by hand. `reconfirm` reports
in three states and refuses to claim the first one without evidence attached.

```
CONFIRMED - evidence supports the claim  (1)
--------------------------------------------
  [takeover] https://legacy.example.com
      serves GitHub Pages's unclaimed-instance page - check whether the name
      can still be registered
      | <h1>404</h1><p>There isn't a GitHub Pages site here.</p>

UNVERIFIED - plausible, proof was inconclusive  (2)
---------------------------------------------------
  [buckets] https://example-backups.s3.amazonaws.com
      publicly listable AWS S3 bucket 'example-backups', ownership unproven
      -> the bucket is listable but empty, so nothing evidences who owns it -
         confirm by hand before treating it as the target's

  [secrets] https://api.example.com
      JWT present in served script
      -> a JWT in client-side code is frequently a public demo or an expired
         fixture token - decode the payload and check its claims and expiry

1 confirmed, 2 unverified, 9 discarded  (re-run with --show-discarded to see
what was ruled out and why)
```

The nine discarded results are the point. Each one is a claim a conventional
scanner would have printed as a finding.

## Install

```bash
git clone https://github.com/TamzidShovon/reconfirm
cd reconfirm
pip install -r requirements.txt
```

Python 3.9+. The only dependency is `requests` — there are no Go binaries to
install and nothing to put on `PATH`.

## Use

Passive only. Reads certificate transparency and the Wayback Machine; sends
nothing to the target:

```bash
python -m reconfirm enumerate example.com
```

Enumerate, then probe and grade:

```bash
python -m reconfirm scan example.com --json results.json
```

Show the claims it declined to make, and why:

```bash
python -m reconfirm scan example.com --show-discarded
```

Run one check against hosts you already have:

```bash
python -m reconfirm scan example.com --hosts-from hosts.txt --checks takeover
```

Useful flags: `--delay` (gap between requests, default 0.3s), `--budget`
(max requests per host, default 200), `--max-hosts` (default 50),
`--also-scope` (additional authorised domains), `--no-wayback`.

Exit code is 1 when something was confirmed, so it composes with CI steps and
shell conditionals. Unverified results deliberately do not trip it.

## Checks

| Check | What it looks for |
|---|---|
| `takeover` | Hosts serving a provider's unclaimed-instance page (GitHub Pages, Heroku, Shopify, Fastly, Zendesk and others) |
| `secrets` | Credential material in served JavaScript, separating self-evidencing formats from contextual assignments that have to earn the claim |
| `buckets` | Publicly listable S3 and GCS buckets, with ownership evidenced by the file keys inside |

## How it decides

The reasoning is written up in [docs/CONFIDENCE.md](docs/CONFIDENCE.md), which
is the part of this repo worth reading. The short version:

- `CONFIRMED` requires evidence, enforced in the constructor rather than by
  convention.
- An inconclusive outcome resolves to `UNVERIFIED`, never `DISCARDED`. A
  timeout, a WAF block and a rate-limit all look like "no evidence found", and
  treating absent evidence as evidence of absence is how a scanner silently
  drops the one real result in a run.
- `DISCARDED` is reserved for claims positively shown to be false.

Those rules came out of auditing a larger scanner I wrote, whose vulnerability
checks were systematically over-claiming — concluding "finding" from a status
code, a byte-count delta or a substring without asking whether the response
supported it. Each rule in the doc prevents a specific false positive I hit.

## Safety rails

- **Scope is fixed before any check runs**, and matching is on label
  boundaries, so `notexample.com` is not inside `example.com`. A check that
  builds a URL outside scope raises rather than sending the request.
- **Per-host request budget** bounds what a run can generate regardless of how
  many candidates enumeration produced.
- **Rate limited** by default, with cloud-storage and archive endpoints kept on
  a separate path from target traffic.
- **Secrets are redacted** in console and JSON output.

Only run this against domains you are authorised to test.

## Tests

```bash
pip install pytest
python -m pytest tests/ -q
```

122 tests. The checks are driven against a local HTTP server that serves the
awkward cases — a catch-all answering 200 to every path, a bucket listing whose
keys belong to someone else, a PEM header with nothing behind it — because
every rule here is a claim about behaviour against real responses, and
asserting it against mocks would only prove the mocks were built right.

## License

MIT
