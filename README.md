# reconfirm

Attack-surface recon that grades its own findings.

[![tests](https://github.com/TamzidShovon/reconfirm/actions/workflows/tests.yml/badge.svg)](https://github.com/TamzidShovon/reconfirm/actions/workflows/tests.yml)

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

Python 3.9+ on Linux, macOS or Windows. `requests` is the only dependency,
there is nothing to build, no Go binaries, and nothing to put on `PATH`.

**Linux / macOS**

```bash
git clone https://github.com/TamzidShovon/reconfirm
cd reconfirm
python3 -m reconfirm --version
```

**Windows** (PowerShell or cmd)

```powershell
git clone https://github.com/TamzidShovon/reconfirm
cd reconfirm
python -m reconfirm --version
```

Kali, Debian, Ubuntu and most distributions already ship `python3-requests`,
so on a lot of machines the clone above is the whole installation. If that
last command reports a missing module, pick one:

```bash
sudo apt install python3-requests          # Debian, Ubuntu, Kali
```

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

```powershell
python -m venv .venv; .venv\Scripts\Activate.ps1
pip install -e .
```

On Kali and current Debian, `pip install` outside a virtualenv fails with
`externally-managed-environment` (PEP 668). That is the distribution
protecting its own Python, not a problem with this package — use `apt` or a
virtualenv rather than `--break-system-packages`.

Examples below use `python`. On Linux and macOS that is often `python3`.

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

Resolve hosts and show their addresses, with `-ip` or `--ip`:

```bash
python -m reconfirm enumerate example.com -ip
python -m reconfirm scan example.com -ip
```

`enumerate -ip` prints one tab-separated `host<TAB>addresses` line per host,
so it still pipes into `cut` and `awk`; an unresolved host shows `-`.
`scan -ip` prints a table grouped by address before probing, which makes
shared hosting obvious at a glance:

```
ADDRESSES  (3 hosts on 2 distinct address sets)
----------------------------------------------------
  192.0.2.10
      example.com
      www.example.com
  192.0.2.44
      api.example.com
```

Several names on one address usually means one box or one load balancer
behind the whole surface, which changes how much of an enumerated list is
actually separate infrastructure. With `--json`, the same mapping is written
under an `addresses` key — present only when `-ip` was passed, since an empty
mapping would read as "these hosts have no addresses" rather than "addresses
were not looked up". IPv4 and IPv6 both come back.

The lookup is free: `scan` already resolves every host to decide which are
worth probing, and `-ip` reuses that result rather than resolving twice.

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

## Maturity

Version 0.1. Here is exactly what has and has not been validated, because a
tool that argues about the difference between proven and plausible should
apply that to its own claims.

**`secrets` — validated against real-world content.** Run over the 93KB
minified jQuery bundle served by a live site, it produced zero results.
With an `AKIA…` key appended to that same bundle it confirmed the key and
redacted it; with `apiKey: "changeme"` appended it discarded the match and
named the placeholder. Minified code is where naive entropy scanners light
up, so the zero matters as much as the catch.

**`buckets` — live path exercised, never a positive.** It has run against
real S3 and GCS endpoints across 51 candidate names per target. The
ownership rule that decides confirmed-versus-discarded is unit tested, but
no run has yet found a listable bucket, so that branch has never executed
against a real one.

**`takeover` — synthetic only.** It fires correctly against a local server
serving a provider's unclaimed-instance page, and correctly discards the
same marker coming from a catch-all host. It has not yet encountered a real
dangling CNAME. Treat its detection rate as unmeasured.

Scan record so far: seven live targets, zero confirmed findings. Six of
those were deliberately-vulnerable teaching applications — Juice Shop,
Gruyere, AltoroMutual, the vulnweb family — which are built to demonstrate
SQL injection, XSS and broken authentication. None of those is something
this tool tests for, so finding nothing there is the correct result rather
than a miss. Two of them serve no JavaScript at all.

What it does not test, deliberately: injection, traversal, authentication,
access control. Confirming any of those needs an out-of-band observer or a
second authenticated session, and a check that cannot confirm its own
result does not belong in a tool built on this premise.

The reporting and host-selection layers are the hardened parts, because
running the tool against real targets is what shook the bugs out of them —
scope filtering, DNS grading, console encoding and budget allocation all
had defects that only live traffic exposed. The commit history has them.

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
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -q
```

Without a virtualenv on Debian or Kali: `sudo apt install python3-pytest`,
then `python3 -m pytest tests/ -q`.

CI runs the suite on Linux, macOS and Windows against Python 3.9, 3.11 and
3.13, and additionally starts the CLI under a cp1252 Windows console -- the
console that broke this tool's output twice.

130 tests. The checks are driven against a local HTTP server that serves the
awkward cases — a catch-all answering 200 to every path, a bucket listing whose
keys belong to someone else, a PEM header with nothing behind it — because
every rule here is a claim about behaviour against real responses, and
asserting it against mocks would only prove the mocks were built right.

## License

MIT
