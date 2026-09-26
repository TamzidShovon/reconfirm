# Why this tool grades itself

Most recon tooling reports in two states: found, or not found. That collapses
two very different situations — "I proved this" and "I saw something that might
be this but could not prove it" — into one word, and leaves the reader no way
to pull them apart. Nearly all the time spent triaging scanner output goes to
undoing that collapse by hand.

The rules below exist because I ran into each of them. They came out of
auditing a larger scanner I had written, where the vulnerability checks were
systematically over-claiming: concluding "finding" from a status code, a
byte-count delta, or a substring, without ever asking whether the response
supported the claim. This tool is the recon half of that work, rebuilt around
the conclusion.

## The three states

| State | Meaning | What to do with it |
|---|---|---|
| `CONFIRMED` | An independent check produced evidence for the claim. | Act on it. The evidence is attached. |
| `UNVERIFIED` | The claim is plausible; the check meant to prove it was inconclusive. | Look by hand. Do not report it as a finding. |
| `DISCARDED` | A check actively disproved the claim. | Ignore, unless auditing the tool. |

`CONFIRMED` requires evidence, and `Result` enforces that in its constructor
rather than trusting the check that built it. A confirmed claim with nothing
behind it is the exact failure this design exists to prevent, so a check that
forgets to attach evidence fails in its own tests instead of quietly emitting
an unsupported claim.

## The asymmetry

**An inconclusive outcome always resolves to `UNVERIFIED`, never `DISCARDED`.**

A timeout, a connection reset, a WAF block and a rate-limit all present as "no
evidence found". Treating absent evidence as evidence of absence is how a
scanner silently drops the one real result in a run, and a wrongly discarded
finding is invisible in a way a wrongly kept one is not — nobody reviews the
discard pile.

`DISCARDED` is reserved for claims positively shown to be false: a value that
matched a placeholder, a response byte-identical to the host's catch-all page,
a bucket whose file keys belong to a different company.

`reconfirm` never assumes a check ran. When a source fails, it says so in a
note rather than presenting a short list as though it were complete:

```
  5 hostnames from crt.sh
  0 hostnames from web.archive.org
note: web.archive.org unreachable (ReadTimeout: ...)
```

An enumeration that half-ran and admits it is more useful than one that does
not.

## The rules, and the false positive each one prevents

| Rule | The false positive it prevents |
|---|---|
| Probe a path that cannot exist first; compare every later response against it | SPAs, CDNs and WAFs that answer 200 to every path. Against those hosts, any check phrased as "did this return 200?" reports everything it tried. |
| Match takeover markers in the first 4KB only | `No such app` appearing 200KB into a bundled application script is a coincidence, not a provider's error page. |
| Judge the captured value, never the surrounding text | `apiKey = ""` matched as a whole string looks like a 12-character secret. The value is empty. |
| Contextual secret matches must clear a placeholder list and a 3.0 bits/char entropy floor | `changeme`, `your_api_key_here`, `/api/v1/users` — all match `apiKey\s*[:=]\s*"..."`, none are credentials. |
| Separate structural patterns from contextual ones | `AKIA…` identifies a credential by a format nothing else uses; `secret: "…"` only identifies an assignment that might hold one. Treating them alike is why generic scanners over-report. |
| A PEM header needs base64 key material behind it | A bare `-----BEGIN PRIVATE KEY-----` matches key-handling code and masked-display components. One real case: a bundled chunk using it as a `split()` fallback. |
| Bucket ownership must be evidenced by file keys | Bucket namespaces are global and flat. `dashboard`, `files` and `data` were claimed years ago by unrelated parties. Reporting someone else's open bucket is worse than reporting nothing. |
| An empty listable bucket is `UNVERIFIED`, not `DISCARDED` | Nothing has been shown either way. This is the asymmetry biting on a case where it would be convenient to ignore it. |
| Skip generic labels when deriving an organisation name | `dashboard.example.com` yields the candidate `dashboard`, a bucket somebody already owns. |
| Scope matches on label boundaries | `notexample.com` ends with `example.com` as a plain string. Suffix matching without the dot is how a tool wanders onto a lookalike domain. |
| Secrets are redacted in output | A tool whose report file is a list of live credentials has made the problem worse. |

## What this tool does not claim

- **It does not confirm a takeover is possible.** A fingerprint match proves the
  provider serves its unclaimed-instance page. Whether the name can still be
  registered is a separate, manual step, and the summary says so.
- **It does not prove a host is live because it appeared in a log.** A
  certificate transparency entry proves a certificate was issued. Sources
  return candidates; deciding what is actually there is the checks' job.
- **It does not test for exploitable vulnerabilities.** No injection, no
  traversal, no authentication testing. Those need either an out-of-band
  observer or a second authenticated session to confirm, and a check that
  cannot confirm its own result does not belong in a tool built on this
  premise.

## Auditing the tool

`--show-discarded` prints every claim `reconfirm` declined to make, with the
reason:

```
DISCARDED - actively disproved  (2)
  [secrets] https://example.com/app.js
      API key assignment matched but rejected
      -> the value 'your_api_key_here' is a known placeholder, not a credential

  [buckets] https://example-assets.s3.amazonaws.com
      publicly listable AWS S3 bucket 'example-assets' belongs to someone else
      -> the bucket is listable but its file keys reference neither
         'example.com' nor 'example' - it belongs to an unrelated party
```

If a rule is wrong, this is where you see it, and `tests/` is where you pin the
correction.
