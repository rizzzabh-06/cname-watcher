# cname-watch

`cname-watch` is a defensive subdomain takeover scanner. It resolves CNAME
chains for a list of subdomains and flags records that point to resources which
no longer exist or are still unclaimed at a cloud provider.

It currently fingerprints:

- **AWS S3** — `NoSuchBucket`
- **GitHub Pages** — "There isn't a GitHub Pages site here"
- **Vercel** — `DEPLOYMENT_NOT_FOUND`
- **Azure App Service** — "404 Web Site not found"

It detects both classic dangling CNAMEs (the target returns `NXDOMAIN` or has no
A/AAAA records) and CNAMEs to provider resources that resolve but report that
the resource is unclaimed.

> **Authorisation:** only scan domains you own or have explicit permission to
> test. The tool performs DNS lookups and HTTP `GET` requests only; it never
> attempts to register, claim, or modify a resource.

## Features

- Follows and reports every hop in a CNAME chain
- Distinguishes input `NXDOMAIN` from a dangling CNAME target
- Two-factor HTTP fingerprints: provider target **and** status/body must match
- Probes the custom hostname first, then the CNAME target as a fallback when
  the custom hostname is unreachable
- Concurrent scans with per-operation DNS and HTTP timeouts
- Table, JSON, and CSV output
- CI-friendly exit codes
- Custom fingerprint rules via JSON
- No shell commands or browser automation required

## Install

Requires Python 3.10 or newer.

```bash
git clone https://github.com/rizzzabh-06/cname-watcher.git
cd cname-watcher
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Or install it as an isolated CLI:

```bash
pipx install .
```

The runtime dependencies are [`dnspython`](https://www.dnspython.org/) and
[`httpx`](https://www.python-httpx.org/).

## Quick start

```bash
# Scan hosts passed directly
cname-watch www.example.com blog.example.com

# Scan a list
cname-watch -l examples/domains.txt

# Pipe domains on stdin and emit JSON
cat subdomains.txt | cname-watch --format json

# Write a CSV report
cname-watch -l subdomains.txt --format csv -o findings.csv

# Show clean and not-found hosts too
cname-watch -l subdomains.txt --all

# Explain each CNAME chain and HTTP attempt
cname-watch -l subdomains.txt --verbose
```

Inputs can be bare hostnames, URLs, wildcard prefixes, trailing-dot FQDNs, or
`host:port` forms. Duplicates and full-line/inline `#` comments are ignored.
Invalid entries are reported as warnings and skipped.

### Example output

```text
STATUS     DOMAIN              CNAME TARGET                PROVIDER      EVIDENCE
---------  ------------------  --------------------------  ------------  ------------------------------------------------------------------------------------
DANGLING   blog.example.com    old-blog.github.io          GitHub Pages  CNAME target old-blog.github.io does not resolve (NXDOMAIN)
CLAIMABLE  assets.example.com  acme-demo.s3.amazonaws.com  Amazon S3     Amazon S3 reports the resource as unclaimed (HTTP 404 at http://assets.example.com/)

Scanned 3 domain(s): 2 candidate(s) (1 dangling, 1 claimable), 1 clean, 0 not found, 0 error(s).
```

The third host was clean, so it is hidden by default. Use `--all` to display
every scanned host, including clean and non-existent names.

## Verdicts

| Verdict | Candidate? | Meaning |
| --- | --- | --- |
| `DANGLING` | yes | The final CNAME target is `NXDOMAIN` or has no A/AAAA records. |
| `CLAIMABLE` | yes | The target resolves, but the provider says the resource is unclaimed. |
| `CLEAN` | no | The CNAME resolves normally, or the input has no CNAME. |
| `NOT_FOUND` | no | The input itself does not exist or has no addresses (not a dangling CNAME). |
| `ERROR` | no | DNS or another scan step failed for this host. |

### Reason codes

| Reason | Verdict | Meaning |
| --- | --- | --- |
| `cname-nxdomain` | `DANGLING` | The CNAME target no longer exists. |
| `cname-no-address` | `DANGLING` | The CNAME target exists but has no A/AAAA records. |
| `provider-fingerprint` | `CLAIMABLE` | The provider's unclaimed-resource response matched. |
| `resolved` | `CLEAN` | The CNAME target resolves and no fingerprint matched. |
| `no-cname` | `CLEAN` | The input has no CNAME record. |
| `input-nxdomain` | `NOT_FOUND` | The input name itself does not exist. |
| `input-no-address` | `NOT_FOUND` | The input name has no A/AAAA records and no CNAME. |
| `dns-error` | `ERROR` | A DNS lookup failed. |
| `internal-error` | `ERROR` | An unexpected error occurred while scanning the host. |

## How it works

1. **Normalise input.** URLs, ports, wildcards, Unicode names (IDNA), and
   trailing dots are converted to ASCII hostnames.
2. **Walk the CNAME chain.** Each hop is resolved explicitly so the terminal
   name and failure point can be reported. Chain loops and chains longer than
   `--max-depth` are errors.
3. **Check terminal existence.** `A` and `AAAA` records are queried for the
   terminal name. `NXDOMAIN` or empty address sets produce a `DANGLING` result
   without making any HTTP request.
4. **Infer the provider.** The terminal CNAME target is matched against the
   built-in rule patterns (for example `*.github.io`).
5. **Probe carefully.** For a known provider, the tool requests
   `http://subdomain/` and then `https://subdomain/` without following
   redirects. If the custom hostname cannot be reached at all, it probes the
   terminal target directly as a fallback.
6. **Fingerprint.** A rule matches only when the CNAME target, HTTP status code,
   and response body all match. This avoids reporting every generic 404 page as
   a takeover.
7. **Report.** Results preserve input order and can be rendered as a table,
   JSON, or CSV.

Plain HTTP is tried first because an unclaimed custom domain often has no
certificate for its hostname yet. TLS verification is disabled by default for
the same reason; use `--verify-tls` if your targets all have valid
certificates. Redirects are deliberately not followed, so a probe cannot leave
the hostname being checked.

## Built-in fingerprints

| Provider | Terminal CNAME patterns | Expected response |
| --- | --- | --- |
| Amazon S3 | `*.s3.amazonaws.com`, `*.s3.*.amazonaws.com`, `*.s3-*.amazonaws.com`, plus `.amazonaws.com.cn` variants | HTTP 404 with `NoSuchBucket` or "The specified bucket does not exist" |
| GitHub Pages | `*.github.io` | HTTP 404 with "There isn't a GitHub Pages site here" |
| Vercel | `*.vercel.app`, `*.now.sh`, `cname.vercel-dns.com`, `*.vercel-dns.com`, `cname.vercel-dns-*.com` | HTTP 404 with `DEPLOYMENT_NOT_FOUND` or "The deployment could not be found" |
| Azure App Service | `*.azurewebsites.net`, `*.cloudapp.net`, `*.cloudapp.azure.com`, `*.trafficmanager.net` | HTTP 404 with "404 Web Site not found", "This site is not configured", or "Web app not found" |

Provider error pages change over time. The rules live in
[`src/cname_watch/rules.py`](src/cname_watch/rules.py) and can be extended or
overridden without changing the scanner.

> Azure app names are usually released by deleting the app, which also removes
> its DNS record. Those cases are caught earlier as `cname-nxdomain`; the Azure
> HTTP rule covers responses where the name still resolves.

## Custom rules

Pass a JSON file with `--rules`. The file can be a list of rules or an object
with a `rules` list:

```json
{
  "rules": [
    {
      "id": "example-cloud",
      "provider": "Example Cloud",
      "cname": ["*.example-cloud.net", "*.apps.example-cloud.net"],
      "status": [404],
      "body": ["this application has not been claimed", "app_not_found"],
      "description": "The Example Cloud app referenced by the CNAME does not exist."
    }
  ]
}
```

| Field | Required | Description |
| --- | --- | --- |
| `id` | yes | Lowercase slug (`[a-z0-9][a-z0-9._-]*`). An existing id replaces that built-in rule. |
| `provider` | yes | Display name for reports. |
| `cname` | yes | Non-empty list of glob patterns matched against the terminal CNAME target. |
| `status` | no | List of HTTP status codes. An empty list means any status. |
| `body` | yes | Non-empty list of case-insensitive substrings sought in the response body. |
| `description` | no | Human-readable explanation. |

A rule only applies when its CNAME pattern matches the terminal target. See
[`examples/rules.example.json`](examples/rules.example.json) for a starting
point.

## CLI reference

```text
cname-watch [DOMAIN ...] [options]
```

| Option | Description |
| --- | --- |
| `-l, --list FILE` | Read domains from `FILE` (use `-` for stdin). |
| `-f, --format {table,json,csv}` | Output format (default: `table`). |
| `-o, --output FILE` | Write output to `FILE` (use `-` for stdout). |
| `--timeout SECONDS` | DNS total and HTTP per-operation timeout (default: `5`). |
| `--concurrency N` | Number of domains scanned concurrently (default: `20`). |
| `--max-depth N` | Maximum CNAME chain length (default: `10`). |
| `--nameserver IP` | Use a specific DNS resolver; repeatable. |
| `--rules FILE` | Load custom fingerprint rules. |
| `--no-probe` | Skip HTTP probing and only analyse DNS. |
| `--https-only` | Do not make plain-HTTP probes. |
| `--verify-tls` | Verify TLS certificates (off by default). |
| `--all` | Show clean and not-found hosts in the table. |
| `-v, --verbose` | Show CNAME chains, terminal state, addresses, and probe attempts. |
| `--no-color` | Disable ANSI colours. |
| `-q, --quiet` | Suppress the summary line. |
| `--version` | Print the version and exit. |

Run `cname-watch --help` for the full help text.

## JSON output

`--format json` always includes every scanned host, regardless of `--all`:

```json
{
  "tool": "cname-watch",
  "version": "0.1.0",
  "generated_at": "2026-11-20T12:00:00+00:00",
  "summary": {
    "total": 1,
    "candidates": 1,
    "dangling": 1,
    "claimable": 0,
    "clean": 0,
    "not_found": 0,
    "errors": 0
  },
  "results": [
    {
      "domain": "blog.example.com",
      "verdict": "dangling",
      "candidate": true,
      "reason": "cname-nxdomain",
      "provider": "GitHub Pages",
      "resolution": {
        "query": "blog.example.com",
        "chain": [
          {
            "owner": "blog.example.com",
            "target": "old-blog.github.io"
          }
        ],
        "terminal": "old-blog.github.io",
        "state": "nxdomain",
        "addresses": [],
        "error": null
      },
      "http": null,
      "detail": "CNAME target old-blog.github.io does not resolve (NXDOMAIN)"
    }
  ]
}
```

When a provider fingerprint matches, `http.match` contains the `rule_id`,
`provider`, `matched_text`, `url`, `status_code`, and a short `snippet`; the
`http.attempts` array records the individual probes without storing full
response bodies.

CSV columns are: `domain`, `verdict`, `reason`, `provider`, `terminal`,
`cname_chain`, `terminal_state`, `http_status`, `evidence`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed with no takeover candidates. |
| `1` | At least one `DANGLING` or `CLAIMABLE` result was found. |
| `2` | Invalid arguments, unreadable input, or an invalid rules file. |
| `130` | Interrupted with Ctrl-C. |

This makes the tool usable in CI:

```yaml
- name: Check for subdomain takeover candidates
  run: cname-watch -l subdomains.txt --format json -o cname-report.json
```

The step fails when a candidate is found. Use `--no-probe` if you want a
DNS-only check, or append `|| true` if the report is informational.

## Limitations

- **Fingerprints drift.** Provider error pages and endpoint names change.
  Validate candidates manually and update the rules when needed.
- **A dangling record is a signal, not proof.** Some providers reserve names or
  prevent re-registration; exploitation depends on the provider's behaviour.
- **CNAMEs only.** Dangling `A`/`AAAA` records, NS delegations, and other
  takeover classes are out of scope.
- **Wildcard DNS.** Wildcard records can produce false positives for names that
  were never individually registered. Confirm findings before reporting them.
- **No JavaScript rendering.** Detection is based on raw HTTP responses.
- **Redirects are not followed.** This is intentional, to keep probes scoped to
  the hostname under test.
- **TLS verification is off by default.** Unclaimed custom domains frequently
  lack certificates. Use `--verify-tls` when appropriate.
- **Rate limiting.** High concurrency can trigger provider rate limits. Lower
  `--concurrency` if you see errors or timeouts.

The fingerprints are inspired by the public
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
project and provider documentation.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest
ruff check src tests
ruff format --check src tests
```

The test suite uses fake DNS resolvers and `httpx.MockTransport`; it does not
make network requests.

```text
src/cname_watch/
  cli.py          # argument parsing, input loading, output selection
  dns_chain.py    # CNAME chain walking and terminal DNS state
  input.py        # domain normalisation and list parsing
  models.py       # result and evidence data types
  probe.py        # bounded HTTP(S) requests and evidence snippets
  report.py       # table, JSON, and CSV renderers
  rules.py        # built-in fingerprints and custom rule loading
  scanner.py      # scan orchestration and verdict logic
tests/            # unit and integration tests
examples/         # sample domain list and custom rules
```

## License

MIT. See [`LICENSE`](LICENSE).
