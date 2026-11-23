# Pathscope

**Repository:** https://github.com/seraphimhub/Pathscope

## Overview
Pathscope is a **high-performance asynchronous web discovery framework** built for **authorized internal security auditing**, **route intelligence**, and **surface mapping**.

Designed with a modular architecture, Pathscope combines:
- deep recursive crawling
- endpoint discovery
- secret pattern scanning
- JavaScript-aware endpoint extraction
- structured JSON output

It is optimized for modern engineering and security teams working with complex internal web estates.

---

## Architecture
```mermaid
flowchart TD
    A[CLI Entry] --> B[Crawl Engine]
    B --> C[Async Fetcher]
    B --> D[HTML Parser]
    D --> E[Link Extractor]
    B --> F[Scanner Modules]
    F --> G[Endpoint Scanner]
    F --> H[Secret Scanner]
    F --> I[Future Plugins]
    B --> J[JSON Output]
```

---

## Core Capabilities

*  Bounded-concurrency asynchronous crawling (fixed worker pool)
*  Deep recursive internal route traversal
*  Endpoint extraction from HTML and JavaScript
*  Secret pattern discovery without exposing secret values
*  Strict host-scope enforcement, including every redirect hop
*  Optional private/loopback/metadata address guard enforced at DNS resolution
*  Redirect chain following with loop detection and hop limits
*  Per-URL error isolation (one failure never aborts the scan)
*  Response size caps and non-text content rejection
*  Structured, de-duplicated JSON findings

---

## Terminal Preview

```bash id="83x5dm"
$ python3 cli.py --target https://example.com --depth 3 --workers 8

███████╗███████╗██████╗  █████╗ ██████╗ ██╗  ██╗██╗███╗   ███╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║  ██║██║████╗ ████║
███████╗█████╗  ██████╔╝███████║██████╔╝███████║██║██╔████╔██║
╚════██║██╔══╝  ██╔══██╗██╔══██║██╔═══╝ ██╔══██║██║██║╚██╔╝██║
███████║███████╗██║  ██║██║  ██║██║     ██║  ██║██║██║ ╚═╝ ██║
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝

[0] https://example.com
[1] https://example.com/search
[1] https://example.com/about
[2] https://example.com/preferences
```

---

## Installation

Requirements: Python 3.11 or newer (CI covers 3.11, 3.12 and 3.13).

Clone the repository:

```bash id="0z9wzj"
git clone https://github.com/seraphimhub/Pathscope.git
cd Pathscope
```

Create virtual environment:

```bash id="zt4u0e"
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash id="o8e5j1"
pip install -r requirements.txt
```

Playwright is pinned in `requirements.txt` for the planned SPA renderer; the
current crawler is HTTP-only and never needs a browser. Installing Chromium is
only required when that renderer lands:

```bash id="nztc95"
playwright install chromium
```

---

## Quick Start

### Via environment

```bash id="uz4w5e"
TARGET_URL=https://example.com python3 cli.py --depth 2
```

### CLI mode

```bash id="d9u3v0"
python3 cli.py --target https://example.com --depth 3 --workers 8
```

### Common options

```text
--target URL              target to crawl (or the TARGET_URL env var)
--depth N                 maximum crawl depth (default 2)
--workers N               concurrent request budget (default 8)
--max-pages N             hard cap on visited pages (default 1000)
--timeout SECONDS         per-request timeout (default 20)
--max-redirects N         redirect hops followed per request (default 5)
--output-dir PATH         where findings.json is written (default "output",
                          or PATHSCOPE_OUTPUT_DIR)
--block-private           refuse loopback/private/link-local/metadata targets
--allow-private           permit private targets (default)
--secrets/--no-secrets    toggle secret pattern scanning (default on)
--endpoints/--no-endpoints
                          toggle endpoint discovery (default on)
--js/--no-js              toggle JavaScript analysis (default on)
--headers JSON|k:v        additional request headers
--cookie JSON|k:v         cookies to send
--api VALUE               API key or JSON token for auth
--auth VALUE              auth profile or token
--config PATH             YAML config file
--quiet                   suppress the summary
--json                    emit a machine-readable summary to stdout
```

Exit codes: `0` for a completed scan (and for a clean Ctrl-C), `2` for an
invalid target, a rejected configuration, or a policy refusal such as
`--block-private` on a private address.

---

## Output

Findings are exported to:

```text id="ywus6g"
output/findings.json
```

Example:

```json id="x07m2m"
[
  {
    "type": "endpoint",
    "url": "https://example.com/app.js",
    "endpoint": "/api/v1/users",
    "category": "path",
    "evidence": "/api/v1/users",
    "line": 12
  },
  {
    "type": "secret_pattern",
    "url": "https://example.com/config.js",
    "pattern": "token",
    "category": "token",
    "evidence": "var token = \"********\";",
    "line": 4,
    "count": 1
  }
]
```

Every finding carries `evidence`, `category`, and `line` so a reviewer can
check it without re-fetching the page. Findings are de-duplicated and never
contain the matched secret value: quoted literals and long unquoted values in
`evidence` are masked with `*`. A match is a pattern occurrence only — Pathscope
does not verify that a credential is live and never uses one.

`--json` prints a separate machine-readable scan summary (pages, requests,
successful fetches, errors, redirects, elapsed time) to stdout.

---

## Scope and SSRF protection

One policy module (`core/security.py`) is used by the CLI, the engine, the
fetcher, and every URL source (links, JavaScript, redirects):

* hosts are canonicalized (IDNA, trailing dot, default port, IPv6 brackets)
  before comparison, so `https://example.com./` cannot slip past scope checks;
* the scope is an exact host match (with the default port normalized), so
  unrelated hosts, other ports, and subdomains such as `admin.example.com` are
  dropped even when reachable — the policy supports an explicit subdomain
  opt-in, but the crawler does not enable it;
* redirect `Location` headers are re-checked hop by hop and never trusted
  because the original host passed;
* with `--block-private`, address checks run **inside the resolver handed to
  the HTTP transport**. Every address in the DNS answer (IPv4, IPv6,
  IPv4-mapped, loopback, private, link-local, unspecified, multicast) is
  rejected if any one is non-public, and the connector dials the exact
  addresses that were validated. A second lookup between check and connect
  (DNS rebinding) therefore cannot swap in a private address.

Private targets remain allowed by default (local lab testing); `--block-private`
is opt-in. Scope rules apply regardless of that setting.

---

## Configuration

`--config pathscope.yaml` accepts a mapping of any CLI option:

```yaml
target: https://example.com
depth: 3
workers: 8
timeout: 10
block_private: true
```

Precedence is explicit: command-line flags (when actually typed) override the
config file, which overrides defaults. Config files are validated before a scan
starts — unknown keys are kept for forward compatibility, but wrong types,
out-of-range numbers, unreadable YAML, and a non-mapping root are rejected with
exit code 2 instead of silently falling back to defaults. For security-relevant
keys such as `block_private`, the value you actually pass on the command line
wins over the file, and the file wins over the built-in default; nothing is
applied silently.

---

## Benchmarking

The crawler ships with a reproducible local harness:

```bash
python -m benchmarks.bench_crawler --scenario low-latency --runs 3
python -m benchmarks.bench_crawler --scenario all --levels 1,2,4,8,16 --runs 5
```

Scenarios cover low and high latency, a slow server, dropped connections,
large responses, and pages full of duplicate links. Each level is run several
times; the report separates graph size, responses, attempts, HTTP requests,
successful fetches, transport errors, elapsed time, throughput, and the
maximum concurrency actually observed by the server, and prints best/median/min
throughput plus the spread. These are single-machine measurements — compare
levels within one run rather than quoting absolute numbers.

---

## Testing

```bash
python -m pytest tests/ --strict-markers -q
```

Beyond unit and integration tests, the suite includes:

* `tests/security/test_ssrf_and_scope_bypass.py` — address classification,
  canonicalization tricks, and connector-level proof that a private DNS answer
  is never dialed;
* `tests/unit/test_discovery_accuracy.py` — precision/recall against a labelled
  fixture (`tests/fixtures/discovery/`), including commented-out examples that
  must stay unmatched and relative strings that are expected negatives;
* `tests/unit/test_config_validation.py` — malformed, missing, mistyped, and
  out-of-range configuration plus CLI-over-config precedence;
* `tests/unit/test_benchmark_harness.py` — sanity checks on benchmark metrics.

---

## Project Structure

```text
Pathscope/
├── cli.py              # Click entry point, config merging, summaries
├── core/               # config, scope/address policy, DNS resolver, models
├── crawler/            # engine, fetcher, HTML/JS parser
├── scanners/           # endpoint and secret-pattern scanners
├── benchmarks/         # reproducible crawler benchmark harness
├── tests/              # unit, integration, security tests and fixtures
├── output/             # default findings.json destination
├── requirements.txt
└── .github/workflows/ci.yml
```

---

## CI / Quality

Workflow:

```text id="rq9tv5"
.github/workflows/ci.yml
```

Jobs:

* `quality` on Python 3.11, 3.12 and 3.13 — import validation, `ruff check .`,
  `ruff format --check .`, `mypy` on `core`, `crawler`, `scanners`, `bandit`
  static scan, the full `pytest` suite, and a coverage report
* `smoke` — boots the CLI and verifies the public surface still imports and runs
* a guard that rejects known secret patterns (AWS key shape, fake test tokens)
  in tracked files

Local equivalent:

```bash
ruff check . && ruff format --check .
python -m mypy core crawler scanners
bandit -r core crawler scanners -iii
python -m pytest tests/ --strict-markers -q
python -m pytest tests/ --cov=core --cov=crawler --cov=scanners --cov-report=term-missing
python -m benchmarks.bench_crawler --scenario low-latency --runs 3
```

---

## Security & Responsible Use

Pathscope must only be used for:

* systems you own
* internal engineering audits
* explicitly authorized environments
* approved security assessments

Always maintain:

* safe concurrency
* documented authorization
* operational awareness
* production-safe rate controls

---

## Roadmap

Planned work, not implemented yet:

*  rate limiting, `Retry-After` handling and circuit breaking
*  authorization metadata (`--authorized-by`) recorded in reports
*  versioned report schema with stable finding IDs and scan diffing
*  SARIF 2.1.0, CSV and self-contained HTML exporters
*  plugin scanner API with per-plugin isolation
*  sitemap.xml / robots.txt ingestion and source-map analysis
*  playbook-driven SPA rendering with the same scope enforcement
*  distributed queue behind the existing in-memory interface

---

## License

Licensed under **GNU Affero General Public License v3.0 (AGPLv3)**.

---

## Trademark Notice

The **Pathscope** name, logo, and branding assets are reserved.

---

## Author

Built and maintained by **[seraphimhub](https://github.com/seraphimhub)**.
