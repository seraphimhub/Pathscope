## Overview
Pathscope is a **high-performance asynchronous web discovery framework** built for **authorized internal security auditing**, **route intelligence**, and **surface mapping**.

Designed with a modular architecture, Pathscope combines:
- deep recursive crawling
- endpoint discovery
- secret pattern scanning
- SPA-aware extensibility
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
````

---

## Core Capabilities

*  Bounded-concurrency asynchronous crawling (fixed worker pool)
*  Deep recursive internal route traversal
*  Endpoint extraction from HTML and JavaScript
*  Secret pattern discovery without exposing secret values
*  Strict host-scope enforcement, including redirect hops
*  Optional private/loopback/metadata address guard
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

Clone repository:

```bash id="0z9wzj"
git clone https://github.com/seraphim-blip/pathscope.git
cd pathscope
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

Optional Playwright support:

```bash id="nztc95"
playwright install chromium
```

---

## Quick Start

### Interactive

```bash id="uz4w5e"
python3 cli.py
```

### CLI mode

```bash id="d9u3v0"
python3 cli.py --target https://example.com --depth 3 --workers 8
```

### Common options

```text
--target URL            target to crawl (or TARGET_URL)
--depth N               maximum crawl depth (default 2)
--workers N             concurrent request budget (default 8)
--max-pages N           hard cap on visited pages (default 1000)
--timeout SECONDS       per-request timeout (default 20)
--max-redirects N       redirect hops followed per request (default 5)
--output-dir PATH       where findings.json is written (default output)
--block-private         refuse loopback/private/link-local/metadata targets
--secrets/--no-secrets  toggle secret pattern scanning
--endpoints/--no-endpoints
--js/--no-js            toggle JavaScript analysis
--headers JSON|k:v      extra request headers
--cookie JSON|k:v       cookies to send
--config PATH           YAML config file
--quiet                 suppress the summary
--json                  emit a machine-readable summary
```

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
    "line": 12
  },
  {
    "type": "secret_pattern",
    "url": "https://example.com/config.js",
    "pattern": "token",
    "line": 4,
    "count": 1
  }
]
```

Findings are de-duplicated and never contain the matched secret value: a
secret finding records *where* the pattern appears, not what it is.

---

## Project Structure

```text
pathscope/
├── cli.py
├── requirements.txt
├── output/
├── core/
├── crawler/
└── scanners/
```

---

## CI / Quality

Workflow:

```text id="rq9tv5"
.github/workflows/ci.yml
```

Checks (Python 3.11 / 3.12 / 3.13):

* import and syntax validation
* `ruff check` and `ruff format --check`
* `mypy` on `core`, `crawler`, `scanners`
* `bandit` static security scan
* full `pytest` suite and coverage report
* secret-pattern guard over tracked files

Local equivalent:

```bash
ruff check . && ruff format --check .
python -m mypy core crawler scanners
bandit -r core crawler scanners
python -m pytest tests/ --strict-markers -q
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

*  Playwright SPA renderer
*  Redis distributed queue
*  HTML reporting
*  CSV / SARIF exporters
*  sitemap ingestion
*  plugin scanner API
*  DNS-resolution based address checks

---

## License

Licensed under **GNU Affero General Public License v3.0 (AGPLv3)**.

---

## Trademark Notice

The **Pathscope** name, logo, and branding assets are reserved.

---

## Author

Built by **Seraphim**.
