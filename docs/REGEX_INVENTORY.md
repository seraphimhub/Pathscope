# Regex inventory and parser safety (Phase 2)

Every regular expression used on runtime input is listed here. Inputs come from
a scanned page, its server, or operator text; none of them are trusted.
`core/robots.py` no longer uses a regex at all (see §3).

Line/segment caps that apply before matching:

| Layer | Cap |
| --- | --- |
| HTTP body | 2,000,000 decoded bytes per response (`DEFAULT_MAX_BYTES`) |
| Whole scan | 50,000,000 decoded bytes (default `--max-total-bytes`) |
| URLs | 2,048 characters (default `--max-url-length`) |
| Links per page | 1,000 (default `--max-links-per-page`) |
| Query variants per path | 50 (default `--max-query-variants`) |
| robots rules | 2,000 rules, 2,048 chars/rule, path truncated to 8,192 chars |

## 1. `core/redaction.py`

| Pattern | Input source | Worst case | Mitigation / test |
| --- | --- | --- | --- |
| `_USERINFO_RE` | error text, redirect URLs, audit strings | **Was quadratic.** At every character of a long word it retried scheme + `[a-z0-9+.-]*` to the end. Fixed with a scheme-boundary lookbehind and a 32-char scheme cap. | [`test_redaction_patterns_are_linear_on_huge_lines`](../tests/unit/test_regex_safety.py) |
| `_HEADER_LINE_RE` | error text | Linear in line length; header value intentionally consumes the rest of the line. | same |
| `_AUTH_SCHEME_RE` | error text | Linear; token class is a single greedy run. | same |
| `_ASSIGNMENT_RE` | error text | Linear; quoted alternatives cannot span newlines and the unquoted branch is a single run. | same |

Measured with a 250,000-character line: the whole `redact_text` call is
~0.03 s locally after the fix. Property tests additionally feed generated
credentials in URL-encoded, quoted, unicode and multi-line forms
([`test_redaction_properties.py`](../tests/unit/test_redaction_properties.py)).

## 2. `core/terminal.py`

| Pattern | Input source | Worst case | Test |
| --- | --- | --- | --- |
| `_OSC_RE`, `_CSI_RE`, `_ESC_RE` | target-derived URLs, errors, audit fields | Linear scans over the string; only ANSI/OSC shapes are consumed. | [`test_terminal_escapes_are_removed_but_text_is_kept`](../tests/security/test_terminal_and_output.py) |
| `_CONTROL_RE` | same | Linear character-class scan; removes C0/C1/DEL. | same |
| `_HEADER_NAME_RE` | operator header names | Anchored token character class; linear. | [`test_header_injection_is_rejected`](../tests/security/test_terminal_and_output.py) |

## 3. `scanners/endpoints.py`

| Pattern | Input source | Worst case | Test |
| --- | --- | --- | --- |
| `_PATH_RE` | page/JS text | Linear scan; character class excludes quote/space/backslash. | [`test_scanner_patterns_are_linear_on_pathological_quotes`](../tests/unit/test_regex_safety.py) |
| `_URL_RE` | page/JS text | Linear scan with a fixed `https?://` prefix. | same |
| `_CONCAT_RE` | page/JS text | Backreferences but no nested quantifiers; tested with 100k repeated `/a` and an escaped quote. | same |

## 4. `core/robots.py`

No regex. `_glob_match` is a two-pointer wildcard walk over `*`, with `$`
handling the end anchor, plus `MAX_RULES`, `MAX_PATTERN_LENGTH` and
`MAX_PATH_LENGTH`. A hostile `Disallow: /*a*a*...$` against a 100 KB path is
tested to finish under one second
([`test_robots_wildcards_do_not_backtrack_catastrophically`](../tests/unit/test_regex_safety.py)).

## 5. `scanners/secrets.py` and `core/config.py`

`SECRET_PATTERNS` are six keyword expressions with optional separators
(`api[_-]?key`, `secret`, `token`, `jwt`, `authorization`, `password`). They
contain no nested quantifiers. `scanners.secrets` compiles them once and uses
`findall`/`search`; input is the capped response body.

| Pattern | Input | Worst case | Test |
| --- | --- | --- | --- |
| six keyword patterns | page/JS text | Linear keyword scan. | [`test_scanners_never_raise_and_bound_output`](../tests/unit/test_regex_safety.py) |
| `_QUOTED_RE` | one evidence line | Linear; quotes cannot span a newline. | [`test_scanner_patterns_are_linear_on_pathological_quotes`](../tests/unit/test_regex_safety.py) |
| `_BARE_ASSIGNMENT_RE` | one evidence line | Linear fixed-width value run. | same |

## 6. Non-regex parsers and their bounds

* **BeautifulSoup/html.parser** receives only the per-response cap. Link
  extraction stops at `max_links_per_page` and caps URL length/query variants
  before normalization. Property test:
  [`test_parser_never_raises_on_arbitrary_text`](../tests/unit/test_regex_safety.py).
* **YAML (scope/config)** is parsed from operator-selected files, not from the
  target. Schema and key validation run afterwards.
* **JSON (audit)** is parsed line by line by `audit verify`; a malformed line is
  reported at its 1-based line number, never executed.
* **Seeded corpus** under `tests/fuzz/corpus/` exercises HTML, robots, error
  text and URLs on every CI run.

## 7. Fuzzing status

Hypothesis property tests (40–80 examples each) cover `extract_links`,
`scan_endpoints`, `scan_secrets`, `RobotsPolicy.parse/allows`, `check_url`,
`canonicalize_request_url`, and the redaction guarantee. Atheris is not used:
the property tests plus committed corpus are deterministic, fast, and run on
every Python version in CI.
