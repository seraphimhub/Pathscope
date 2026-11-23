# Pathscope threat model (Phase 2)

Scope: the crawler, scanners, persistence, CLI and audit verification at commit
`c04b4bd` plus the Phase 2 changes. Playwright rendering and plugins (later
phases) are out of scope. This document maps each mitigation to the test that
would fail if the mitigation were removed.

## Assets

1. **Target availability and integrity** — a scan must not be usable to flood,
   hang, or exhaust a target.
2. **Operator credentials** — Authorization headers, cookies, API keys, URL
   userinfo. Losing them to a report, log, audit entry, or error message is a
   security incident.
3. **Scan reports and audit evidence** — findings, `scan.json`, and
   `audit.jsonl` must stay truthful, private (0600), and tamper-evident.
4. **The scanning host** — disk, memory, CPU and output filesystem. A hostile
   site must not write outside the output directory, follow a symlink, or drive
   super-linear CPU/memory use.
5. **Authorization record** — who approved the scan, for which hosts, until
   when.

## Trust boundaries

| Boundary | Untrusted input | Trusted code |
| --- | --- | --- |
| Operator → CLI | flags, headers, cookies, output path, authorization text | Click parser, `core.terminal`, `core.authorization` |
| Network → crawler | status, headers, body, redirects, TLS certificate, robots.txt | `crawler.fetcher`, `core.resolver`, `core.robots` |
| Page → scanners/parser | HTML, JavaScript text, quoted literals | BeautifulSoup, `crawler.parser`, `scanners.*` |
| Crawler → disk | URLs, error strings, findings, audit events | `crawler.engine`, `core.audit` |
| Audit file → verifier | previously written JSONL | `core.audit.verify_audit_file` |

The target server is the primary attacker. It controls its certificate, every
response body, redirect target, `Retry-After`, robots rules, link graph, and
the text that ends up in findings. The operator is trusted to choose a target
but not to supply safe strings: headers and output paths are validated.

## STRIDE and mitigations

| # | Threat | STRIDE | Mitigation | Enforcing test |
| --- | --- | --- | --- | --- |
| 1 | Huge or gzip-compressed response exhausts memory/disk | Denial of service | Per-response cap is applied to **decoded** bytes (`fetcher._read_text`); aiohttp decompresses before the cap | [`test_size_cap_applies_to_decoded_gzip_bytes`](../tests/security/test_resource_budgets.py) |
| 2 | Many large pages exceed the whole-scan budget | Denial of service | One global byte budget claimed chunk-by-chunk, exact under concurrency; clean stop + audit event | [`test_total_download_budget_stops_cleanly`](../tests/security/test_resource_budgets.py) |
| 3 | Slow or endless responses keep a scan alive forever | Denial of service | `--max-time` deadline, per-request timeout clamped to the remaining time, clean stop with `stop_reason` | [`test_wall_clock_budget_stops_cleanly`](../tests/security/test_resource_budgets.py) |
| 4 | Infinite calendar / faceted-search / parameter trap | Denial of service | Page, link-per-page, URL-length and query-variant budgets; stop reason in `scan.json` and audit | [`test_crawler_trap_terminates_at_page_budget`](../tests/security/test_resource_budgets.py), [`test_query_variant_budget_is_recorded`](../tests/security/test_resource_budgets.py) |
| 5 | One page contains thousands of links | Denial of service | Parser stops at `max_links_per_page`; suppression is counted and audited once | [`test_links_per_page_and_url_length_are_bounded`](../tests/security/test_resource_budgets.py) |
| 6 | Huge single line drives super-linear redaction | Denial of service | Userinfo pattern bounded by a scheme lookbehind/length; every pattern timed on 250 KB hostile input | [`test_redaction_patterns_are_linear_on_huge_lines`](../tests/unit/test_regex_safety.py) |
| 7 | Hostile robots wildcard causes regex backtracking | Denial of service | robots matching uses a linear two-pointer wildcard walk, no regex; rule count/length/path capped | [`test_robots_wildcards_do_not_backtrack_catastrophically`](../tests/unit/test_regex_safety.py), [`test_robots_parser_caps_hostile_rule_counts`](../tests/unit/test_regex_safety.py) |
| 8 | Hostile HTML crashes or explodes the parser/scanners | Denial of service / Tampering | Caps before scanning, exception isolation, property/fuzz tests with committed corpus | [`test_parser_never_raises_on_arbitrary_text`](../tests/unit/test_regex_safety.py), [`test_seed_corpus_is_handled_without_exceptions`](../tests/unit/test_regex_safety.py) |
| 9 | Target text injects ANSI/OSC/CR/backspace into console, log, audit, findings | Tampering / Information disclosure | `sanitize_terminal` at every target-derived output boundary | [`test_terminal_escapes_are_removed_but_text_is_kept`](../tests/security/test_terminal_and_output.py), [`test_engine_errors_and_audit_never_contain_terminal_controls`](../tests/security/test_terminal_and_output.py), [`test_console_never_prints_a_hostile_target_escape`](../tests/integration/test_cli_hardening.py) |
| 10 | Operator header/cookie/User-Agent/scan-id injects a second HTTP line | Tampering / Elevation | Header names and values validated; CR/LF and all C0/C1 controls rejected before a scan starts | [`test_control_characters_in_operator_input_are_refused`](../tests/integration/test_cli_hardening.py), [`test_header_injection_is_rejected`](../tests/security/test_terminal_and_output.py) |
| 11 | Output path traversal or symlink redirects reports/audit | Tampering / Elevation | `..` and symlinked output dirs refused; audit opened `O_NOFOLLOW`; JSON written to a temp file then atomically replaced; final file must be regular and current-user owned | [`test_output_dir_traversal_and_symlink_are_refused`](../tests/security/test_terminal_and_output.py), [`test_audit_log_refuses_to_follow_a_symlink`](../tests/security/test_terminal_and_output.py), [`test_json_output_replaces_a_symlink_without_following_it`](../tests/security/test_terminal_and_output.py) |
| 12 | On-path attacker presents a forged certificate | Spoofing / Information disclosure | Verification on by default; `--insecure` is loud and recorded; `--ca-bundle` adds an explicit trust anchor; scope/resolver checks stay active | [`test_default_verification_fails_with_a_clear_error`](../tests/security/test_tls.py), [`test_ca_bundle_allows_the_self_signed_server`](../tests/security/test_tls.py), [`test_insecure_is_recorded_and_audited`](../tests/security/test_tls.py), [`test_scope_and_private_checks_still_apply_in_every_tls_mode`](../tests/security/test_tls.py) |
| 13 | Redirect escapes the authorized host or downgrades HTTPS | Elevation / Information disclosure | Scheme and host/port checked on every hop before the next request; out-of-scope redirect is refused and audited | [`test_redirect_out_of_scope_is_refused`](../tests/crawler/test_engine_concurrency_and_isolation.py), [`test_userinfo_in_redirect_cannot_widen_scope`](../tests/security/test_numeric_ip_forms.py) |
| 14 | URL credentials leak into findings/log/report/audit | Information disclosure | Userinfo stripped centrally; header/cookie/bearer/token values redacted; property tests over generated credentials | [`test_url_userinfo_is_removed`](../tests/unit/test_redaction_properties.py), [`test_authorization_header_never_leaks`](../tests/unit/test_redaction_properties.py), [`test_audit_and_metadata_never_store_start_url_credentials`](../tests/crawler/test_engine_safe_operations.py) |
| 15 | Numeric IPv4 spelling bypasses scope then fails in yarl | Spoofing / Elevation | Legacy forms canonicalized to dotted-quad before aiohttp sees the URL; scope comparisons already agree with the kernel | [`test_engine_scans_and_follows_redirects_from_numeric_host`](../tests/security/test_numeric_fetch.py), [`test_legacy_numeric_form_matches_scope_of_dotted_quad`](../tests/security/test_numeric_ip_forms.py) |
| 16 | Audit log is edited or a middle line is removed | Tampering / Repudiation | SHA-256 hash chain; `pathscope audit verify` reports the first broken line | [`test_editing_a_middle_entry_reports_the_first_bad_line`](../tests/unit/test_audit_chain.py), [`test_cli_audit_verify_reports_success_and_tampering`](../tests/unit/test_audit_chain.py) |
| 17 | Audit log cannot be opened (symlink, wrong owner) | Denial of service | Failure is detected, recorded as `audit_error`, and the scan continues with reports so evidence is not silently lost | [`test_audit_log_refuses_to_follow_a_symlink`](../tests/security/test_terminal_and_output.py) |
| 18 | Scan starts without an authorization record | Elevation / Repudiation | Gate requires `--authorized-by`, a validated scope file, or recorded `--lab-mode`; optional expiry is enforced and recorded | [`test_scan_without_authorization_is_refused`](../tests/unit/test_authorization.py), [`test_expired_authorized_until_is_refused`](../tests/integration/test_cli_hardening.py), [`test_missing_authorized_until_warns_loudly`](../tests/integration/test_cli_hardening.py) |
| 19 | Authorization text can inject terminal controls or imply proof it does not have | Repudiation / Tampering | Authorization strings pass through the same output sanitizer; README states the gate records attribution, not cryptographic proof | [`test_engine_errors_and_audit_never_contain_terminal_controls`](../tests/security/test_terminal_and_output.py), [`test_cli_records_authorized_by_in_metadata`](../tests/integration/test_cli_governance.py) |

## Measured limits (Phase 2 verification)

Local run on the development container (Python 3.12, Linux): a 5 MB decoded
gzip bomb served from a local server with a 10 KB cap returned
`decoded_bytes=10000`, `truncated=True`, and the whole measurement process
peaked at **~43 MB RSS** (`/usr/bin/time -v`, maximum resident set size 43,036
KB). A self-replicating crawler trap with `max_pages=12` terminated in
**0.33 s** with `stop_reason=max_pages` after 12 pages (~37 pages/s on
loopback). Worst-case regex calls on 250 KB/100 KB hostile inputs measured:
redaction **0.037 s**, robots wildcard match **0.012 s**, endpoint scan
**0.168 s**. The bundled low-latency benchmark on the same machine measured
**53.19 pages/s** at 4 workers (28 responses, 0 errors); absolute throughput is
local-machine specific.

Memory ceiling estimate with defaults (`workers=8`, 2 MB per response): eight
in-flight bodies (~16 MB) plus a conservative 5–10× DOM/text expansion during
parsing (~80–160 MB) plus the interpreter/aiohttp baseline (~40 MB) puts a
normal scan in the **~150–220 MB** range in the worst case, not a hard RSS
limit. Setting `--workers`, `--max-bytes` (library) and `--max-total-bytes`
lower is the supported way to reduce it; a process-level `RLIMIT_AS` is not
implemented.

## Residual risks (explicit)

1. **Audit deletion/truncation is undetectable.** The hash chain detects edits,
   reordering, and deletion of a middle line. Deleting the whole file or the
   tail leaves a valid chain. No external anchoring or signing exists yet.
2. **The authorization gate is attribution, not proof.** `--authorized-by` and
   `--authorized-until` are operator-supplied strings. A malicious operator can
   claim any authorization; the log only shows what was claimed. Only a scope
   file adds host and validity structure, and it is still self-asserted.
3. **Redaction is pattern-based.** Covered: URL userinfo, credential-like URL
   query parameters (`token`, `api_key`, `authorization`, `password`, …),
   Authorization/Cookie/Set-Cookie and common API-key headers, bearer/basic
   values, quoted/unquoted `token`/`secret`/`password` assignments,
   percent-encoded and unicode values, multi-line text. **Not covered:** base64 or encrypted transformations,
   credentials split across lines, credentials embedded in prose with no
   sensitive key, custom header names not in the allowlist, and arbitrary
   binary encodings. Over-redaction (dropping the rest of a header line) is
   accepted.
4. **Memory is bounded per response and in total, but not by a hard RSS
   ceiling.** HTML is held in memory while parsed; a pathological DOM near the
   per-response cap can still require several times the body size. The measured
   numbers and a conservative 150–220 MB estimate are above; a process-level
   `RLIMIT_AS` is not set.
5. **BeautifulSoup/html.parser complexity is third-party.** Project regexes
   are bounded and tested; the HTML parser itself is not fuzzed beyond the
   corpus/property tests and is only fed capped bodies.
6. **Regex safety is a time budget, not a formal proof.** Patterns are tested
   with known adversarial shapes and 250 KB inputs; a novel engine-specific
   case could still be slower. The inventory records the reasoning.
7. **A hostile server can still be slow within per-request and total limits.**
   `--max-time` limits scan duration, not the target's experience.
8. **TLS `--insecure` is a deliberate downgrade.** It is loud and recorded but
   cannot protect credentials from an on-path attacker.
9. **The output directory is not protected from a local attacker after the
   scan.** Files are 0600 and atomically replaced, but an attacker who can write
   the directory can replace them later.
10. **No sandboxing.** The process runs with the operator's privileges and no
    seccomp/container boundary; a third-party parser memory-corruption bug is
    out of the model.
