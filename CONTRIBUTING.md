# Contributing to Pathscope

Pathscope is a security engineering tool for authorized web discovery and attack surface intelligence. Contributions should preserve that goal and the safety constraints around it.

## Project principles

- Write for authorized auditing only.
- Keep discovery and verification separate.
- Fail safely on bad input, network failures, and scope violations.
- Do not store or print secrets in plain text.
- Do not add placeholder features and mark them as available.

## Development setup

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install pytest pytest-asyncio pytest-cov ruff mypy bandit
```

## Running checks

```bash
.venv/bin/python -m pytest tests/ -q --strict-markers
.venv/bin/python -m compileall -q .
.venv/bin/ruff check .
.venv/bin/python -m mypy core crawler scanners --ignore-missing-imports
.venv/bin/bandit -r core scanners
```

Type checking with mypy is currently configured to ignore missing library stubs for third-party packages.

## Testing standards

- Add unit tests for URL normalization, scope filtering, parsing, endpoint extraction, secret scanning, retry behavior, redirect handling, and output serialization.
- Add integration tests against a local mock HTTP server where possible.
- Add security regression tests for SSRF, redirect scope escape, private/loopback targets, oversized responses, and malformed input.
- Do not add tests that only assert mock call counts without checking behavior.

## Code quality expectations

- Keep public interfaces typed where reasonable.
- Use structured logging instead of free-form stdout for operational state.
- Keep errors explicit and centralized where practical.
- Do not store large response bodies without retention limits.

## Security

- Never commit credentials, tokens, private keys, or fake secrets that resemble real ones too closely.
- Do not introduce unsafe request behavior.
- When adding new networking code, include scope and safety checks.

## Pull requests

- Keep changes focused.
- Include tests for new behavior.
- Update documentation only for features that are actually implemented.
- Do not include AI attribution, watermarks, or generated-by metadata in commits.

## Reporting issues

Include:
- what you ran
- the target behavior
- the actual behavior
- environment details if relevant
