"""
Pathscope CLI entry point.

This module is the public Click command used by `python -m pathscope` and the
`pathscope` console_script entry point. It wraps the async crawler `Engine`
and translates command-line options, optional YAML config, and environment
fallbacks into a single scan run.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

import click

from core.banner import BANNER
from core.config import load_config_from_file, merge_cli_options
from core.exceptions import PathscopeError
from crawler.engine import DEFAULT_MAX_PAGES, Engine
from crawler.fetcher import DEFAULT_MAX_REDIRECTS, DEFAULT_TIMEOUT

OUTPUT_DIR = os.environ.get("PATHSCOPE_OUTPUT_DIR", "output")

logging.basicConfig(
    stream=sys.stderr,
    format="%(asctime)s | %(message)s",
    level=logging.WARNING,
    force=True,
)

log = logging.getLogger("pathscope.cli")


def _parse_kv_or_json(raw: str) -> dict[str, str]:
    """Parse `raw` as a JSON object or as a comma-separated ``key:value`` list."""
    raw = (raw or "").strip()
    if not raw:
        return {}

    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("expected JSON object")
        return {str(k): str(v) for k, v in parsed.items()}
    except (json.JSONDecodeError, ValueError):
        out: dict[str, str] = {}
        for pair in raw.split(","):
            if ":" not in pair:
                continue
            key, value = pair.split(":", 1)
            out[key.strip()] = value.strip()
        return out


def _parse_api_key(raw: str) -> str | None:
    """Accept an API key as a plain string, a JSON string, or a JSON object."""
    raw = (raw or "").strip()
    if not raw:
        return None

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return raw

    if isinstance(parsed, dict):
        for value in parsed.values():
            if isinstance(value, str):
                return value
        keys = list(parsed.keys())
        if keys:
            first = parsed[keys[0]]
            if isinstance(first, str):
                return first

    if isinstance(parsed, str):
        return parsed

    return None


def _ensure_scheme(target: str) -> str:
    """Prefix ``https://`` when the operator omitted the scheme."""
    target = (target or "").strip()
    if not target:
        return target
    if "://" in target:
        return target
    return f"https://{target}"


def _build_headers(*, headers: str, cookie: str, api: str, auth: str | None) -> dict[str, str]:
    """Compose the request headers from the CLI options."""
    result = _parse_kv_or_json(headers)

    cookies = _parse_kv_or_json(cookie)
    if cookies:
        result["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
    elif cookie.strip():
        result["Cookie"] = cookie.strip()

    token = _parse_api_key(api) or _parse_api_key(auth or "")
    if token:
        result.setdefault("Authorization", f"Bearer {token}")

    return result


async def _run_cli(
    *,
    target: str | None,
    depth: int,
    workers: int,
    headers: str,
    cookie: str,
    api: str,
    secrets: bool,
    endpoints: bool,
    js: bool,
    auth: str | None,
    quiet: bool,
    config: str | None,
    json_out: bool,
    output_dir: str = OUTPUT_DIR,
    max_pages: int = DEFAULT_MAX_PAGES,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    block_private: bool = False,
    explicit: dict[str, Any] | None = None,
) -> int:
    """Run one Pathscope scan using the resolved CLI + config + env values."""
    logging.getLogger().setLevel(logging.ERROR if quiet else logging.INFO)

    click.echo(BANNER)

    env_target = os.environ.get("TARGET_URL", "")
    resolved_target = target or env_target
    if not resolved_target:
        click.echo("Error: No target URL provided. Use --target or set TARGET_URL env var.")
        sys.exit(1)
    resolved_target = _ensure_scheme(str(resolved_target))

    defaults: dict[str, Any] = {
        "target": resolved_target,
        "depth": depth,
        "workers": workers,
        "headers": headers,
        "cookie": cookie,
        "api": api,
        "secrets": secrets,
        "endpoints": endpoints,
        "js": js,
        "auth": auth,
        "output_dir": output_dir,
        "max_pages": max_pages,
        "timeout": timeout,
        "max_redirects": max_redirects,
        "block_private": block_private,
    }

    try:
        config_values = load_config_from_file(config, strict=True) if config else {}
        merged = merge_cli_options(defaults, config_values, explicit)
    except PathscopeError as exc:
        click.echo(f"\n[!] Configuration error: {exc}")
        return 2

    if config and not quiet:
        click.echo(f"Using configuration file: {config}")

    resolved_target = _ensure_scheme(str(merged.get("target") or resolved_target))
    depth = int(merged["depth"])
    workers = int(merged["workers"])
    headers = str(merged.get("headers") or "")
    cookie = str(merged.get("cookie") or "")
    api = str(merged.get("api") or "")
    secrets = bool(merged["secrets"])
    endpoints = bool(merged["endpoints"])
    js = bool(merged["js"])
    auth = merged.get("auth")
    output_dir = str(merged["output_dir"])
    max_pages = int(merged["max_pages"])
    timeout = float(merged["timeout"])
    max_redirects = int(merged["max_redirects"])
    block_private = bool(merged["block_private"])

    os.environ["TARGET_URL"] = str(resolved_target)
    os.environ["CRAWL_DEPTH"] = str(depth)
    os.environ["MAX_WORKERS"] = str(workers)

    runner = Engine(
        start_url=str(resolved_target),
        depth=depth,
        workers=workers,
        timeout=float(timeout),
        max_pages=int(max_pages),
        max_redirects=int(max_redirects),
        headers=_build_headers(headers=headers, cookie=cookie, api=api, auth=auth),
        block_private=block_private,
        scan_secrets_enabled=secrets,
        scan_endpoints_enabled=endpoints,
        scan_js=js,
        output_dir=output_dir,
    )

    try:
        if not quiet:
            click.echo("\n[!] Running scan...")
        await runner.run()
    except KeyboardInterrupt:
        click.echo("\r[!] Scan interrupted by user.")
        click.echo("\n[!] Scan stopped safely.")
        return 0
    except PathscopeError as exc:
        click.echo(f"\n[!] Scan failed: {exc}")
        return 2

    discovered = len(runner.discovered_urls)
    endpoints_total = len(runner.endpoints)
    findings = len(runner.findings)
    errors_count = len(runner.errors)
    elapsed = runner.elapsed
    requests_made = runner.requests_made
    successful = runner.successful_pages

    if not quiet:
        click.echo("\n[!] Scan complete")
        click.echo(f"[*] Findings written to {os.path.join(output_dir, 'findings.json')}")
        click.echo("")
        click.echo(f"Total Discovered : {discovered}")
        click.echo(f"Total Pages      : {runner.pages_fetched}")
        click.echo(f"Total Requests   : {requests_made}")
        click.echo(f"Successful       : {successful}")
        click.echo(f"Total Endpoints  : {endpoints_total}")
        click.echo(f"Total Findings   : {findings}")
        click.echo(f"Total Errors     : {errors_count}")
        click.echo(f"Redirects        : {runner.redirects_followed}")
        click.echo(f"Elapsed          : {elapsed:.2f}s")
        click.echo("")

    if json_out:
        click.echo("")
        click.echo(
            json.dumps(
                {
                    "target": str(resolved_target),
                    "discovered": discovered,
                    "pages": runner.pages_fetched,
                    "requests": requests_made,
                    "successful": successful,
                    "endpoints": endpoints_total,
                    "findings": findings,
                    "errors": errors_count,
                    "redirects": runner.redirects_followed,
                    "elapsed": round(elapsed, 3),
                },
                indent=2,
                default=str,
            )
        )

    return 0


TARGET_OPTION = click.option(
    "--target",
    "target",
    default=None,
    help="Target URL to crawl. Can also be set via TARGET_URL env var.",
)


@click.command()
@TARGET_OPTION
@click.option("--depth", "depth", default=2, type=int, help="Max crawl depth.")
@click.option("--workers", "workers", default=8, type=int, help="Max concurrent requests.")
@click.option("--headers", "headers", default="", help="Headers as JSON or key:value pairs.")
@click.option("--cookie", "cookie", default="", help="Cookies as JSON or key:value pairs.")
@click.option("--api", "api", default="", help="API key or JSON token for auth.")
@click.option("--secrets/--no-secrets", "secrets", default=True, help="Toggle secret scanning.")
@click.option(
    "--endpoints/--no-endpoints",
    "endpoints",
    default=True,
    help="Toggle endpoint discovery.",
)
@click.option("--js/--no-js", "js", default=True, help="Toggle JavaScript analysis.")
@click.option("--auth", "auth", default=None, help="Auth profile or token.")
@click.option("--quiet", "quiet", is_flag=True, help="Suppress scan summary output.")
@click.option("--config", "config", default=None, help="Path to YAML config file.")
@click.option(
    "--json",
    "json_out",
    is_flag=True,
    help="Emit machine-readable JSON summary to stdout.",
)
@click.option(
    "--output-dir",
    "output_dir",
    default=OUTPUT_DIR,
    show_default=True,
    help="Directory for findings.json.",
)
@click.option(
    "--max-pages",
    "max_pages",
    default=DEFAULT_MAX_PAGES,
    type=int,
    show_default=True,
    help="Hard cap on pages visited.",
)
@click.option(
    "--timeout",
    "timeout",
    default=DEFAULT_TIMEOUT,
    type=float,
    show_default=True,
    help="Per-request timeout in seconds.",
)
@click.option(
    "--max-redirects",
    "max_redirects",
    default=DEFAULT_MAX_REDIRECTS,
    type=int,
    show_default=True,
    help="Maximum redirect hops to follow per request.",
)
@click.option(
    "--block-private/--allow-private",
    "block_private",
    default=False,
    show_default=True,
    help="Refuse loopback, private, link-local and metadata targets.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    target: str | None,
    depth: int,
    workers: int,
    headers: str,
    cookie: str,
    api: str,
    secrets: bool,
    endpoints: bool,
    js: bool,
    auth: str | None,
    quiet: bool,
    config: str | None,
    json_out: bool,
    output_dir: str,
    max_pages: int,
    timeout: float,
    max_redirects: int,
    block_private: bool,
) -> None:
    """Pathscope: professional web discovery and attack surface intelligence."""
    explicit = {
        name: value
        for name, value in {
            "target": target,
            "depth": depth,
            "workers": workers,
            "headers": headers,
            "cookie": cookie,
            "api": api,
            "secrets": secrets,
            "endpoints": endpoints,
            "js": js,
            "auth": auth,
            "output_dir": output_dir,
            "max_pages": max_pages,
            "timeout": timeout,
            "max_redirects": max_redirects,
            "block_private": block_private,
        }.items()
        if ctx.get_parameter_source(name) == click.core.ParameterSource.COMMANDLINE
    }

    sys.exit(
        asyncio.run(
            _run_cli(
                target=target,
                depth=depth,
                workers=workers,
                headers=headers,
                cookie=cookie,
                api=api,
                secrets=secrets,
                endpoints=endpoints,
                js=js,
                auth=auth,
                quiet=quiet,
                config=config,
                json_out=json_out,
                output_dir=output_dir,
                max_pages=max_pages,
                timeout=timeout,
                max_redirects=max_redirects,
                block_private=block_private,
                explicit=explicit,
            )
        )
    )


if __name__ == "__main__":
    cli(prog_name="pathscope")
