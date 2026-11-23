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
from core.config import load_cli_options_from_config, resolve_target_from_args
from core.exceptions import PathscopeError
from crawler.engine import Engine

OUTPUT_DIR = os.environ.get("PATHSCOPE_OUTPUT_DIR", "output")

logging.basicConfig(
    stream=sys.stderr,
    format="%(asctime)s | %(message)s",
    level=logging.WARNING,
    force=True,
)


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
        if keys and isinstance(parsed[keys[0]], str):
            return parsed[keys[0]]

    if isinstance(parsed, str):
        return parsed

    return None


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
) -> int:
    """Run one Pathscope scan using the resolved CLI + config + env values."""
    click.echo(BANNER)

    resolved_target = target or resolve_target_from_args(
        config, env_target=os.environ.get("TARGET_URL", "")
    )
    if not resolved_target:
        click.echo("Error: No target URL provided. Use --target or set TARGET_URL env var.")
        sys.exit(1)

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
    }

    config_path = config
    if config_path:
        merged = load_cli_options_from_config(config_path, defaults=defaults)
        resolved_target = merged.get("target", resolved_target) or resolved_target
        depth = int(merged.get("depth", depth))
        workers = int(merged.get("workers", workers))
        headers = merged.get("headers", headers) or headers
        cookie = merged.get("cookie", cookie) or cookie
        api = merged.get("api", api) or api
        secrets = bool(merged.get("secrets", secrets))
        endpoints = bool(merged.get("endpoints", endpoints))
        js = bool(merged.get("js", js))
        auth = merged.get("auth", auth) or auth
        if not quiet:
            click.echo(f"Using configuration file: {config_path}")

    os.environ["TARGET_URL"] = str(resolved_target)
    os.environ["CRAWL_DEPTH"] = str(depth)
    os.environ["MAX_WORKERS"] = str(workers)

    runner = Engine(
        start_url=str(resolved_target),
        depth=depth,
    )

    try:
        if not quiet:
            click.echo("\n[!] Running scan...")
        await runner.run()
        results: Any = runner
    except KeyboardInterrupt:
        click.echo("\r[!] Scan interrupted by user.")
        click.echo("\n[!] Scan stopped safely.")
        return 0

    except PathscopeError as exc:
        click.echo(f"\n[!] Scan failed: {exc}")
        return 2

    if not results:
        click.echo("\n[!] No results returned.")
        return 1

    discovered = (
        len(getattr(results, "discovered_urls", [])) if hasattr(results, "discovered_urls") else 0
    )
    endpoints_total = len(getattr(results, "endpoints", [])) if hasattr(results, "endpoints") else 0
    findings = len(getattr(results, "findings", [])) if hasattr(results, "findings") else 0
    errors_count = len(getattr(results, "errors", [])) if hasattr(results, "errors") else 0
    elapsed = getattr(results, "elapsed", "N/A")

    if not quiet:
        click.echo("\n[!] Scan complete")
        click.echo("[*] Results saved to output directory")
        click.echo("")
        click.echo(f"Total Discovered : {discovered}")
        click.echo(f"Total Endpoints  : {endpoints_total}")
        click.echo(f"Total Findings   : {findings}")
        click.echo(f"Total Errors     : {errors_count}")
        click.echo(f"Elapsed         : {elapsed}")
        click.echo("")

        if findings > 0:
            click.echo("[!] Results saved to output directory")
            click.echo("[*] Run again with --quiet to suppress this display")
            click.echo("")

    if json_out:
        click.echo("")
        click.echo(
            json.dumps(
                {
                    "target": str(resolved_target),
                    "discovered": discovered,
                    "endpoints": endpoints_total,
                    "findings": findings,
                    "errors": errors_count,
                    "elapsed": elapsed,
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
@click.option("--workers", "workers", default=8, type=int, help="Max concurrent workers.")
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
@click.option("--js/--no-js", "js", default=True, help="Toggle JavaScript discovery.")
@click.option("--auth", "auth", default=None, help="Auth profile or token.")
@click.option("--quiet", "quiet", is_flag=True, help="Suppress scan summary output.")
@click.option("--config", "config", default=None, help="Path to YAML config file.")
@click.option(
    "--json",
    "json_out",
    is_flag=True,
    help="Emit machine-readable JSON summary to stdout.",
)
def cli(
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
) -> None:
    """Pathscope: professional web discovery and attack surface intelligence."""
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
            )
        )
    )


if __name__ == "__main__":
    cli(prog_name="pathscope")
