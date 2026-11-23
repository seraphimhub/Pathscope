"""CLI integration checks for the Pathscope entry point."""

import cli


def test_cli_module_is_importable_and_has_cli() -> None:
    assert cli.cli is not None
    assert cli._run_cli is not None
    assert hasattr(cli, "OUTPUT_DIR")


def test_cli_accepts_required_kwargs() -> None:
    import inspect

    sig = inspect.signature(cli._run_cli)
    params = list(sig.parameters.keys())
    expected = [
        "target",
        "depth",
        "workers",
        "headers",
        "cookie",
        "api",
        "secrets",
        "endpoints",
        "js",
        "auth",
        "quiet",
        "config",
        "json_out",
        "output_dir",
        "max_pages",
        "timeout",
        "max_redirects",
        "block_private",
        "allow_scheme_downgrade",
        "explicit",
    ]
    assert params == expected
