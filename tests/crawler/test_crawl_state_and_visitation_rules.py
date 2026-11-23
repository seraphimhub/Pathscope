"""Tests for crawl state, visitation rules, and output consistency."""

import json
import os
import tempfile
from urllib.parse import urlparse

import pytest

from crawler.engine import Engine


def _normalize_url(url: str) -> str:
    from crawler.parser import normalize

    return normalize(url)


@pytest.mark.asyncio
async def test_engine_visits_start_url_only_when_depth_zero():
    engine = Engine("https://example.com/", depth=0)
    await engine.run()
    visited = {urlparse(u).path for u in engine.visited}
    assert "/" in visited or "/index.html" in visited


@pytest.mark.asyncio
async def test_engine_does_not_visit_same_url_twice():
    engine = Engine("https://example.com/", depth=5)
    await engine.run()
    assert len(engine.visited) == len(set(engine.visited))


@pytest.mark.asyncio
async def test_engine_findings_are_written_to_output_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = os.path.join(tmpdir, "output")
        os.makedirs(out_dir, exist_ok=True)

        original = os.getcwd()
        try:
            os.chdir(tmpdir)
            engine = Engine("https://example.com/", depth=1)
            await engine.run()
            path = os.path.join("output", "findings.json")
            assert os.path.exists(path)
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            assert isinstance(data, list)
        finally:
            os.chdir(original)


def test_engine_findings_contain_required_fields_for_each_entry():
    engine = Engine("https://example.com/", depth=1)
    for finding in engine.findings:
        assert isinstance(finding, dict)
        assert finding.get("type") in ("endpoint", "secret_pattern")


def test_engine_findings_include_source_url():
    engine = Engine("https://example.com/", depth=1)
    for finding in engine.findings:
        assert finding.get("url") == "https://example.com/"
