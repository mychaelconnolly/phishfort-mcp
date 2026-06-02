from __future__ import annotations

import json
from pathlib import Path


def test_manifest_has_complete_source_set() -> None:
    manifest_path = Path("docs/reference/source-manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(manifest["sources"]) == 13
    assert all(source["status"] == 200 for source in manifest["sources"])
    names = {source["name"] for source in manifest["sources"]}
    assert "Webhooks" in names
    assert "Hidden Single Incident OpenAPI YAML" in names
    assert {probe["status"] for probe in manifest["probes"]} == {404}
    assert manifest["raw_copy_policy"] == "local-only; not intended for public repository tracking"


def test_manifest_uses_official_source_urls() -> None:
    manifest = json.loads(Path("docs/reference/source-manifest.json").read_text(encoding="utf-8"))
    for source in manifest["sources"]:
        assert source["url"].startswith("https://phishfort.github.io/unified-client-api-docs/")
        assert "local_path" not in source
