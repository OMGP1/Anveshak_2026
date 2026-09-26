"""The simple site must coexist with the original root-mounted dashboard."""
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import main


@pytest.mark.parametrize("original_built", [False, True])
@pytest.mark.parametrize("simple_built", [False, True])
def test_dashboard_mounts_are_independent(tmp_path: Path, monkeypatch, original_built, simple_built):
    original = tmp_path / "original"
    simple = tmp_path / "simple"
    for directory, built, name in ((original, original_built, "original"), (simple, simple_built, "simple")):
        if built:
            directory.mkdir()
            (directory / "index.html").write_text(f"<h1>{name}</h1>", encoding="utf-8")
            (directory / "asset.js").write_text(f"// {name} asset", encoding="utf-8")
    if simple_built:
        (simple / "dashboard-guide.md").write_text("# User guide", encoding="utf-8")
    monkeypatch.setattr(main, "DIST", original)
    monkeypatch.setattr(main, "SIMPLE_DIST", simple)
    app = FastAPI()

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    main.mount_dashboard(app)
    with TestClient(app) as client:
        assert client.get("/api/health").json() == {"status": "ok"}
        root = client.get("/")
        assert root.status_code == 200
        if original_built:
            assert root.text == "<h1>original</h1>"
            assert client.get("/asset.js").text == "// original asset"
        else:
            assert "ui/" in root.json()["detail"]
        for path in ("/simple", "/simple/", "/simple/?mock=0", "/simple?mock=1"):
            response = client.get(path)
            assert response.status_code == 200
            if simple_built:
                assert response.text == "<h1>simple</h1>"
                if "?" in path:
                    assert response.url.query.decode() == path.split("?", 1)[1]
            else:
                assert "ui-simple/" in response.json()["detail"]
        if simple_built:
            assert client.get("/simple/asset.js").text == "// simple asset"
            assert client.get("/simple/dashboard-guide.md").text == "# User guide"
            assert client.get("/simple/missing.js").status_code == 404
