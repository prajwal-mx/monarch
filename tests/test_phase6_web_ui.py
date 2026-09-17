"""Tests for MONARCH Web Dashboard & REST API Endpoints.
Verifies Section 4.2 Security Team Dashboard and all interactive views.
"""

from __future__ import annotations

import json
import pytest
from monarch.web.app import create_app


@pytest.fixture
def client():
    app = create_app(":memory:")
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_ui_index_route(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"MONARCH" in res.data
    assert b"Supply Chain Risk Intelligence Platform" in res.data


def test_api_overview_endpoint(client):
    res = client.get("/api/overview")
    assert res.status_code == 200
    data = res.get_json()
    assert "epoch_id" in data
    assert data["package_count"] > 0
    assert data["edge_count"] > 0
    assert "cra_sla_alerts" in data


def test_api_packages_and_detail_endpoint(client):
    res = client.get("/api/packages")
    assert res.status_code == 200
    pkgs = res.get_json()
    assert len(pkgs) > 0
    pkg_name = pkgs[0]["name"]

    detail_res = client.get(f"/api/package/{pkg_name}")
    assert detail_res.status_code == 200
    detail = detail_res.get_json()
    assert detail["name"] == pkg_name
    assert "consequence_score" in detail
    assert "blast_radius_count" in detail
    assert "evidence_contract" in detail


def test_api_graph_endpoint(client):
    res = client.get("/api/graph")
    assert res.status_code == 200
    data = res.get_json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) > 0


def test_api_simulation_endpoint(client):
    payload = {"package": "express", "version": "4.18.3", "damping": 0.6}
    # 1. Lockfile-only inventory (AST reachability not evaluated)
    res = client.post("/api/simulate", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["naive_reach"] >= data["semver_gated_reach"]
    assert data["reachability_status"] == "NOT_EVALUATED"
    assert data["reachability_gated_reach"] is None
    assert data["noise_reduction_percent"] >= 0

    # 2. Upload source code to build AST index, then re-simulate
    src_res = client.post("/api/upload-source", json={
        "source_code": "const express = require('express'); const app = express();",
        "filename": "server.js"
    })
    assert src_res.status_code == 200

    res2 = client.post("/api/simulate", json=payload)
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2["reachability_status"] == "EVALUATED"
    assert data2["reachability_gated_reach"] is not None
    assert data2["semver_gated_reach"] >= data2["reachability_gated_reach"]
    assert data2["noise_reduction_percent"] >= 0


def test_api_solver_endpoint(client):
    res = client.post("/api/solve", json={"budget": 5.0})
    assert res.status_code == 200
    data = res.get_json()
    assert "interventions" in data
    assert "percentage_eliminated" in data
    assert data["percentage_eliminated"] > 0


def test_api_backtest_endpoint(client):
    res = client.get("/api/backtest")
    assert res.status_code == 200
    data = res.get_json()
    assert data["summary"]["precision"] == 1.0
    assert data["summary"]["recall"] == 1.0
    assert len(data["incidents"]) == 6


def test_api_exports_vex_and_sbom(client):
    vex_res = client.get("/api/export/vex")
    assert vex_res.status_code == 200
    vex = vex_res.get_json()
    assert vex["@context"] == "https://openvex.dev/ns/v0.2.0"

    sbom_res = client.get("/api/export/sbom")
    assert sbom_res.status_code == 200
    sbom = sbom_res.get_json()
    assert sbom["bomFormat"] == "CycloneDX"


def test_api_upload_lockfile_and_reset(client):
    lockfile_sample = {
        "name": "ecommerce-frontend",
        "lockfileVersion": 2,
        "packages": {
            "": {"dependencies": {"express": "^4.18.2", "react": "^18.2.0"}},
            "node_modules/express": {"version": "4.18.2", "dependencies": {"body-parser": "1.20.1"}},
            "node_modules/body-parser": {"version": "1.20.1", "dependencies": {"bytes": "3.1.2"}},
            "node_modules/bytes": {"version": "3.1.2"},
            "node_modules/react": {"version": "18.2.0", "dependencies": {"loose-envify": "^1.1.0"}},
            "node_modules/loose-envify": {"version": "1.4.0", "dependencies": {"js-tokens": "^4.0.0"}},
            "node_modules/js-tokens": {"version": "4.0.0"}
        }
    }
    res = client.post(
        "/api/upload-lockfile",
        json={"content": json.dumps(lockfile_sample), "filename": "package-lock.json"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["project_name"] == "ecommerce-frontend"
    assert data["package_count"] >= 6
    assert data["direct_count"] == 2
    assert "dominators" in data or "dominator_tree" in data

    # Verify overview reflects the uploaded project
    ov_res = client.get("/api/overview")
    assert ov_res.status_code == 200
    ov_data = ov_res.get_json()
    assert ov_data["project_name"] == "ecommerce-frontend"

    # Reset demo
    reset_res = client.post("/api/reset-demo")
    assert reset_res.status_code == 200
    reset_data = reset_res.get_json()
    assert reset_data["success"] is True
    assert reset_data["package_count"] > 0


def test_api_live_fetch_endpoint(client):
    # Test valid fetch with a real lightweight npm package
    res = client.post("/api/packages/live-fetch", json={"package_name": "is-number"})
    assert res.status_code in (200, 304)
    data = res.get_json()
    assert data["success"] is True
    assert data["package"]["name"] == "is-number"
    assert "consequence_score" in data["package"]
    assert "fragility_score" in data["package"]

