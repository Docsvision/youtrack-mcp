"""HTTP health contracts for the FastMCP application."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import main


@pytest.mark.unit
def test_health_and_readiness_routes_share_mcp_event_loop():
    with (
        patch.object(main, "load_all_tools", return_value={}),
        patch.object(main.config, "SANITIZER_REQUIRED", False),
    ):
        server = main.create_server(host="127.0.0.1", port=8000)
        app = server.streamable_http_app()

        with TestClient(app) as client:
            health = client.get("/healthz")
            ready = client.get("/readyz")

        assert health.status_code == 200
        assert health.json() == {"status": "ok"}
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"
        assert ready.json()["toolPool"]["active"] == 0
