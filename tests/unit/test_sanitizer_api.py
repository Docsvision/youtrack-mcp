"""HTTP contract tests for the local sanitizer sidecar."""

from fastapi.testclient import TestClient

from sanitizer_service import service


class FakePolicy:
    def sanitize(self, tool_name, payload):
        if tool_name == "get_attachment_content":
            raise service.PolicyViolation("blocked")
        return {"safe": payload.get("safe", True)}


def test_sanitize_endpoint_returns_payload(monkeypatch):
    monkeypatch.setattr(service, "get_policy", lambda: FakePolicy())
    client = TestClient(service.app)

    response = client.post(
        "/sanitize",
        json={"tool": "get_issue", "payload": {"safe": True}},
    )

    assert response.status_code == 200
    assert response.json() == {"payload": {"safe": True}}


def test_sanitize_endpoint_rejects_non_allowlisted_tool(monkeypatch):
    monkeypatch.setattr(service, "get_policy", lambda: FakePolicy())
    client = TestClient(service.app)

    response = client.post(
        "/sanitize",
        json={
            "tool": "get_attachment_content",
            "payload": {"content_base64": "secret"},
        },
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "output rejected by policy"}


def test_health_and_readiness_are_separate():
    client = TestClient(service.app)
    original_ready = service.runtime_state.ready
    try:
        service.runtime_state.ready = False
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503

        service.runtime_state.ready = True
        response = client.get("/ready")
        assert response.status_code == 200
        assert response.json()["ready"] is True
    finally:
        service.runtime_state.ready = original_ready


def test_sanitizer_metrics_do_not_include_payload(monkeypatch):
    monkeypatch.setattr(service, "get_policy", lambda: FakePolicy())
    client = TestClient(service.app)

    client.post(
        "/sanitize",
        json={"tool": "get_issue", "payload": {"safe": "secret-value"}},
    )
    metrics = client.get("/metrics").json()

    assert metrics["total"] >= 1
    assert "secret-value" not in str(metrics)


def test_sanitizer_rejects_excess_work_without_running_policy(monkeypatch):
    class FullCapacity:
        def acquire(self, *, timeout):
            return False

    policy = FakePolicy()
    monkeypatch.setattr(service, "get_policy", lambda: policy)
    monkeypatch.setattr(service, "sanitizer_slots", FullCapacity())
    before = service.runtime_state.snapshot()

    response = TestClient(service.app).post(
        "/sanitize",
        json={"tool": "get_issue", "payload": {"safe": True}},
    )

    after = service.runtime_state.snapshot()
    assert response.status_code == 503
    assert response.json() == {"detail": "sanitizer busy"}
    assert after["rejected"] == before["rejected"] + 1
    assert after["active"] == before["active"]
