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
