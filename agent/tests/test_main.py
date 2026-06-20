from unittest.mock import patch

from fastapi.testclient import TestClient

import main


def test_ping_returns_healthy():
    client = TestClient(main.app)
    response = client.get("/ping")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "Healthy"
    assert "time_of_last_update" in body


def test_invocations_returns_agent_response():
    with patch("main._get_agent") as mock_get_agent:
        mock_get_agent.return_value = lambda prompt: f"echo: {prompt}"
        client = TestClient(main.app)
        response = client.post("/invocations", json={"prompt": "audit us-east-1"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["response"] == "echo: audit us-east-1"


def test_invocations_requires_prompt_field():
    client = TestClient(main.app)
    response = client.post("/invocations", json={})
    assert response.status_code == 422
