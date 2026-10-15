import asyncio
from pathlib import Path

import httpx
import pytest

from ddos_sentinel.api.app import create_app
from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database


@pytest.fixture
async def client(tmp_path: Path):
    app = create_app(
        LabConfig(lab_name='<script>alert("x")</script>'), Database(tmp_path / "dashboard.db")
    )
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as session:
            yield session


async def token(client: httpx.AsyncClient) -> dict[str, str]:
    await client.get("/")
    return {"X-CSRF-Token": client.cookies["sentinel_csrf"]}


async def test_dashboard_health_and_escaping(client: httpx.AsyncClient) -> None:
    assert (await client.get("/health")).json()["status"] == "healthy"
    response = await client.get("/")
    assert '<script>alert("x")</script>' not in response.text
    assert "&lt;script&gt;" in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert (await client.get("/static/dashboard.js")).status_code == 200
    assert (await client.get("/static/dashboard.css")).status_code == 200
    assert (await client.get("/safety")).status_code == 200


async def test_csrf_origin_host_and_confirmation(client: httpx.AsyncClient) -> None:
    response = await client.post("/api/mitigation/reset", json={"confirmed": True})
    assert response.status_code == 403
    headers = await token(client)
    response = await client.post(
        "/api/mitigation/reset", json={"confirmed": False}, headers=headers
    )
    assert response.status_code == 422
    response = await client.post(
        "/api/mitigation/reset",
        json={"confirmed": True},
        headers={**headers, "Origin": "http://evil.test"},
    )
    assert response.status_code == 403
    assert (await client.get("/", headers={"Host": "evil.test"})).status_code == 403
    response = await client.post("/api/mitigation/reset", json={"confirmed": True}, headers=headers)
    assert response.status_code == 200
    response = await client.post("/api/mitigation/reset", content="x" * 8193, headers=headers)
    assert response.status_code == 403


async def test_simulation_control_and_reports(client: httpx.AsyncClient) -> None:
    headers = await token(client)
    body = {
        "options": {"scenario": "normal", "duration": 0.3, "authorized": True},
        "confirmed": True,
    }
    response = await client.post("/api/simulations", json=body, headers=headers)
    assert response.status_code == 202
    for _ in range(100):
        state = (await client.get("/api/status")).json()
        if not state["running"]:
            break
        await asyncio.sleep(0.02)
    assert state["simulations"][0]["status"] == "COMPLETED"
    response = await client.post("/api/baseline/create", json={"confirmed": True}, headers=headers)
    assert response.status_code == 200
    assert (await client.get("/api/status")).json()["baseline"] is not None
    for format in ("json", "markdown", "html"):
        response = await client.get(f"/reports/{format}")
        assert response.status_code == 200 and "DDoS Sentinel" in response.text
        assert '<script>alert("x")</script>' not in response.text
    assert (await client.get("/reports/invalid")).status_code == 404


async def test_simulation_authorization_and_concurrency(client: httpx.AsyncClient) -> None:
    headers = await token(client)
    body = {"options": {"scenario": "normal", "duration": 5}, "confirmed": True}
    response = await client.post("/api/simulations", json=body, headers=headers)
    assert response.status_code == 400
    body["options"]["authorized"] = True
    response = await client.post("/api/simulations", json=body, headers=headers)
    assert response.status_code == 202
    response = await client.post("/api/simulations", json=body, headers=headers)
    assert response.status_code == 409
    response = await client.post(
        "/api/simulations/cancel", json={"confirmed": True}, headers=headers
    )
    assert response.status_code == 200
    assert not (await client.get("/api/status")).json()["running"]


async def test_mitigation_controls(client: httpx.AsyncClient) -> None:
    headers = await token(client)
    response = await client.post(
        "/api/mitigation/enable", json={"mode": "cooldown", "reason": "Lab test"}, headers=headers
    )
    assert response.status_code == 200
    assert (await client.get("/api/status")).json()["mitigations"]
    response = await client.post("/api/mitigation/reset", json={"confirmed": True}, headers=headers)
    assert response.json()["disabled"] == 1


async def test_invalid_payloads_and_malformed_boundaries(client: httpx.AsyncClient) -> None:
    headers = await token(client)
    secret = "PRIVATE_BODY_NOT_TO_ECHO"
    response = await client.post(
        "/api/simulations",
        headers=headers,
        json={"options": {"scenario": "normal", "body": secret}, "confirmed": True},
    )
    assert response.status_code == 422
    assert secret not in response.text
    response = await client.post(
        "/api/mitigation/reset", headers={**headers, "Origin": "http://["}, json={"confirmed": True}
    )
    assert response.status_code == 403
    response = await client.post(
        "/api/mitigation/reset", headers={"X-CSRF-Token": "bad"}, json={"confirmed": True}
    )
    assert response.status_code == 403

    async def large_body():
        yield b"{" + b" " * 8192
        yield b"}"

    response = await client.post("/api/mitigation/reset", headers=headers, content=large_body())
    assert response.status_code == 400
