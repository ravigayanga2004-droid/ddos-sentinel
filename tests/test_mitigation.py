from pathlib import Path

import pytest

from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.safety import SimulationOptions
from ddos_sentinel.lab.runtime import Runtime
from ddos_sentinel.response.mitigation import MitigationRequest, Mitigator


def test_activation_expiry_reset_and_unblock(tmp_path: Path) -> None:
    db = Database(tmp_path / "data.db")
    engine = Mitigator(db)
    action_id = engine.enable(MitigationRequest(mode="global-throttle", reason="Lab test", rate=1))
    assert engine.check("client-1", "/", 0) is None
    assert engine.check("client-1", "/", 0) == 429
    engine.status(now=db.get("mitigation_actions", action_id)["expires_at"] + 1)
    assert engine.check("client-1", "/", 0) is None
    assert db.get("mitigation_actions", action_id)["status"] == "EXPIRED"
    engine.enable(MitigationRequest(mode="block-client", reason="Lab test", client_id="client-1"))
    assert engine.check("client-1", "/", 0) == 403
    assert engine.check("client-2", "/", 0) is None
    assert engine.unblock("client-1") == 1
    assert engine.check("client-1", "/", 0) is None
    engine.enable(MitigationRequest(mode="circuit-breaker", reason="Lab test"))
    assert engine.check("client-2", "/", 0) == 503
    assert engine.reset() == 1
    assert engine.check("client-2", "/", 0) is None


@pytest.mark.parametrize(
    ("mode", "kwargs", "code"),
    [
        ("cooldown", {}, 429),
        ("body-size-limit", {"body_limit": 1}, 413),
        ("endpoint-rate-limit", {"endpoint": "/api/test", "rate": 1}, 429),
        ("client-rate-limit", {"rate": 1}, 429),
    ],
)
def test_supported_controls(tmp_path: Path, mode: str, kwargs: dict, code: int) -> None:
    engine = Mitigator(Database(tmp_path / "data.db"))
    engine.enable(MitigationRequest(mode=mode, reason="Lab test", **kwargs))
    engine.check("client-1", "/api/test", 10)
    assert engine.check("client-1", "/api/test", 10) == code
    if mode == "client-rate-limit":
        assert engine.check("client-2", "/api/test", 10) is None
    if mode == "endpoint-rate-limit":
        assert engine.check("client-1", "/health", 10) is None
    assert engine.disable(mode) == 1


@pytest.mark.parametrize(
    "options",
    [
        {"mode": "firewall"},
        {"mode": "block-client"},
        {"mode": "block-client", "client_id": "192.168.0.1"},
        {"mode": "endpoint-rate-limit", "endpoint": "http://evil.test"},
        {"mode": "cooldown", "ttl": 301},
        {"mode": "cooldown", "reason": ""},
    ],
)
def test_invalid_controls(options: dict) -> None:
    with pytest.raises(ValueError):
        MitigationRequest.model_validate({"reason": "Lab test", **options})


async def test_real_middleware_and_reset(tmp_path: Path) -> None:
    db = Database(tmp_path / "lab.db")
    async with Runtime(LabConfig(), db) as runtime:
        runtime.mitigator.enable(
            MitigationRequest(mode="global-throttle", reason="Lab test", rate=2)
        )
        result = await runtime.run(SimulationOptions(duration=0.4, rate=20, authorized=True))
        assert result["metrics"]["requests_throttled"] > 0
        runtime.mitigator.reset()
        result = await runtime.run(SimulationOptions(duration=0.4, rate=20, authorized=True))
        assert result["metrics"]["requests_throttled"] == 0
