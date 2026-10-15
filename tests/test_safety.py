from pathlib import Path

import pytest
from pydantic import ValidationError

from ddos_sentinel.core.authorization import LabAuthorization, issue_authorization
from ddos_sentinel.core.config import LabConfig, Limits, Target, load_config
from ddos_sentinel.core.safety import SimulationOptions, validate_target


@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8:80",
        "http://example.com:80",
        "http://192.168.1.2:80",
        "https://127.0.0.1:80",
        "ftp://127.0.0.1:80",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://user:secret@127.0.0.1:80",
        "http://127.0.0.1:80/other",
        "http://localhost.evil.test:80",
        "http://2130706433:80",
        "http://[::ffff:127.0.0.1]:80",
        "http://127.0.0.1:80?target=evil",
        "http://127.1:80",
    ],
)
def test_unsafe_targets_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        validate_target(url)


def test_authorization_ownership() -> None:
    auth = issue_authorization("http://localhost:1234", "lab")
    assert auth.require("http://127.0.0.1:1234", True) == "http://127.0.0.1:1234"
    with pytest.raises(ValueError):
        auth.require("http://127.0.0.1:1235", True)
    with pytest.raises(ValueError):
        auth.require(auth.target, False)
    with pytest.raises(ValueError):
        LabAuthorization(auth.target, "fake").require(auth.target, True)
    auth.active = False
    with pytest.raises(ValueError):
        auth.require(auth.target, True)


@pytest.mark.parametrize(
    "data",
    [
        {"duration": 61},
        {"rate": 201},
        {"clients": 101},
        {"body_size": 65537},
        {"duration": float("nan")},
        {"rate": True},
        {"clients": 0},
        {"duration": -1},
    ],
)
def test_hard_simulation_limits(data: dict) -> None:
    with pytest.raises(ValidationError):
        SimulationOptions(**data)


def test_config_limits_and_consent() -> None:
    with pytest.raises(ValueError):
        SimulationOptions().check(Limits())
    with pytest.raises(ValueError):
        SimulationOptions(authorized=True, rate=11).check(Limits(max_requests_per_second=10))
    with pytest.raises(ValueError):
        SimulationOptions(authorized=True, scenario="shell").check(Limits())
    SimulationOptions(authorized=True).check(Limits())


@pytest.mark.parametrize(
    "data",
    [
        {"target": {"host": "8.8.8.8"}},
        {"target": {"host": "example.com"}},
        {"target": {"port": -1}},
        {"target": {"protocol": "ftp"}},
        {"safety": {"allow_public_targets": True}},
        {"safety": {"localhost_only": False}},
        {"limits": {"max_clients": 101}},
        {"command": "anything"},
        {"target": {"service_type": "external"}},
    ],
)
def test_config_rejects_unsafe_values(data: dict) -> None:
    with pytest.raises(ValueError):
        LabConfig.model_validate(data)


def test_config_json(tmp_path: Path) -> None:
    path = tmp_path / "lab.json"
    path.write_text(LabConfig().model_dump_json(), encoding="utf-8")
    assert load_config(path) == LabConfig()
    assert Target(port=0).port == 0
    path.write_text("x" * 65537)
    with pytest.raises(ValueError):
        load_config(path)
