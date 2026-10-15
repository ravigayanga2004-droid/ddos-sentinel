import ast
import socket
from pathlib import Path

import httpx
import pytest

from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.lab.service import TemporaryLab


def test_network_tripwire() -> None:
    with socket.socket() as sock, pytest.raises(AssertionError, match="external connection"):
        sock.connect(("8.8.8.8", 80))
    with pytest.raises(AssertionError, match="external DNS"):
        socket.getaddrinfo("example.com", 80)


def test_no_raw_packets_script_execution_or_shells() -> None:
    source = Path(__file__).parents[1] / "src" / "ddos_sentinel"
    for file in source.rglob("*.py"):
        tree = ast.parse(file.read_text(encoding="utf-8"))
        for item in ast.walk(tree):
            if isinstance(item, ast.Import):
                assert not {entry.name.split(".")[0] for entry in item.names} & {
                    "subprocess",
                    "scapy",
                    "ctypes",
                    "importlib",
                }, file
            if isinstance(item, ast.ImportFrom):
                assert (item.module or "").split(".")[0] not in {"subprocess", "scapy", "ctypes"}
            if isinstance(item, ast.Attribute):
                assert item.attr not in {"SOCK_RAW", "system", "popen", "execv", "execve"}, file
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name):
                assert item.func.id not in {"eval", "exec", "compile", "__import__"}, file


async def test_actual_sensitive_body_and_headers_are_never_stored(tmp_path: Path) -> None:
    db = Database(tmp_path / "lab.db")
    secret = "PRIVATE_SENTINEL_BODY_7eb1"
    async with TemporaryLab(LabConfig(), db) as lab:
        assert lab.authorization
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.post(
                lab.target + "/api/test",
                content=secret,
                headers={
                    "X-Sentinel-Lab": lab.authorization.token,
                    "Authorization": secret,
                    "Cookie": secret,
                },
            )
            assert response.status_code == 200
        sample = lab.telemetry.samples[-1]
        db.put("traffic_samples", sample.model_dump())
        assert secret not in str(db.list("traffic_samples"))
        assert lab.authorization.token not in str(db.list("traffic_samples"))
    for file in tmp_path.iterdir():
        assert secret.encode() not in file.read_bytes()
