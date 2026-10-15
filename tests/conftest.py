"""Network tripwire: tests must never resolve or connect to an external host."""

import socket

import pytest


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch: pytest.MonkeyPatch) -> None:
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_resolve = socket.getaddrinfo

    def approved(address: object) -> None:
        if isinstance(address, tuple) and address[0] not in {"127.0.0.1", "::1", "localhost"}:
            raise AssertionError(f"external connection forbidden in tests: {address[0]}")

    def connect(sock: socket.socket, address: object):
        approved(address)
        return original_connect(sock, address)

    def connect_ex(sock: socket.socket, address: object):
        approved(address)
        return original_connect_ex(sock, address)

    def resolve(host: object, *args, **kwargs):
        if host not in {"127.0.0.1", "::1", "localhost", b"127.0.0.1", None}:
            raise AssertionError(f"external DNS forbidden in tests: {host}")
        return original_resolve(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
