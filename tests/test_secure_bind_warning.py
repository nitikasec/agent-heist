"""Startup warning when the server binds outside loopback (audit finding H5)."""

import logging

import httpx2
import pytest
from secure_support import ISSUER, READ, RESOURCE, TestIdentityProvider, directory_json, running, write_private_file

from agentheist.secure import __main__ as entrypoint
from agentheist.secure.auth import ConfigurationError
from agentheist.secure.config import SecureConfig
from agentheist.secure.helpdesk import build_server

LOOPBACK = ["127.0.0.1", "localhost", "::1"]
# 127.0.0.2, LOCALHOST and "localhost." are loopback in practice, but the SDK only enables its
# Host/Origin checks for the three exact strings above, so they must warn too.
NON_LOOPBACK = ["0.0.0.0", "::", "192.168.1.10", "10.0.0.5", "helpdesk.internal", "127.0.0.2", "LOCALHOST",
                "localhost.", "[::1]", "::ffff:127.0.0.1"]
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}


def config(host: str) -> SecureConfig:
    return SecureConfig(issuer=ISSUER, resource_url=RESOURCE, public_key_file="k.pem", host=host)


@pytest.mark.parametrize("host", LOOPBACK)
def test_loopback_hosts_do_not_warn(host):
    assert config(host).binds_to_loopback
    assert config(host).startup_warnings() == []


@pytest.mark.parametrize("host", NON_LOOPBACK)
def test_other_hosts_warn(host):
    cfg = config(host)
    assert not cfg.binds_to_loopback
    [warning] = cfg.startup_warnings()
    assert repr(host) in warning and "plain HTTP" in warning and "TLS" in warning


def test_default_host_is_loopback():
    assert SecureConfig.from_env({
        "AGENTHEIST_SECURE_ISSUER": ISSUER, "AGENTHEIST_SECURE_RESOURCE_URL": RESOURCE,
        "AGENTHEIST_SECURE_PUBLIC_KEY_FILE": "k.pem", "AGENTHEIST_SECURE_DIRECTORY_FILE": "p.json",
    }).startup_warnings() == []


@pytest.mark.parametrize("host", ["", "   "])
def test_empty_host_is_refused(host):
    with pytest.raises(ConfigurationError, match="Host must not be empty"):
        SecureConfig.from_env({
            "AGENTHEIST_SECURE_ISSUER": ISSUER, "AGENTHEIST_SECURE_RESOURCE_URL": RESOURCE,
            "AGENTHEIST_SECURE_PUBLIC_KEY_FILE": "k.pem", "AGENTHEIST_SECURE_DIRECTORY_FILE": "p.json",
            "AGENTHEIST_SECURE_HOST": host,
        })


@pytest.fixture
def idp():
    return TestIdentityProvider()


@pytest.fixture
def server_env(tmp_path, idp, monkeypatch):
    key_file = write_private_file(tmp_path / "issuer-public.pem", idp.public_pem())
    directory = write_private_file(tmp_path / "principals.json", directory_json(("sam", ["staff"])))
    for name, value in {"AGENTHEIST_SECURE_ISSUER": ISSUER, "AGENTHEIST_SECURE_RESOURCE_URL": RESOURCE,
                        "AGENTHEIST_SECURE_PUBLIC_KEY_FILE": str(key_file),
                        "AGENTHEIST_SECURE_DIRECTORY_FILE": str(directory)}.items():
        monkeypatch.setenv(name, value)
    for name in ("AGENTHEIST_SECURE_JWKS_URL", "AGENTHEIST_SECURE_JWKS_CA_FILE", "AGENTHEIST_SECURE_DEBUG",
                 "AGENTHEIST_SECURE_MAX_TOKEN_LIFETIME_SECONDS", "AGENTHEIST_SECURE_PORT"):
        monkeypatch.delenv(name, raising=False)
    started = []
    monkeypatch.setattr(entrypoint.uvicorn, "run", lambda app, **kwargs: started.append(kwargs))
    return started


@pytest.mark.parametrize("host, warns", [("127.0.0.1", False), ("::1", False), ("0.0.0.0", True),
                                         ("127.0.0.2", True)])
def test_entrypoint_logs_the_warning_before_serving(server_env, monkeypatch, caplog, host, warns):
    monkeypatch.setenv("AGENTHEIST_SECURE_HOST", host)
    caplog.set_level(logging.WARNING, logger="agentheist.secure")
    assert entrypoint.main() == 0
    assert server_env == [{"host": host, "port": 8000}]
    warnings = [r for r in caplog.records if r.name == "agentheist.secure" and r.levelno == logging.WARNING]
    assert len(warnings) == int(warns)
    if warns:
        assert repr(host) in warnings[0].getMessage()


@pytest.mark.parametrize("host, status", [("127.0.0.1", 421), ("0.0.0.0", 200)])
async def test_warning_describes_real_sdk_behaviour(server_env, monkeypatch, idp, host, status):
    """The reason for the warning: off loopback, the SDK no longer rejects a foreign Host header."""
    monkeypatch.setenv("AGENTHEIST_SECURE_HOST", host)
    cfg = SecureConfig.from_env()
    server = build_server(cfg)
    app = server.streamable_http_app(host=cfg.host)
    async with running(server):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://evil.example") as c:
            response = await c.post("/mcp", json=INITIALIZE,
                                    headers={**HEADERS, "Authorization": f"Bearer {idp.issue('sam', READ)}"})
    assert response.status_code == status
