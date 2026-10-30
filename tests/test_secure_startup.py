"""Environment configuration and the shared startup path used by `python -m dvmcp.secure`."""

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from secure_support import (
    INTERNAL, ISSUER, READ, LocalJWKSServer, TestIdentityProvider, closed_port, directory_json, running,
    write_private_file,
)

from dvmcp.secure import __main__ as entrypoint
from dvmcp.secure.auth import ConfigurationError
from dvmcp.secure.config import SecureConfig
from dvmcp.secure.helpdesk import TICKETS, build_server

BASE_URL = "http://127.0.0.1:8765"
RESOURCE = f"{BASE_URL}/mcp"
INTERNAL_BODY = TICKETS[7001]["body"]


@pytest.fixture
def directory_file(tmp_path):
    return write_private_file(tmp_path / "principals.json", directory_json(("alice", ["customer"]), ("sam", ["staff"])))


def base_env(directory_file, **overrides):
    env = {
        "DVMCP_SECURE_ISSUER": ISSUER,
        "DVMCP_SECURE_RESOURCE_URL": RESOURCE,
        "DVMCP_SECURE_DIRECTORY_FILE": str(directory_file),
        "DVMCP_SECURE_PORT": "8765",
        **overrides,
    }
    return {key: value for key, value in env.items() if value is not None}


async def call_as(server, config, token, ticket_id):
    """Serve the app exactly as __main__ does (default stateful mode) and call get_ticket."""
    app = server.streamable_http_app(host=config.host)
    async with running(server):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=BASE_URL,
                                      headers={"Authorization": f"Bearer {token}"}) as http:
            async with Client(streamable_http_client(RESOURCE, http_client=http)) as mcp:
                result = await mcp.call_tool("get_ticket", {"ticket_id": ticket_id})
    return bool(result.is_error), "\n".join(item.text for item in result.content)


@pytest.mark.parametrize("algorithm", ["RS256", "ES256"])
async def test_static_key_environment_builds_a_working_server(tmp_path, directory_file, algorithm):
    idp = TestIdentityProvider(algorithm)
    key_file = write_private_file(tmp_path / "issuer-public.pem", idp.public_pem(), mode=0o644)
    config = SecureConfig.from_env(base_env(directory_file, DVMCP_SECURE_PUBLIC_KEY_FILE=str(key_file)))
    assert (config.host, config.port, config.required_scopes) == ("127.0.0.1", 8765, [READ])

    server = build_server(config)
    staff = await call_as(server, config, idp.issue("sam", f"{READ} {INTERNAL}", audience=RESOURCE), 7001)
    customer = await call_as(build_server(config), config, idp.issue("alice", f"{READ} {INTERNAL}", audience=RESOURCE), 7001)
    assert staff[0] is False and INTERNAL_BODY in staff[1]
    assert customer[0] is True and INTERNAL_BODY not in customer[1]


async def test_jwks_environment_builds_a_working_server(tmp_path, directory_file):
    jwks = LocalJWKSServer(tmp_path)
    try:
        idp = TestIdentityProvider("ES256")
        jwks.keys = [idp.jwk()]
        config = SecureConfig.from_env(base_env(
            directory_file, DVMCP_SECURE_JWKS_URL=jwks.url, DVMCP_SECURE_JWKS_CA_FILE=str(jwks.ca_file)))
        server = build_server(config)
        assert jwks.requests == 1  # keys were prefetched at startup
        is_error, text = await call_as(server, config, idp.issue("sam", f"{READ} {INTERNAL}", audience=RESOURCE), 7001)
        assert not is_error and INTERNAL_BODY in text
    finally:
        jwks.close()


def test_unreachable_jwks_fails_at_startup(directory_file):
    config = SecureConfig.from_env(base_env(
        directory_file, DVMCP_SECURE_JWKS_URL=f"https://127.0.0.1:{closed_port()}/jwks.json"))
    with pytest.raises(ConfigurationError, match="Could not load signing keys"):
        build_server(config)


def test_bad_directory_fails_at_startup(tmp_path):
    idp = TestIdentityProvider()
    key_file = write_private_file(tmp_path / "issuer-public.pem", idp.public_pem())
    bad = write_private_file(tmp_path / "bad.json", directory_json(("sam", ["staff"]), ("sam", ["staff"])))
    config = SecureConfig.from_env(base_env(bad, DVMCP_SECURE_PUBLIC_KEY_FILE=str(key_file)))
    with pytest.raises(ConfigurationError, match="duplicate identity"):
        build_server(config)


@pytest.mark.parametrize("overrides, message", [
    ({"DVMCP_SECURE_ISSUER": None}, "DVMCP_SECURE_ISSUER"),
    ({"DVMCP_SECURE_ISSUER": "  "}, "DVMCP_SECURE_ISSUER"),
    ({"DVMCP_SECURE_RESOURCE_URL": None}, "DVMCP_SECURE_RESOURCE_URL"),
    ({"DVMCP_SECURE_DIRECTORY_FILE": None}, "DVMCP_SECURE_DIRECTORY_FILE"),
    ({}, "exactly one signing-key source"),
    ({"DVMCP_SECURE_PUBLIC_KEY_FILE": "k.pem", "DVMCP_SECURE_JWKS_URL": "https://idp.test.invalid/jwks"},
     "exactly one signing-key source"),
    ({"DVMCP_SECURE_PUBLIC_KEY_FILE": "k.pem", "DVMCP_SECURE_JWKS_CA_FILE": "ca.pem"}, "JWKS CA file"),
    ({"DVMCP_SECURE_PUBLIC_KEY_FILE": "k.pem", "DVMCP_SECURE_PORT": "eighty"}, "must be a number"),
    ({"DVMCP_SECURE_PUBLIC_KEY_FILE": "k.pem", "DVMCP_SECURE_PORT": "70000"}, "between 1 and 65535"),
    ({"DVMCP_SECURE_PUBLIC_KEY_FILE": "k.pem", "DVMCP_SECURE_REQUIRED_SCOPES": " "}, "required scope"),
    ({"DVMCP_SECURE_PUBLIC_KEY_FILE": "k.pem", "DVMCP_SECURE_INTERNAL_SCOPE": "tickets:read"}, "must differ"),
    ({"DVMCP_SECURE_PUBLIC_KEY_FILE": "k.pem", "DVMCP_SECURE_INTERNAL_SCOPE": 'bad"scope'}, "invalid scope"),
    ({"DVMCP_SECURE_PUBLIC_KEY_FILE": "k.pem", "DVMCP_SECURE_RESOURCE_URL": "http://localhost.evil.example/mcp"},
     "Resource URL"),
])
def test_invalid_or_incomplete_environment_is_refused(directory_file, overrides, message):
    with pytest.raises(ConfigurationError, match=message):
        SecureConfig.from_env(base_env(directory_file, **overrides))


def test_unreadable_files_are_configuration_errors(tmp_path, directory_file):
    config = SecureConfig.from_env(base_env(directory_file, DVMCP_SECURE_PUBLIC_KEY_FILE=str(tmp_path / "none.pem")))
    with pytest.raises(ConfigurationError, match="Cannot read public key file"):
        build_server(config)
    config = SecureConfig.from_env(base_env(directory_file, DVMCP_SECURE_JWKS_URL="https://idp.test.invalid/jwks",
                                            DVMCP_SECURE_JWKS_CA_FILE=str(tmp_path / "none.pem")))
    with pytest.raises(ConfigurationError, match="JWKS CA file"):
        config.key_source()


def test_entrypoint_reports_configuration_errors_without_traceback(monkeypatch, capsys):
    for name in ("DVMCP_SECURE_ISSUER", "DVMCP_SECURE_DEBUG"):
        monkeypatch.delenv(name, raising=False)
    assert entrypoint.main() == 1
    err = capsys.readouterr().err
    assert "Configuration error: Missing required setting DVMCP_SECURE_ISSUER." in err
    assert "Traceback" not in err


def test_entrypoint_hides_unexpected_error_details(monkeypatch, capsys):
    monkeypatch.delenv("DVMCP_SECURE_DEBUG", raising=False)

    def explode():
        raise RuntimeError("internal detail that should not be printed")

    monkeypatch.setattr(entrypoint.SecureConfig, "from_env", staticmethod(explode))
    assert entrypoint.main() == 1
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "internal detail" not in err and "Traceback" not in err

    monkeypatch.setenv("DVMCP_SECURE_DEBUG", "1")
    with pytest.raises(RuntimeError):
        entrypoint.main()
