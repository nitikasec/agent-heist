"""Tests for the secure helpdesk over the SDK's real streamable-HTTP app, in-process.

The identity provider below is TEST-ONLY: it generates throwaway RSA keys at test
time and signs JWTs with them. It exists to exercise the verifier and the
authorization logic; it is not a production identity provider.
"""

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from dvmcp.secure.auth import JWTTokenVerifier, PrincipalDirectory, StaticPublicKey
from dvmcp.secure.config import SecureConfig
from dvmcp.secure.helpdesk import NOT_AUTHORIZED, NOT_FOUND, TICKETS, create_server

ISSUER = "https://idp.test.invalid"
BASE_URL = "http://127.0.0.1:8000"
RESOURCE = f"{BASE_URL}/mcp"
READ = "tickets:read"
INTERNAL = "tickets:read_internal"
INTERNAL_BODY = TICKETS[7001]["body"]


class TestIdentityProvider:
    """TEST-ONLY token issuer with a key pair generated per test run."""

    __test__ = False  # not a pytest test class

    def __init__(self, issuer: str = ISSUER):
        self.issuer = issuer
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def issue(self, subject: str, scope: str = READ, *, audience: str = RESOURCE, issuer: str | None = None,
              expires_in: int = 300, **extra_claims) -> str:
        now = int(time.time())
        claims = {
            "iss": issuer or self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": now + expires_in,
            "scope": scope,
            "client_id": "test-client",
            **extra_claims,
        }
        return jwt.encode(claims, self.private_key, algorithm="RS256")


@pytest.fixture
def idp():
    return TestIdentityProvider()


@pytest.fixture
def directory():
    return PrincipalDirectory({
        (ISSUER, "alice"): ["customer"],
        (ISSUER, "sam"): ["staff"],
    })


@pytest.fixture
def server(idp, directory):
    config = SecureConfig(issuer=ISSUER, resource_url=RESOURCE, public_key_file="unused", directory_file="unused")
    verifier = JWTTokenVerifier(issuer=ISSUER, audience=RESOURCE, key_source=StaticPublicKey(idp.public_pem()))
    return create_server(config, verifier, directory)


@pytest.fixture
async def app(server):
    asgi_app = server.streamable_http_app(stateless_http=True, json_response=True, host="127.0.0.1")
    # The session manager's task group must be entered and exited in the same task, but
    # pytest-asyncio runs fixture setup and teardown in different tasks, so own it here.
    started, stop = asyncio.Event(), asyncio.Event()

    async def run_session_manager():
        async with server.session_manager.run():
            started.set()
            await stop.wait()

    runner = asyncio.create_task(run_session_manager())
    await started.wait()
    yield asgi_app
    stop.set()
    await runner


def http_client(app, token: str | None) -> httpx2.AsyncClient:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=BASE_URL, headers=headers)


async def initialize_status(app, token: str | None) -> int:
    """Send a raw MCP initialize request and return the HTTP status."""
    async with http_client(app, token) as client:
        response = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "test", "version": "0"}},
            },
            headers={"Accept": "application/json, text/event-stream"},
        )
    return response.status_code


@asynccontextmanager
async def mcp_session(app, token: str):
    async with http_client(app, token) as http:
        async with Client(streamable_http_client(RESOURCE, http_client=http)) as client:
            yield client


async def call(app, token: str, tool: str, arguments: dict | None = None) -> tuple[bool, str]:
    async with mcp_session(app, token) as client:
        result = await client.call_tool(tool, arguments or {})
    return bool(result.is_error), "\n".join(item.text for item in result.content)


# --- authentication: rejected at the HTTP boundary -------------------------------------------


async def test_no_bearer_token_is_rejected(app):
    assert await initialize_status(app, None) == 401


async def test_garbage_token_is_rejected(app):
    assert await initialize_status(app, "not-a-jwt") == 401


async def test_invalid_signature_is_rejected(app):
    other_idp = TestIdentityProvider()  # same issuer name, different key
    assert await initialize_status(app, other_idp.issue("sam", f"{READ} {INTERNAL}")) == 401


async def test_expired_token_is_rejected(app, idp):
    assert await initialize_status(app, idp.issue("alice", expires_in=-3600)) == 401


async def test_wrong_issuer_is_rejected(app, idp):
    assert await initialize_status(app, idp.issue("alice", issuer="https://evil.test.invalid")) == 401


async def test_wrong_audience_is_rejected(app, idp):
    assert await initialize_status(app, idp.issue("alice", audience="https://other-service.test.invalid/mcp")) == 401


async def test_unsigned_token_is_rejected(app):
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "sam", "aud": RESOURCE, "iat": now, "exp": now + 300, "scope": READ}
    assert await initialize_status(app, jwt.encode(claims, key=None, algorithm="none")) == 401


async def test_token_missing_required_claim_is_rejected(app, idp):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": RESOURCE, "iat": now, "exp": now + 300, "scope": READ}  # no "sub"
    assert await initialize_status(app, jwt.encode(claims, idp.private_key, algorithm="RS256")) == 401


async def test_token_without_required_scope_is_forbidden(app, idp):
    assert await initialize_status(app, idp.issue("alice", scope="profile")) == 403


async def test_valid_token_is_accepted(app, idp):
    assert await initialize_status(app, idp.issue("alice")) == 200


async def test_staff_role_claim_in_invalid_token_is_not_trusted(app):
    forged = TestIdentityProvider().issue("mallory", f"{READ} {INTERNAL}", roles=["staff"], role="staff")
    assert await initialize_status(app, forged) == 401


# --- authorization: enforced inside the tools ------------------------------------------------


async def test_customer_can_read_public_ticket(app, idp):
    is_error, text = await call(app, idp.issue("alice"), "get_ticket", {"ticket_id": 2001})
    assert not is_error
    assert TICKETS[2001]["body"] in text


async def test_customer_cannot_read_internal_ticket(app, idp):
    token = idp.issue("alice", f"{READ} {INTERNAL}")  # even with the internal scope, the role is missing
    is_error, text = await call(app, token, "get_ticket", {"ticket_id": 7001})
    assert is_error
    assert NOT_FOUND in text
    assert INTERNAL_BODY not in text


async def test_internal_ticket_denial_matches_unknown_ticket(app, idp):
    token = idp.issue("alice")
    internal = await call(app, token, "get_ticket", {"ticket_id": 7001})
    unknown = await call(app, token, "get_ticket", {"ticket_id": 424242})
    assert internal == unknown == (True, internal[1])
    assert NOT_FOUND in unknown[1]


async def test_customer_cannot_discover_internal_tickets(app, idp):
    token = idp.issue("alice")
    _, listing = await call(app, token, "list_tickets")
    _, search = await call(app, token, "search_tickets", {"query": "runbook"})
    assert "#2001" in listing and "#7001" not in listing and "INTERNAL" not in listing
    assert "#7001" not in search


async def test_staff_can_read_internal_ticket(app, idp):
    token = idp.issue("sam", f"{READ} {INTERNAL}")
    is_error, text = await call(app, token, "get_ticket", {"ticket_id": 7001})
    assert not is_error
    assert INTERNAL_BODY in text
    _, listing = await call(app, token, "list_tickets")
    assert "#7001" in listing


async def test_staff_without_internal_scope_is_denied(app, idp):
    is_error, text = await call(app, idp.issue("sam"), "get_ticket", {"ticket_id": 7001})
    assert is_error and INTERNAL_BODY not in text


async def test_role_claim_in_valid_token_grants_nothing(app, idp):
    token = idp.issue("alice", f"{READ} {INTERNAL}", roles=["staff"], role="staff")
    is_error, text = await call(app, token, "get_ticket", {"ticket_id": 7001})
    assert is_error and INTERNAL_BODY not in text


async def test_role_in_tool_arguments_grants_nothing(app, idp):
    token = idp.issue("alice", f"{READ} {INTERNAL}")
    is_error, text = await call(app, token, "get_ticket", {"ticket_id": 7001, "role": "staff", "is_staff": True})
    assert is_error and INTERNAL_BODY not in text


async def test_valid_token_for_unknown_subject_is_denied(app, idp):
    is_error, text = await call(app, idp.issue("bob"), "get_ticket", {"ticket_id": 2001})
    assert is_error
    assert NOT_AUTHORIZED in text


async def test_authorization_is_checked_on_every_invocation(app, idp, directory):
    token = idp.issue("sam", f"{READ} {INTERNAL}")
    async with mcp_session(app, token) as client:
        first = await client.call_tool("get_ticket", {"ticket_id": 7001})
        directory.set_roles(ISSUER, "sam", ["customer"])
        second = await client.call_tool("get_ticket", {"ticket_id": 7001})
        directory.revoke(ISSUER, "sam")
        third = await client.call_tool("get_ticket", {"ticket_id": 2001})
    assert not first.is_error
    assert second.is_error and INTERNAL_BODY not in second.content[0].text
    assert third.is_error and NOT_AUTHORIZED in third.content[0].text


async def test_tools_fail_closed_without_http_auth(server):
    # The in-memory transport bypasses the HTTP auth middleware entirely; tools must still deny.
    async with Client(server) as client:
        for tool, arguments in [("get_ticket", {"ticket_id": 2001}), ("list_tickets", {}),
                                ("search_tickets", {"query": "a"})]:
            result = await client.call_tool(tool, arguments)
            assert result.is_error and NOT_AUTHORIZED in result.content[0].text


async def test_audit_log_never_contains_ticket_bodies(app, idp, caplog):
    caplog.set_level(logging.INFO, logger="dvmcp.secure.audit")
    await call(app, idp.issue("sam", f"{READ} {INTERNAL}"), "get_ticket", {"ticket_id": 7001})
    await call(app, idp.issue("alice"), "get_ticket", {"ticket_id": 7001})

    events = [json.loads(record.getMessage()) for record in caplog.records if record.name == "dvmcp.secure.audit"]
    assert {"tool": "get_ticket", "subject": "sam", "ticket": 7001, "decision": "allow"} in events
    assert {"tool": "get_ticket", "subject": "alice", "ticket": 7001, "decision": "deny"} in events
    assert INTERNAL_BODY not in caplog.text


# --- configuration ---------------------------------------------------------------------------


def test_private_key_material_is_refused(idp):
    pem = idp.private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(ValueError):
        StaticPublicKey(pem)


def test_symmetric_algorithms_are_refused(idp):
    with pytest.raises(ValueError):
        JWTTokenVerifier(issuer=ISSUER, audience=RESOURCE, key_source=StaticPublicKey(idp.public_pem()),
                         algorithms=["HS256"])


@pytest.mark.parametrize("overrides", [
    {"issuer": "http://idp.test.invalid"},
    {"resource_url": "http://example.test.invalid/mcp"},
    {"jwks_url": None, "public_key_file": None},
    {"jwks_url": "https://idp.test.invalid/jwks", "public_key_file": "key.pem"},
    {"required_scopes": []},
])
def test_insecure_configuration_is_refused(overrides):
    settings = {"issuer": ISSUER, "resource_url": RESOURCE, "public_key_file": "key.pem", "directory_file": "d.json"}
    with pytest.raises(ValueError):
        SecureConfig(**{**settings, **overrides})


def test_missing_environment_settings_are_refused():
    with pytest.raises(ValueError, match="DVMCP_SECURE_ISSUER"):
        SecureConfig.from_env({})


def test_directory_rejects_unknown_roles():
    with pytest.raises(ValueError):
        PrincipalDirectory({(ISSUER, "x"): ["superadmin"]})
