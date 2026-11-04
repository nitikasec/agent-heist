"""Authorization over both SDK HTTP modes and both key types (audit finding H2).

"stateful" is the SDK default used by `python -m agentheist.secure` (sessions + SSE responses);
"stateless" is JSON responses with no sessions.
"""

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from secure_support import BASE_URL, INTERNAL, ISSUER, READ, RESOURCE, TestIdentityProvider, running

from agentheist.secure.auth import JWTTokenVerifier, PrincipalDirectory, StaticPublicKey
from agentheist.secure.config import SecureConfig
from agentheist.secure.helpdesk import NOT_AUTHORIZED, TICKETS, create_server

INTERNAL_BODY = TICKETS[7001]["body"]
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}
MODES = {
    "stateless": {"stateless_http": True, "json_response": True},
    "stateful": {},
}


def build(idp: TestIdentityProvider):
    directory = PrincipalDirectory({(ISSUER, "alice"): ["customer"], (ISSUER, "sam"): ["staff"]}, trusted_issuer=ISSUER)
    config = SecureConfig(issuer=ISSUER, resource_url=RESOURCE, public_key_file="unused", directory_file="unused")
    verifier = JWTTokenVerifier(issuer=ISSUER, audience=RESOURCE, key_source=StaticPublicKey(idp.public_pem()))
    return create_server(config, verifier, directory)


@pytest.fixture(params=["RS256", "ES256"])
def idp(request):
    return TestIdentityProvider(request.param)


@pytest.fixture(params=sorted(MODES))
async def app(request, idp):
    server = build(idp)
    asgi_app = server.streamable_http_app(host="127.0.0.1", **MODES[request.param])
    async with running(server):
        yield asgi_app


def http(app, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=BASE_URL, headers=headers)


async def call(app, token, tool, arguments=None):
    async with http(app, token) as client, Client(streamable_http_client(RESOURCE, http_client=client)) as mcp:
        result = await mcp.call_tool(tool, arguments or {})
    return bool(result.is_error), "\n".join(item.text for item in result.content)


async def test_missing_and_foreign_tokens_are_rejected(app, idp):
    async with http(app) as client:
        assert (await client.post("/mcp", json=INITIALIZE, headers=HEADERS)).status_code == 401
    foreign = TestIdentityProvider(idp.algorithm).issue("sam", f"{READ} {INTERNAL}")
    async with http(app, foreign) as client:
        assert (await client.post("/mcp", json=INITIALIZE, headers=HEADERS)).status_code == 401


async def test_customer_is_limited_to_public_tickets(app, idp):
    token = idp.issue("alice", f"{READ} {INTERNAL}")
    is_error, text = await call(app, token, "get_ticket", {"ticket_id": 7001})
    assert is_error and INTERNAL_BODY not in text
    _, listing = await call(app, token, "list_tickets")
    assert "#2001" in listing and "#7001" not in listing


async def test_staff_can_read_internal_ticket(app, idp):
    is_error, text = await call(app, idp.issue("sam", f"{READ} {INTERNAL}"), "get_ticket", {"ticket_id": 7001})
    assert not is_error and INTERNAL_BODY in text


async def test_unknown_subject_is_denied(app, idp):
    is_error, text = await call(app, idp.issue("bob"), "list_tickets")
    assert is_error and NOT_AUTHORIZED in text


@pytest.mark.parametrize("app", ["stateful"], indirect=True)
async def test_session_id_cannot_be_used_by_another_user(app, idp):
    async with http(app, idp.issue("sam", f"{READ} {INTERNAL}")) as staff:
        response = await staff.post("/mcp", json=INITIALIZE, headers=HEADERS)
        assert response.status_code == 200
        session_id = response.headers["mcp-session-id"]

    request = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": "get_ticket", "arguments": {"ticket_id": 7001}}}
    async with http(app, idp.issue("alice", f"{READ} {INTERNAL}")) as customer:
        response = await customer.post("/mcp", json=request, headers={**HEADERS, "mcp-session-id": session_id})
    assert response.status_code == 404
    assert INTERNAL_BODY not in response.text

    async with http(app) as anonymous:
        response = await anonymous.post("/mcp", json=request, headers={**HEADERS, "mcp-session-id": session_id})
    assert response.status_code == 401
