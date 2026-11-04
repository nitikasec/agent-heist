import re

import pytest
from mcp import Client

from agentheist import idp
from agentheist.flags import check_flag
from agentheist.levels import get_level
from agentheist.levels import level03_secure_billing as secure
from agentheist.levels.level03_helpful_integration import (
    ANALYTICS_SYNC_TOKEN,
    FLAG,
    billing_api,
    server,
    session_downstream_token,
)

TOKEN_IN_OUTPUT = re.compile(r"Bearer (\S+)")


def text(result) -> str:
    return result.content[0].text


# --- the simulated identity provider and internal API --------------------------------------


def test_tokens_are_checked_for_audience_signature_and_scope():
    own = session_downstream_token()
    assert "INV-1042" in billing_api(own) and "INV-7001" not in billing_api(own)
    assert "404" in billing_api(own, "INV-7001")

    wrong_audience = idp.issue("cust_42", idp.MCP_SERVER_AUDIENCE, "invoices:read:all")
    assert "401" in billing_api(wrong_audience)

    forged = idp.jwt.encode({"iss": idp.ISSUER, "sub": "x", "aud": idp.BILLING_API_AUDIENCE, "exp": 2**31,
                             "scope": "invoices:read:all"}, "an-attacker-guessed-key-that-is-long-enough", algorithm="HS256")
    assert "401" in billing_api(forged)

    no_scope = idp.issue("cust_42", idp.BILLING_API_AUDIENCE, "profile:read")
    assert "403" in billing_api(no_scope)

    expired = idp.issue("cust_42", idp.BILLING_API_AUDIENCE, "invoices:read:self", lifetime=-60)
    assert "401" in billing_api(expired)


# --- the vulnerable level ------------------------------------------------------------------


async def test_server_exposes_expected_tools():
    async with Client(server) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
    assert names == {"list_invoices", "get_invoice", "integration_status"}


async def test_customer_sees_only_their_own_invoices_by_default():
    async with Client(server) as client:
        listing = text(await client.call_tool("list_invoices", {}))
        treasury = text(await client.call_tool("get_invoice", {"invoice_id": "INV-7001"}))
    assert "INV-1042" in listing and "INV-2210" not in listing
    assert FLAG not in treasury and "404" in treasury


async def test_leaked_service_token_passes_through_to_the_internal_api():
    async with Client(server) as client:
        status = text(await client.call_tool("integration_status", {}))
        leaked = TOKEN_IN_OUTPUT.search(status).group(1)
        listing = text(await client.call_tool("list_invoices", {"delegation_token": leaked}))
        treasury = text(await client.call_tool("get_invoice", {"invoice_id": "INV-7001", "delegation_token": leaked}))

    assert leaked == ANALYTICS_SYNC_TOKEN
    assert "INV-7001" in listing and "INV-2210" in listing
    assert FLAG in treasury


def test_level_metadata_and_flag():
    level = get_level(3)
    assert level.mode == "chat"
    assert "delegation_token" in level.system_prompt
    assert check_flag(3, FLAG)
    assert not check_flag(3, "HEIST{nope}")


# --- the secure reference ------------------------------------------------------------------


async def test_secure_server_has_no_token_parameters_and_leaks_no_credentials():
    async with Client(secure.server) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        status = text(await client.call_tool("integration_status", {}))
    for tool in tools.values():
        assert not any("token" in name for name in tool.input_schema.get("properties", {}))
    assert ANALYTICS_SYNC_TOKEN not in status
    assert not re.search(r"Bearer eyJ", status)


async def test_secure_server_ignores_the_stolen_token_and_blocks_cross_account_reads():
    async with Client(secure.server) as client:
        listing = text(await client.call_tool("list_invoices", {}))
        own = text(await client.call_tool("get_invoice", {"invoice_id": "INV-1042"}))
        other = text(await client.call_tool("get_invoice", {"invoice_id": "INV-7001", "account": "acmecloud-treasury"}))
        hidden = text(await client.call_tool("get_invoice", {"invoice_id": "INV-7001"}))
    assert "INV-1042" in listing and "INV-7001" not in listing
    assert "Pro plan" in own
    assert other.startswith("Not allowed:")
    assert FLAG not in hidden and "404" in hidden


async def test_secure_delegation_grants_come_from_the_server(monkeypatch):
    monkeypatch.setattr(secure, "DELEGATIONS", {"cust_42": frozenset({"cust_77"})})
    async with Client(secure.server) as client:
        granted = text(await client.call_tool("get_invoice", {"invoice_id": "INV-2210", "account": "cust_77"}))
        refused = text(await client.call_tool("get_invoice", {"invoice_id": "INV-7001", "account": "acmecloud-treasury"}))
    assert "Enterprise plan" in granted
    assert refused.startswith("Not allowed:")


def test_secure_session_token_must_be_issued_to_this_server(monkeypatch):
    assert secure.authenticated_subject() == "cust_42"
    monkeypatch.setattr(secure, "SESSION_TOKEN", ANALYTICS_SYNC_TOKEN)  # a token for a different audience
    with pytest.raises(idp.TokenError):
        secure.authenticated_subject()


def test_secure_redaction():
    assert secure.redact("Authorization: Bearer eyJabc.def-ghi_jk") == "Authorization: Bearer [REDACTED]"
