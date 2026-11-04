"""Identifier validation and audit-log integrity (audit finding H4)."""

import json
import logging

import pytest
from secure_support import ISSUER, RESOURCE, TestIdentityProvider

from agentheist.secure.auth import JWTTokenVerifier, StaticPublicKey, is_safe_identifier
from agentheist.secure.helpdesk import audit

UNSAFE_SUBJECTS = [
    'alice\n{"decision": "allow", "subject": "sam", "tool": "get_ticket"}',
    "alice\r\nINFO second line",
    "alice\x00",
    "alice\x1b[2K",
    "alice next",
    "",
    "x" * 256,
]


@pytest.mark.parametrize("subject", UNSAFE_SUBJECTS)
def test_unsafe_identifiers_are_detected(subject):
    assert not is_safe_identifier(subject)


@pytest.mark.parametrize("subject", ["alice", "auth0|5f7c8ec7c33c6c004bbafe82", "user@example.com", "x" * 255])
def test_normal_identifiers_are_accepted(subject):
    assert is_safe_identifier(subject)


@pytest.mark.parametrize("subject", UNSAFE_SUBJECTS)
async def test_token_with_unsafe_subject_is_rejected(subject):
    idp = TestIdentityProvider()
    v = JWTTokenVerifier(issuer=ISSUER, audience=RESOURCE, key_source=StaticPublicKey(idp.public_pem()))
    assert await v.verify_token(idp.issue(subject)) is None


@pytest.mark.parametrize("value", UNSAFE_SUBJECTS + ["ünïcödé", 'quote " and backslash \\'])
def test_audit_event_is_always_one_parseable_line(caplog, value):
    caplog.set_level(logging.INFO, logger="agentheist.secure.audit")
    audit(tool="get_ticket", subject=value, ticket=1, decision="deny")

    records = [r for r in caplog.records if r.name == "agentheist.secure.audit"]
    assert len(records) == 1
    message = records[0].getMessage()
    assert "\n" not in message and "\r" not in message and message.isascii() and message.isprintable()
    assert json.loads(message) == {"tool": "get_ticket", "subject": value, "ticket": 1, "decision": "deny"}
