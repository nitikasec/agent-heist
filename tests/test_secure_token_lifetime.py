"""Maximum token lifetime, exp - iat (audit finding H6)."""

import time

import httpx2
import pytest
from secure_support import (
    BASE_URL, ISSUER, READ, RESOURCE, TestIdentityProvider, directory_json, running, write_private_file,
)

from agentheist.secure import auth
from agentheist.secure.auth import ConfigurationError, JWTTokenVerifier, StaticPublicKey
from agentheist.secure.config import SecureConfig
from agentheist.secure.helpdesk import build_server

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}


@pytest.fixture
def idp():
    return TestIdentityProvider()


def verifier(idp, **kwargs) -> JWTTokenVerifier:
    return JWTTokenVerifier(issuer=ISSUER, audience=RESOURCE, key_source=StaticPublicKey(idp.public_pem()), **kwargs)


def token(idp, *, iat, exp) -> str:
    return idp.sign({"iss": ISSUER, "sub": "sam", "aud": RESOURCE, "iat": iat, "exp": exp, "scope": READ})


def test_default_limit_is_one_hour():
    assert auth.DEFAULT_MAX_TOKEN_LIFETIME_SECONDS == 3600
    assert SecureConfig(issuer=ISSUER, resource_url=RESOURCE, public_key_file="k.pem").max_token_lifetime_seconds == 3600


@pytest.mark.parametrize("limit", [None, 600, 60, 86400])
@pytest.mark.parametrize("delta, accepted", [(0, True), (1, False)])
async def test_lifetime_boundary(idp, limit, delta, accepted):
    kwargs = {} if limit is None else {"max_token_lifetime_seconds": limit}
    v = verifier(idp, **kwargs)
    now = int(time.time())
    result = await v.verify_token(token(idp, iat=now, exp=now + v.max_token_lifetime_seconds + delta))
    assert (result is not None) is accepted


async def test_old_iat_with_fresh_exp_is_rejected(idp):
    """A long-lived token stays rejected however close to expiry it is."""
    now = int(time.time())
    assert await verifier(idp).verify_token(token(idp, iat=now - 86400, exp=now + 60)) is None


@pytest.mark.parametrize("iat_offset, exp_offset", [(10, 10), (20, 5), (20, 19)])
async def test_non_positive_lifetime_is_rejected(idp, iat_offset, exp_offset):
    """exp at or before iat. Both are within what jwt.decode allows, so only the lifetime check rejects it."""
    now = int(time.time())
    assert await verifier(idp).verify_token(token(idp, iat=now + iat_offset, exp=now + exp_offset)) is None


async def test_shortest_positive_lifetime_is_accepted(idp):
    now = int(time.time())
    assert await verifier(idp).verify_token(token(idp, iat=now + 9, exp=now + 10)) is not None


async def test_iat_in_the_future_beyond_leeway_is_rejected(idp):
    now = int(time.time())
    assert await verifier(idp).verify_token(token(idp, iat=now + 120, exp=now + 600)) is None


async def test_iat_in_the_future_within_leeway_is_accepted(idp):
    now = int(time.time())
    assert await verifier(idp).verify_token(token(idp, iat=now + 20, exp=now + 20 + 3600)) is not None


@pytest.mark.parametrize("iat", [True, "now", None, 1.5e300])
async def test_malformed_iat_is_rejected(idp, iat):
    now = int(time.time())
    assert await verifier(idp).verify_token(token(idp, iat=iat, exp=now + 300)) is None


async def test_missing_iat_is_rejected(idp):
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "sam", "aud": RESOURCE, "exp": now + 300, "scope": READ}
    assert await verifier(idp).verify_token(idp.sign(claims)) is None


@pytest.mark.parametrize("limit", [59, 86401, 0, -1, True, 3600.0, "3600", None])
def test_out_of_range_limits_are_refused(idp, limit):
    with pytest.raises(ConfigurationError, match="Maximum token lifetime"):
        verifier(idp, max_token_lifetime_seconds=limit)
    with pytest.raises(ConfigurationError, match="Maximum token lifetime"):
        SecureConfig(issuer=ISSUER, resource_url=RESOURCE, public_key_file="k.pem", max_token_lifetime_seconds=limit)


def env(tmp_path, idp, **overrides):
    key_file = write_private_file(tmp_path / "issuer-public.pem", idp.public_pem())
    directory = write_private_file(tmp_path / "principals.json", directory_json(("sam", ["staff"])))
    values = {"AGENTHEIST_SECURE_ISSUER": ISSUER, "AGENTHEIST_SECURE_RESOURCE_URL": RESOURCE,
              "AGENTHEIST_SECURE_PUBLIC_KEY_FILE": str(key_file), "AGENTHEIST_SECURE_DIRECTORY_FILE": str(directory),
              **overrides}
    return {key: value for key, value in values.items() if value is not None}


@pytest.mark.parametrize("value, expected", [(None, 3600), ("60", 60), (" 900 ", 900), ("86400", 86400)])
def test_environment_setting_reaches_the_verifier(tmp_path, idp, value, expected):
    config = SecureConfig.from_env(env(tmp_path, idp, AGENTHEIST_SECURE_MAX_TOKEN_LIFETIME_SECONDS=value))
    assert config.max_token_lifetime_seconds == expected
    assert config.token_verifier().max_token_lifetime_seconds == expected


@pytest.mark.parametrize("value, message", [
    ("59", "between 60 and 86400"), ("86401", "between 60 and 86400"), ("0", "between 60 and 86400"),
    ("", "whole number"), ("-5", "whole number"), ("1h", "whole number"), ("3600.0", "whole number"),
])
def test_invalid_environment_setting_is_refused(tmp_path, idp, value, message):
    with pytest.raises(ConfigurationError, match=message):
        SecureConfig.from_env(env(tmp_path, idp, AGENTHEIST_SECURE_MAX_TOKEN_LIFETIME_SECONDS=value))


@pytest.mark.parametrize("lifetime, status", [(900, 200), (901, 401)])
async def test_limit_is_enforced_over_http(tmp_path, idp, lifetime, status):
    config = SecureConfig.from_env(env(tmp_path, idp, AGENTHEIST_SECURE_MAX_TOKEN_LIFETIME_SECONDS="900"))
    server = build_server(config)
    app = server.streamable_http_app(host=config.host)
    now = int(time.time())
    async with running(server):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=BASE_URL) as client:
            response = await client.post("/mcp", json=INITIALIZE, headers={
                **HEADERS, "Authorization": f"Bearer {token(idp, iat=now, exp=now + lifetime)}"})
    assert response.status_code == status
