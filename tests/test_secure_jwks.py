"""JWKS key source over real HTTPS (audit finding H1).

Uses the TEST-ONLY local JWKS server from secure_support, with a temporary self-signed
certificate trusted only by the test's SSL context.
"""

import asyncio
import time

import jwt
import pytest
from secure_support import ISSUER, RESOURCE, HangingServer, LocalJWKSServer, TestIdentityProvider, closed_port

from agentheist.secure import auth
from agentheist.secure.auth import ConfigurationError, JWKSKeySource, JWTTokenVerifier


@pytest.fixture
def jwks(tmp_path):
    server = LocalJWKSServer(tmp_path)
    yield server
    server.close()


def verifier(source: JWKSKeySource) -> JWTTokenVerifier:
    return JWTTokenVerifier(issuer=ISSUER, audience=RESOURCE, key_source=source)


def source_for(jwks: LocalJWKSServer, **options) -> JWKSKeySource:
    return JWKSKeySource(jwks.url, ssl_context=jwks.client_ssl_context(), **options)


def test_jwks_client_settings_are_explicit():
    source = JWKSKeySource("https://idp.test.invalid/jwks.json")
    client = source._client
    assert client.timeout == auth.JWKS_TIMEOUT_SECONDS == 5.0
    assert client.jwk_set_cache is not None and client.jwk_set_cache.lifespan == auth.JWKS_CACHE_LIFESPAN_SECONDS == 300.0
    assert client.cooldown_duration == auth.JWKS_REFRESH_COOLDOWN_SECONDS == 30.0
    assert not hasattr(client.get_signing_key, "cache_info")  # no per-key LRU cache that outlives the key set


def test_jwks_url_must_be_https():
    with pytest.raises(ConfigurationError):
        JWKSKeySource("http://idp.test.invalid/jwks.json")


@pytest.mark.parametrize("algorithm", ["RS256", "ES256"])
async def test_key_is_found_by_kid(jwks, algorithm):
    idp = TestIdentityProvider(algorithm)
    jwks.keys = [idp.jwk()]
    access = await verifier(source_for(jwks)).verify_token(idp.issue("alice"))
    assert access is not None and access.subject == "alice"
    assert jwks.requests == 1


async def test_cached_key_set_is_reused(jwks):
    idp = TestIdentityProvider()
    jwks.keys = [idp.jwk()]
    v = verifier(source_for(jwks))
    for _ in range(5):
        assert await v.verify_token(idp.issue("alice")) is not None
    assert jwks.requests == 1


async def test_unknown_kid_is_rejected_and_refreshes_are_rate_limited(jwks):
    idp = TestIdentityProvider(kid="known")
    jwks.keys = [idp.jwk()]
    v = verifier(source_for(jwks))
    assert await v.verify_token(idp.issue("alice")) is not None
    for index in range(20):
        unknown = TestIdentityProvider(kid=f"unknown-{index}")
        assert await v.verify_token(unknown.issue("alice")) is None
    assert jwks.requests == 1  # still inside the refresh cooldown: no further network fetches


async def test_token_without_kid_is_rejected_without_network_access(jwks):
    idp = TestIdentityProvider()
    jwks.keys = [idp.jwk()]
    v = verifier(source_for(jwks))
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "alice", "aud": RESOURCE, "iat": now, "exp": now + 300}
    assert await v.verify_token(jwt.encode(claims, idp.private_key, algorithm="RS256")) is None
    assert jwks.requests == 0


async def test_rotated_key_is_picked_up_after_the_cooldown(jwks):
    old, new = TestIdentityProvider(kid="old"), TestIdentityProvider(kid="new")
    jwks.keys = [old.jwk()]
    v = verifier(source_for(jwks, refresh_cooldown=0.3))
    assert await v.verify_token(old.issue("alice")) is not None

    jwks.keys = [old.jwk(), new.jwk()]
    assert await v.verify_token(new.issue("alice")) is None  # inside the cooldown: not fetched yet
    assert jwks.requests == 1
    await asyncio.sleep(0.4)
    assert await v.verify_token(new.issue("alice")) is not None
    assert jwks.requests == 2


async def test_removed_key_stops_working_when_the_cache_expires(jwks):
    old, new = TestIdentityProvider(kid="old"), TestIdentityProvider(kid="new")
    jwks.keys = [old.jwk()]
    v = verifier(source_for(jwks, cache_lifespan=0.3, refresh_cooldown=0.1))
    assert await v.verify_token(old.issue("alice")) is not None

    jwks.keys = [new.jwk()]
    await asyncio.sleep(0.4)
    assert await v.verify_token(old.issue("alice")) is None
    assert await v.verify_token(new.issue("alice")) is not None


async def test_symmetric_key_in_the_key_set_is_never_used(jwks):
    secret = b"test-only-shared-secret-value-123456"
    jwks.keys = [{"kty": "oct", "k": jwt.utils.base64url_encode(secret).decode(), "kid": "oct", "alg": "HS256"}]
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "alice", "aud": RESOURCE, "iat": now, "exp": now + 300}
    token = jwt.encode(claims, secret, algorithm="HS256", headers={"kid": "oct"})
    assert await verifier(source_for(jwks)).verify_token(token) is None


async def test_unreachable_endpoint_fails_closed():
    source = JWKSKeySource(f"https://127.0.0.1:{closed_port()}/jwks.json", timeout=1.0)
    started = time.monotonic()
    assert await verifier(source).verify_token(TestIdentityProvider().issue("alice")) is None
    assert time.monotonic() - started < 3


async def test_hanging_endpoint_times_out():
    hanging = HangingServer()
    try:
        source = JWKSKeySource(hanging.url, timeout=0.5)
        started = time.monotonic()
        assert await verifier(source).verify_token(TestIdentityProvider().issue("alice")) is None
        assert time.monotonic() - started < 3
    finally:
        hanging.close()


async def test_failing_endpoint_is_not_retried_on_every_request(jwks):
    jwks.status = 500
    v = verifier(source_for(jwks))
    for _ in range(10):
        assert await v.verify_token(TestIdentityProvider().issue("alice")) is None
    assert jwks.requests == 1


async def test_untrusted_certificate_fails_closed(jwks):
    idp = TestIdentityProvider()
    jwks.keys = [idp.jwk()]
    source = JWKSKeySource(jwks.url)  # system trust store: the test certificate is not trusted
    assert await verifier(source).verify_token(idp.issue("alice")) is None


def test_prefetch_reports_unreachable_endpoint_as_configuration_error():
    source = JWKSKeySource(f"https://127.0.0.1:{closed_port()}/jwks.json", timeout=1.0)
    with pytest.raises(ConfigurationError, match="Could not load signing keys"):
        source.prefetch()


def test_prefetch_succeeds_against_a_working_endpoint(jwks):
    jwks.keys = [TestIdentityProvider().jwk()]
    source_for(jwks).prefetch()
    assert jwks.requests == 1
