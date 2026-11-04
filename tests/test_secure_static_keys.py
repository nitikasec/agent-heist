"""Static public-key verification: RS256, ES256 and algorithm-to-key binding."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from secure_support import ISSUER, READ, RESOURCE, TestIdentityProvider

from agentheist.secure.auth import ConfigurationError, JWTTokenVerifier, StaticPublicKey


def verifier_for(idp: TestIdentityProvider) -> JWTTokenVerifier:
    return JWTTokenVerifier(issuer=ISSUER, audience=RESOURCE, key_source=StaticPublicKey(idp.public_pem()))


@pytest.mark.parametrize("algorithm", ["RS256", "ES256"])
async def test_valid_token_is_verified(algorithm):
    idp = TestIdentityProvider(algorithm)
    access = await verifier_for(idp).verify_token(idp.issue("alice"))
    assert access is not None
    assert access.subject == "alice"
    assert access.scopes == [READ]
    assert access.claims == {"iss": ISSUER}


@pytest.mark.parametrize("algorithm", ["RS256", "ES256"])
async def test_token_from_a_different_key_is_rejected(algorithm):
    assert await verifier_for(TestIdentityProvider(algorithm)).verify_token(
        TestIdentityProvider(algorithm).issue("alice")
    ) is None


async def test_es256_token_is_rejected_by_an_rsa_configured_server():
    rsa_idp, ec_idp = TestIdentityProvider("RS256"), TestIdentityProvider("ES256")
    assert await verifier_for(rsa_idp).verify_token(ec_idp.issue("alice")) is None


async def test_rs256_token_is_rejected_by_an_ec_configured_server():
    rsa_idp, ec_idp = TestIdentityProvider("RS256"), TestIdentityProvider("ES256")
    assert await verifier_for(ec_idp).verify_token(rsa_idp.issue("alice")) is None


async def test_hs256_token_signed_with_the_public_key_bytes_is_rejected():
    idp = TestIdentityProvider("RS256")
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "alice", "aud": RESOURCE, "iat": now, "exp": now + 300, "scope": READ}
    # Classic key-confusion attempt: HMAC "signed" with the public key's PEM as the secret.
    # PyJWT refuses to sign with PEM-looking secrets, so build the HMAC token by hand.
    import base64, hashlib, hmac, json

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    signing_input = f"{b64(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())}.{b64(json.dumps(claims).encode())}"
    signature = hmac.new(idp.public_pem(), signing_input.encode(), hashlib.sha256).digest()
    assert await verifier_for(idp).verify_token(f"{signing_input}.{b64(signature)}") is None


def test_small_rsa_keys_and_other_curves_are_refused():
    small_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key()
    for key in (small_rsa, p384):
        pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with pytest.raises(ConfigurationError):
            StaticPublicKey(pem)


def test_invalid_pem_and_missing_file_are_configuration_errors(tmp_path):
    with pytest.raises(ConfigurationError):
        StaticPublicKey(b"-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n")
    with pytest.raises(ConfigurationError, match="Cannot read public key file"):
        StaticPublicKey.from_file(tmp_path / "missing.pem")


async def test_static_keys_do_not_use_worker_threads(monkeypatch):
    import anyio.to_thread

    def fail(*args, **kwargs):
        raise AssertionError("static key lookup should not use a worker thread")

    monkeypatch.setattr(anyio.to_thread, "run_sync", fail)
    idp = TestIdentityProvider("ES256")
    assert await verifier_for(idp).verify_token(idp.issue("alice")) is not None


async def test_algorithm_not_bound_to_the_key_is_rejected():
    idp = TestIdentityProvider("RS256")
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "alice", "aud": RESOURCE, "iat": now, "exp": now + 300}
    token = jwt.encode(claims, idp.private_key, algorithm="RS512")  # correctly signed, but only RS256 is allowed
    assert await verifier_for(idp).verify_token(token) is None
