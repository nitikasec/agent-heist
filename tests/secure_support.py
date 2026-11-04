"""TEST-ONLY helpers for the secure helpdesk tests.

Everything here generates throwaway keys and certificates at test time. Nothing is a
production identity provider, and no key material is stored in the repository.
"""

import asyncio
import datetime
import ipaddress
import json
import os
import socket
import ssl
import threading
import time
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

ISSUER = "https://idp.test.invalid"
BASE_URL = "http://127.0.0.1:8000"
RESOURCE = f"{BASE_URL}/mcp"
READ = "tickets:read"
INTERNAL = "tickets:read_internal"


class TestIdentityProvider:
    """TEST-ONLY token issuer. Generates a fresh RS256 or ES256 key pair per instance."""

    __test__ = False  # not a pytest test class

    def __init__(self, algorithm: str = "RS256", *, issuer: str = ISSUER, kid: str = "test-key-1"):
        self.algorithm = algorithm
        self.issuer = issuer
        self.kid = kid
        if algorithm == "RS256":
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif algorithm == "ES256":
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            raise ValueError(algorithm)

    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def jwk(self) -> dict:
        algorithm = RSAAlgorithm if self.algorithm == "RS256" else ECAlgorithm
        return {**algorithm.to_jwk(self.private_key.public_key(), as_dict=True),
                "kid": self.kid, "use": "sig", "alg": self.algorithm}

    def sign(self, claims: dict, *, headers: dict | None = None) -> str:
        return jwt.encode(claims, self.private_key, algorithm=self.algorithm,
                          headers={"kid": self.kid, **(headers or {})})

    def issue(self, subject: str, scope: str = READ, *, audience: str = RESOURCE, issuer: str | None = None,
              expires_in: int = 300, **extra_claims) -> str:
        now = int(time.time())
        return self.sign({
            "iss": issuer or self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": now + expires_in,
            "scope": scope,
            "client_id": "test-client",
            **extra_claims,
        })


def _self_signed_localhost_cert() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agentheist-test-jwks")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


class LocalJWKSServer:
    """TEST-ONLY HTTPS JWKS endpoint on 127.0.0.1 that counts requests."""

    def __init__(self, directory: Path):
        cert_pem, key_pem = _self_signed_localhost_cert()
        self.ca_file = directory / "jwks-test-cert.pem"
        key_file = directory / "jwks-test-cert-key.pem"
        self.ca_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)
        os.chmod(key_file, 0o600)

        self.keys: list[dict] = []
        self.status = 200
        self.requests = 0
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                server.requests += 1
                if server.status != 200:
                    self.send_error(server.status)
                    return
                body = json.dumps({"keys": server.keys}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.ca_file, key_file)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}/jwks.json"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def client_ssl_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.ca_file))

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def closed_port() -> int:
    """A localhost port with nothing listening on it."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class HangingServer:
    """Accepts TCP connections (via the listen backlog) but never answers, to exercise timeouts."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.url = f"https://127.0.0.1:{self.sock.getsockname()[1]}/jwks.json"

    def close(self) -> None:
        self.sock.close()


def write_private_file(path: Path, content: str | bytes, mode: int = 0o600) -> Path:
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    os.chmod(path, mode)
    return path


def directory_json(*principals: tuple[str, list[str]], issuer: str = ISSUER) -> str:
    return json.dumps({"principals": [
        {"issuer": issuer, "subject": subject, "roles": roles} for subject, roles in principals
    ]})


@asynccontextmanager
async def running(server):
    """Run the SDK session manager in its own task (its task group must enter and exit in one task)."""
    started, stop = asyncio.Event(), asyncio.Event()

    async def run_session_manager():
        async with server.session_manager.run():
            started.set()
            await stop.wait()

    runner = asyncio.create_task(run_session_manager())
    await started.wait()
    try:
        yield
    finally:
        stop.set()
        await runner
