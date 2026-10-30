"""Authentication and identity for the secure helpdesk.

Trust chain:

1. The MCP SDK's bearer middleware hands every HTTP request's bearer token to
   `JWTTokenVerifier.verify_token`, which checks signature, issuer, audience,
   expiry and required claims against explicitly configured values.
2. The SDK stores the verified `AccessToken` in its auth context.
3. Tools call `resolve_principal`, which reads that context and looks the
   verified (issuer, subject) pair up in a server-side `PrincipalDirectory`.
   Roles come only from the directory, never from token claims, tool arguments
   or user messages.
"""

import json
import logging
import os
import ssl
import stat
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import anyio
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)

ALLOWED_ALGORITHMS = ("RS256", "ES256")
REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp", "iat")
MIN_RSA_KEY_BITS = 2048
MAX_IDENTIFIER_LENGTH = 255
MAX_KID_LENGTH = 128
MAX_DIRECTORY_BYTES = 1024 * 1024

# Longest token lifetime (exp - iat) accepted. Short-lived tokens bound the damage of a leaked token,
# since there is no revocation check.
DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 3600
MIN_TOKEN_LIFETIME_LIMIT_SECONDS = 60
MAX_TOKEN_LIFETIME_LIMIT_SECONDS = 86400

STAFF_ROLE = "staff"
CUSTOMER_ROLE = "customer"
KNOWN_ROLES = frozenset({STAFF_ROLE, CUSTOMER_ROLE})

# JWKS client settings (PyJWT 2.15 `PyJWKClient`), set explicitly rather than relying on defaults.
JWKS_TIMEOUT_SECONDS = 5.0  # per HTTP fetch, covers connect, TLS handshake and read
JWKS_CACHE_LIFESPAN_SECONDS = 300.0  # how long a fetched key set is trusted before re-fetching
JWKS_REFRESH_COOLDOWN_SECONDS = 30.0  # minimum gap between network fetches of any kind
JWKS_MAX_CONCURRENT_LOOKUPS = 4  # worker threads that may block on JWKS lookups at once


class ConfigurationError(ValueError):
    """Raised for invalid security configuration. Messages never include secrets or file contents."""


def validate_max_token_lifetime(seconds: object) -> int:
    if (isinstance(seconds, bool) or not isinstance(seconds, int)
            or not MIN_TOKEN_LIFETIME_LIMIT_SECONDS <= seconds <= MAX_TOKEN_LIFETIME_LIMIT_SECONDS):
        raise ConfigurationError(
            f"Maximum token lifetime must be a whole number of seconds between {MIN_TOKEN_LIFETIME_LIMIT_SECONDS}"
            f" and {MAX_TOKEN_LIFETIME_LIMIT_SECONDS}.")
    return seconds


def is_safe_identifier(value: object) -> bool:
    """True for non-empty, bounded strings with no control or line-break characters."""
    return isinstance(value, str) and 0 < len(value) <= MAX_IDENTIFIER_LENGTH and value.isprintable()


def algorithms_for_key(key: object) -> frozenset[str]:
    """The only JWT algorithm each supported public key type may verify."""
    if isinstance(key, rsa.RSAPublicKey) and key.key_size >= MIN_RSA_KEY_BITS:
        return frozenset({"RS256"})
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        return frozenset({"ES256"})
    return frozenset()


class SigningKeySource(Protocol):
    # True when `key_for` may block on network I/O and must run off the event loop.
    requires_io: bool

    def key_for(self, token: str) -> object:
        """Return the public key that should have signed `token`. Raise on any failure."""
        ...

    def prefetch(self) -> None:
        """Load keys eagerly so misconfiguration fails at startup."""
        ...


class StaticPublicKey:
    """A single trusted RSA (>= 2048 bit) or P-256 public key loaded from PEM. Private keys are rejected."""

    requires_io = False

    def __init__(self, pem: bytes):
        if b"PRIVATE KEY" in pem:
            raise ConfigurationError("Refusing to load private key material; configure the issuer's public key only.")
        try:
            self._key = load_pem_public_key(pem)
        except ValueError as exc:
            raise ConfigurationError("Public key is not a valid PEM public key.") from exc
        if not algorithms_for_key(self._key):
            raise ConfigurationError(f"Public key must be RSA >= {MIN_RSA_KEY_BITS} bits or EC P-256.")

    @classmethod
    def from_file(cls, path: str | Path) -> "StaticPublicKey":
        try:
            return cls(Path(path).read_bytes())
        except OSError as exc:
            raise ConfigurationError(f"Cannot read public key file {path}: {exc.strerror}") from exc

    def key_for(self, token: str) -> object:
        return self._key

    def prefetch(self) -> None:
        pass


class _RateLimitedJWKClient(jwt.PyJWKClient):
    """PyJWKClient that also rate-limits *failed* fetches.

    PyJWT's own cooldown only starts after a successful fetch, so while the
    identity provider is unreachable every unknown-`kid` request would hit the
    network. Here at most one fetch attempt, successful or not, happens per
    `min_fetch_interval`.
    """

    def __init__(self, uri: str, *, min_fetch_interval: float, **kwargs: Any):
        super().__init__(uri, **kwargs)
        self._min_fetch_interval = min_fetch_interval
        self._attempt_lock = threading.Lock()
        self._last_attempt: float | None = None

    def fetch_data(self) -> Any:
        with self._attempt_lock:
            now = time.monotonic()
            if self._last_attempt is not None and now - self._last_attempt < self._min_fetch_interval:
                raise jwt.PyJWKClientConnectionError("JWKS fetch suppressed: attempted too recently")
            self._last_attempt = now
        return super().fetch_data()


class JWKSKeySource:
    """Public keys fetched from the identity provider's JWKS endpoint, with bounded network use.

    - Each fetch times out after `timeout` seconds.
    - The key set is cached for `cache_lifespan` seconds. Individual keys are NOT cached
      separately, so a key removed from the JWKS stops being trusted when the cache expires.
    - An unknown `kid` (for example after key rotation) triggers at most one refresh per
      `refresh_cooldown`, and failed fetches are rate-limited the same way.
    - Tokens without a usable `kid` are rejected before any network access.
    """

    requires_io = True

    def __init__(
        self,
        jwks_url: str,
        *,
        timeout: float = JWKS_TIMEOUT_SECONDS,
        cache_lifespan: float = JWKS_CACHE_LIFESPAN_SECONDS,
        refresh_cooldown: float = JWKS_REFRESH_COOLDOWN_SECONDS,
        ssl_context: ssl.SSLContext | None = None,
    ):
        if not jwks_url.startswith("https://"):
            raise ConfigurationError("JWKS URL must use https.")
        self.jwks_url = jwks_url
        self._client = _RateLimitedJWKClient(
            jwks_url,
            min_fetch_interval=refresh_cooldown,
            cache_keys=False,
            cache_jwk_set=True,
            lifespan=cache_lifespan,
            timeout=timeout,
            cooldown_duration=refresh_cooldown,
            ssl_context=ssl_context,
        )

    def key_for(self, token: str) -> object:
        kid = jwt.get_unverified_header(token).get("kid")  # untrusted; only selects a candidate key
        if not isinstance(kid, str) or not 0 < len(kid) <= MAX_KID_LENGTH:
            raise jwt.InvalidTokenError("Token has no usable kid header")
        jwk = self._client.get_signing_key(kid)
        if jwk.algorithm_name not in ALLOWED_ALGORITHMS:
            raise jwt.InvalidTokenError("JWKS key uses a disallowed algorithm")
        return jwk.key

    def prefetch(self) -> None:
        try:
            self._client.get_signing_keys()
        except jwt.PyJWKClientError as exc:
            raise ConfigurationError(f"Could not load signing keys from {self.jwks_url}.") from exc


class JWTTokenVerifier:
    """Implements the MCP SDK's `TokenVerifier` protocol for signed JWT access tokens.

    Any failure returns None, which the SDK turns into HTTP 401.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        key_source: SigningKeySource,
        algorithms: Iterable[str] = ALLOWED_ALGORITHMS,
        leeway_seconds: int = 30,
        max_token_lifetime_seconds: int = DEFAULT_MAX_TOKEN_LIFETIME_SECONDS,
    ):
        self.issuer = issuer
        self.audience = audience
        self.key_source = key_source
        self.algorithms = frozenset(alg for alg in algorithms if alg in ALLOWED_ALGORITHMS)
        if not self.algorithms:
            raise ConfigurationError(f"At least one asymmetric algorithm from {ALLOWED_ALGORITHMS} is required.")
        self.leeway_seconds = leeway_seconds
        self.max_token_lifetime_seconds = validate_max_token_lifetime(max_token_lifetime_seconds)
        self._lookup_limiter: anyio.CapacityLimiter | None = None

    async def _key_for(self, token: str) -> object:
        if not self.key_source.requires_io:
            return self.key_source.key_for(token)
        if self._lookup_limiter is None:
            self._lookup_limiter = anyio.CapacityLimiter(JWKS_MAX_CONCURRENT_LOOKUPS)
        # JWKS lookups can hit the network: keep them off the event loop, on a bounded set of threads.
        return await anyio.to_thread.run_sync(self.key_source.key_for, token, limiter=self._lookup_limiter)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            key = await self._key_for(token)
            # Bind the algorithm to the key type so a key can only verify its own algorithm.
            algorithms = sorted(self.algorithms & algorithms_for_key(key))
            if not algorithms:
                raise jwt.InvalidAlgorithmError("No allowed algorithm for this key")
            claims = jwt.decode(
                token,
                key=key,
                algorithms=algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway_seconds,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except (jwt.PyJWTError, ValueError) as exc:
            logger.info("token rejected: %s", type(exc).__name__)
            return None

        # jwt.decode has already checked that exp and iat are integers, exp is not past and iat is not in the
        # future, so this also bounds how long from now the token can remain valid.
        if not 0 < int(claims["exp"]) - int(claims["iat"]) <= self.max_token_lifetime_seconds:
            logger.info("token rejected: lifetime is not positive or exceeds the maximum")
            return None
        subject = claims["sub"]
        if not is_safe_identifier(subject):
            logger.info("token rejected: invalid subject")
            return None
        scope = claims.get("scope", "")
        scopes = scope.split() if isinstance(scope, str) else []
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("azp") or "unknown"),
            scopes=scopes,
            expires_at=int(claims["exp"]),
            # Audience is enforced by jwt.decode above; this records the resource it was bound to.
            resource=self.audience,
            subject=subject,
            claims={"iss": claims["iss"]},
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    if duplicates:
        raise ConfigurationError(f"duplicate JSON keys {duplicates}")
    return dict(pairs)


def _read_protected_file(path: Path) -> bytes:
    """Read a security-sensitive file, refusing files that other users could have modified.

    POSIX only: on other platforms the permission checks are skipped (see README).
    """
    if os.name != "posix":
        return path.read_bytes()[: MAX_DIRECTORY_BYTES + 1]
    fd = os.open(path, os.O_RDONLY)
    try:
        info = os.fstat(fd)  # check the file we actually opened, not a path that could be swapped
        if not stat.S_ISREG(info.st_mode):
            raise ConfigurationError(f"{path} is not a regular file.")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ConfigurationError(f"{path} is group- or world-writable; run: chmod go-w {path}")
        if info.st_uid not in (os.geteuid(), 0):
            raise ConfigurationError(f"{path} must be owned by the server's user or root.")
        parent = os.stat(path.resolve().parent)
        if parent.st_mode & stat.S_IWOTH and not parent.st_mode & stat.S_ISVTX:
            raise ConfigurationError(f"The directory containing {path} is world-writable.")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read(MAX_DIRECTORY_BYTES + 1)
    finally:
        os.close(fd)


class PrincipalDirectory:
    """Server-side source of truth for which verified identities hold which roles."""

    def __init__(self, entries: dict[tuple[str, str], Iterable[str]] | None = None, *, trusted_issuer: str | None = None):
        self.trusted_issuer = trusted_issuer
        self._roles: dict[tuple[str, str], frozenset[str]] = {}
        for (issuer, subject), roles in (entries or {}).items():
            self.set_roles(issuer, subject, roles)

    @classmethod
    def from_file(cls, path: str | Path, *, trusted_issuer: str) -> "PrincipalDirectory":
        """Load and strictly validate a directory file. Errors name the record, never its contents."""
        path = Path(path)
        prefix = f"Principal directory {path}"
        try:
            raw = _read_protected_file(path)
        except OSError as exc:
            raise ConfigurationError(f"{prefix}: cannot read file: {exc.strerror}") from exc
        except ConfigurationError as exc:
            raise ConfigurationError(f"{prefix}: {exc}") from exc
        if len(raw) > MAX_DIRECTORY_BYTES:
            raise ConfigurationError(f"{prefix}: file is larger than {MAX_DIRECTORY_BYTES} bytes.")
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        except ConfigurationError as exc:
            raise ConfigurationError(f"{prefix}: {exc}") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConfigurationError(f"{prefix}: not valid UTF-8 JSON.") from exc

        if not isinstance(data, dict) or set(data) != {"principals"} or not isinstance(data["principals"], list):
            raise ConfigurationError(f'{prefix}: expected an object with exactly one key, "principals", holding a list.')

        directory = cls(trusted_issuer=trusted_issuer)
        for index, entry in enumerate(data["principals"]):
            where = f"{prefix}: principals[{index}]"
            if not isinstance(entry, dict) or set(entry) != {"issuer", "subject", "roles"}:
                raise ConfigurationError(f'{where}: expected exactly the keys "issuer", "subject" and "roles".')
            roles = entry["roles"]
            if not isinstance(roles, list) or not roles or not all(isinstance(role, str) for role in roles):
                raise ConfigurationError(f"{where}.roles: expected a non-empty list of strings.")
            if len(set(roles)) != len(roles):
                raise ConfigurationError(f"{where}.roles: duplicate roles.")
            key = (entry["issuer"], entry["subject"])
            if key in directory._roles:
                raise ConfigurationError(f"{where}: duplicate identity (same issuer and subject as an earlier entry).")
            try:
                directory.set_roles(entry["issuer"], entry["subject"], roles)
            except ConfigurationError as exc:
                raise ConfigurationError(f"{where}: {exc}") from exc
        return directory

    def set_roles(self, issuer: str, subject: str, roles: Iterable[str]) -> None:
        if self.trusted_issuer is not None and issuer != self.trusted_issuer:
            raise ConfigurationError("issuer does not match the configured trusted issuer.")
        if not is_safe_identifier(issuer) or not is_safe_identifier(subject):
            raise ConfigurationError("issuer and subject must be non-empty strings without control characters.")
        roles = frozenset(roles)
        unknown = roles - KNOWN_ROLES
        if unknown:
            raise ConfigurationError(f"unknown roles {sorted(unknown)}; allowed: {sorted(KNOWN_ROLES)}.")
        self._roles[(issuer, subject)] = roles

    def revoke(self, issuer: str, subject: str) -> None:
        self._roles.pop((issuer, subject), None)

    def roles_for(self, issuer: str, subject: str) -> frozenset[str]:
        return self._roles.get((issuer, subject), frozenset())


@dataclass(frozen=True)
class Principal:
    """A verified caller with permissions resolved from the server-side directory."""

    issuer: str
    subject: str
    roles: frozenset[str]
    scopes: frozenset[str]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


def resolve_principal(directory: PrincipalDirectory, trusted_issuer: str) -> Principal | None:
    """Build the caller's Principal from the SDK's verified auth context, or None to deny."""
    access_token = get_access_token()
    if access_token is None or not is_safe_identifier(access_token.subject):
        return None
    issuer = (access_token.claims or {}).get("iss")
    if issuer != trusted_issuer:
        return None
    roles = directory.roles_for(issuer, access_token.subject)
    if not roles:
        return None
    return Principal(
        issuer=issuer,
        subject=access_token.subject,
        roles=roles,
        scopes=frozenset(access_token.scopes),
    )
