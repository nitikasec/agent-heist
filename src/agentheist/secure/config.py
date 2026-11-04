"""Configuration for the secure helpdesk, read from environment variables.

Every trust setting must be supplied explicitly; there are no built-in identities or keys.
"""

import ipaddress
import os
import re
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from agentheist.secure.auth import (
    DEFAULT_MAX_TOKEN_LIFETIME_SECONDS,
    ConfigurationError,
    JWKSKeySource,
    JWTTokenVerifier,
    PrincipalDirectory,
    SigningKeySource,
    StaticPublicKey,
    validate_max_token_lifetime,
)

DEFAULT_READ_SCOPE = "tickets:read"
DEFAULT_INTERNAL_SCOPE = "tickets:read_internal"

# Plain http is only acceptable to these exact (already lowercased) hostnames.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_DNS_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
# RFC 6749 section 3.3 scope-token characters.
_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")
# ASCII digits only: str.isdigit() also accepts "²", "٨" and full-width digits.
_WHOLE_NUMBER = re.compile(r"\A[0-9]+\Z")
# More digits than any accepted setting needs, and far below int()'s 4300-digit conversion limit.
_MAX_NUMBER_DIGITS = 18


def _validate_hostname(host: str) -> None:
    if ":" in host:  # urlsplit only yields ':' for a bracketed IPv6 literal
        if "%" in host:
            raise ValueError("IPv6 zone identifiers are not allowed")
        ipaddress.IPv6Address(host)  # raises ValueError if malformed
        return
    try:
        ipaddress.IPv4Address(host)
        return
    except ValueError:
        pass
    labels = host.split(".")
    if len(host) > 253 or not all(_DNS_LABEL.match(label) for label in labels):
        raise ValueError("invalid hostname")
    if labels[-1].isdigit():  # e.g. "127.1" or "2130706433": ambiguous numeric hosts
        raise ValueError("numeric hostname that is not a valid IP address")


def validate_url(url: str, *, setting: str, allow_loopback_http: bool) -> str:
    """Validate a security-relevant URL by parsing it. Returns the URL unchanged."""

    def fail(reason: str) -> ConfigurationError:
        return ConfigurationError(f"{setting} is not acceptable: {reason}.")

    if not isinstance(url, str) or not url:
        raise fail("empty")
    if any(not 0x21 <= ord(char) <= 0x7E for char in url) or "\\" in url:
        raise fail("contains whitespace, control, non-ASCII or backslash characters")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError for an invalid port
        host = parts.hostname
    except ValueError as exc:
        raise fail(f"malformed URL ({exc})") from exc
    if parts.scheme not in ("https", "http"):
        raise fail("scheme must be https" + (" (or http on localhost)" if allow_loopback_http else ""))
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise fail("user info (user@host) is not allowed")
    if not host:
        raise fail("missing hostname")
    if parts.fragment or url.endswith("#"):
        raise fail("fragments are not allowed")
    try:
        _validate_hostname(host)
    except ValueError as exc:
        raise fail(str(exc)) from exc
    if parts.scheme == "http" and not (allow_loopback_http and host in LOOPBACK_HOSTS):
        allowed = ", ".join(sorted(LOOPBACK_HOSTS))
        raise fail(f"plain http is only allowed for exactly {allowed}" if allow_loopback_http else "must use https")
    return url


def _parse_whole_number(value: str, setting: str, description: str) -> int:
    """Parse a non-negative decimal setting; range checks are left to SecureConfig."""
    if not _WHOLE_NUMBER.match(value):
        raise ConfigurationError(f"{setting} must be {description}.")
    significant = value.lstrip("0") or "0"  # int()'s digit limit counts leading zeros too
    if len(significant) > _MAX_NUMBER_DIGITS:
        raise ConfigurationError(f"{setting} is too large.")
    return int(significant)


def _validate_scope(scope: str, setting: str) -> str:
    if not _SCOPE_TOKEN.match(scope):
        raise ConfigurationError(f"{setting} contains an invalid scope token.")
    return scope


@dataclass(frozen=True)
class SecureConfig:
    issuer: str
    resource_url: str
    required_scopes: list[str] = field(default_factory=lambda: [DEFAULT_READ_SCOPE])
    internal_scope: str = DEFAULT_INTERNAL_SCOPE
    jwks_url: str | None = None
    jwks_ca_file: str | None = None
    public_key_file: str | None = None
    directory_file: str | None = None
    host: str = "127.0.0.1"
    port: int = 8000
    max_token_lifetime_seconds: int = DEFAULT_MAX_TOKEN_LIFETIME_SECONDS

    def __post_init__(self):
        validate_url(self.issuer, setting="Issuer", allow_loopback_http=False)
        validate_url(self.resource_url, setting="Resource URL", allow_loopback_http=True)
        if bool(self.jwks_url) == bool(self.public_key_file):
            raise ConfigurationError("Configure exactly one signing-key source: a JWKS URL or a public key file.")
        if self.jwks_url:
            validate_url(self.jwks_url, setting="JWKS URL", allow_loopback_http=False)
        if self.jwks_ca_file and not self.jwks_url:
            raise ConfigurationError("A JWKS CA file only applies together with a JWKS URL.")
        if not self.required_scopes:
            raise ConfigurationError("At least one required scope must be configured.")
        for scope in self.required_scopes:
            _validate_scope(scope, "Required scopes")
        _validate_scope(self.internal_scope, "Internal scope")
        if self.internal_scope in self.required_scopes:
            raise ConfigurationError("The internal scope must differ from the scopes every caller needs.")
        if not 1 <= self.port <= 65535:
            raise ConfigurationError("Port must be between 1 and 65535.")
        if not self.host:
            raise ConfigurationError("Host must not be empty.")
        validate_max_token_lifetime(self.max_token_lifetime_seconds)

    @property
    def binds_to_loopback(self) -> bool:
        """True only for the exact hosts the MCP SDK protects against DNS rebinding (Host/Origin checks)."""
        return self.host in LOOPBACK_HOSTS

    def startup_warnings(self) -> list[str]:
        if self.binds_to_loopback:
            return []
        return [
            f"AGENTHEIST_SECURE_HOST={self.host!r} is not one of {', '.join(sorted(LOOPBACK_HOSTS))}. The server serves"
            " plain HTTP and the MCP SDK's Host/Origin (DNS-rebinding) checks are off, so bearer tokens and"
            " tickets can cross the network unencrypted. Only do this behind a TLS-terminating reverse proxy"
            " on a trusted network."
        ]

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "SecureConfig":
        env = os.environ if env is None else env

        def required(name: str) -> str:
            value = env.get(name, "").strip()
            if not value:
                raise ConfigurationError(f"Missing required setting {name}.")
            return value

        port = _parse_whole_number(env.get("AGENTHEIST_SECURE_PORT", "8000").strip(), "AGENTHEIST_SECURE_PORT", "a number")
        lifetime = _parse_whole_number(
            env.get("AGENTHEIST_SECURE_MAX_TOKEN_LIFETIME_SECONDS", str(DEFAULT_MAX_TOKEN_LIFETIME_SECONDS)).strip(),
            "AGENTHEIST_SECURE_MAX_TOKEN_LIFETIME_SECONDS", "a whole number of seconds")
        return cls(
            issuer=required("AGENTHEIST_SECURE_ISSUER"),
            resource_url=required("AGENTHEIST_SECURE_RESOURCE_URL"),
            required_scopes=env.get("AGENTHEIST_SECURE_REQUIRED_SCOPES", DEFAULT_READ_SCOPE).split(),
            internal_scope=env.get("AGENTHEIST_SECURE_INTERNAL_SCOPE", DEFAULT_INTERNAL_SCOPE).strip(),
            jwks_url=env.get("AGENTHEIST_SECURE_JWKS_URL", "").strip() or None,
            jwks_ca_file=env.get("AGENTHEIST_SECURE_JWKS_CA_FILE", "").strip() or None,
            public_key_file=env.get("AGENTHEIST_SECURE_PUBLIC_KEY_FILE", "").strip() or None,
            directory_file=required("AGENTHEIST_SECURE_DIRECTORY_FILE"),
            host=env.get("AGENTHEIST_SECURE_HOST", "127.0.0.1").strip(),
            port=port,
            max_token_lifetime_seconds=lifetime,
        )

    def key_source(self) -> SigningKeySource:
        if self.jwks_url:
            ssl_context = None
            if self.jwks_ca_file:
                try:
                    ssl_context = ssl.create_default_context(cafile=self.jwks_ca_file)
                except (OSError, ssl.SSLError) as exc:
                    raise ConfigurationError(f"Cannot load JWKS CA file {self.jwks_ca_file}.") from exc
            return JWKSKeySource(self.jwks_url, ssl_context=ssl_context)
        return StaticPublicKey.from_file(self.public_key_file)

    def token_verifier(self) -> JWTTokenVerifier:
        return JWTTokenVerifier(issuer=self.issuer, audience=self.resource_url, key_source=self.key_source(),
                                max_token_lifetime_seconds=self.max_token_lifetime_seconds)

    def directory(self) -> PrincipalDirectory:
        return PrincipalDirectory.from_file(self.directory_file, trusted_issuer=self.issuer)
