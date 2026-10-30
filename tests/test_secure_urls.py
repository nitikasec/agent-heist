"""URL validation for security-relevant settings (audit finding V1)."""

import pytest

from dvmcp.secure.auth import ConfigurationError
from dvmcp.secure.config import SecureConfig, validate_url

ISSUER = "https://idp.test.invalid"


@pytest.mark.parametrize("url", [
    "http://localhost/mcp",
    "http://localhost:8000/mcp",
    "http://127.0.0.1:8000/mcp",
    "http://[::1]:8000/mcp",
    "HTTP://LOCALHOST:8000/mcp",  # scheme and hostname are case-insensitive
    "https://helpdesk.example.com/mcp",
    "https://helpdesk.example.com:8443/mcp",
    "https://203.0.113.10/mcp",
    "https://[2001:db8::1]/mcp",
])
def test_resource_url_accepts_https_and_exact_loopback_http(url):
    assert validate_url(url, setting="Resource URL", allow_loopback_http=True) == url


@pytest.mark.parametrize("url", [
    # hostname suffix tricks: the hostname only starts with a loopback name
    "http://localhost.attack127.0.0.1.nip.io/mcp",
    "http://localhost.evil.example/mcp",
    "http://127.0.0.1.nip.io/mcp",
    "http://localhost./mcp",
    # user info tricks: the real host is after the @
    "http://localhost@evil.example/mcp",
    "http://user:pass@localhost/mcp",
    "https://localhost:443@evil.example/mcp",
    # other loopback spellings are not the exact allowed hostnames
    "http://127.1/mcp",
    "http://2130706433/mcp",
    "http://[::ffff:127.0.0.1]/mcp",
    "http://[0:0:0:0:0:0:0:1]/mcp",
    "http://[fe80::1%25eth0]/mcp",
    # plain http to a non-loopback host
    "http://helpdesk.example.com/mcp",
    # other schemes
    "ftp://localhost/mcp",
    "file:///etc/passwd",
    "javascript:alert(1)",
    # malformed
    "",
    "localhost/mcp",
    "http:///mcp",
    "http://[::1/mcp",
    "http://localhost:99999/mcp",
    "http://localhost:abc/mcp",
    " http://localhost/mcp",
    "http://local host/mcp",
    "http://localhost\\@evil.example/mcp",
    "http://localhost/mcp#fragment",
    "http://localhost/mcp\n",
    "https://-bad-.example/mcp",
    "https://exa_mple.com/mcp",
])
def test_resource_url_rejects_bypasses_and_malformed_input(url):
    with pytest.raises(ConfigurationError):
        validate_url(url, setting="Resource URL", allow_loopback_http=True)


@pytest.mark.parametrize("url", ["http://localhost/issuer", "http://127.0.0.1", "http://[::1]/"])
def test_issuer_and_jwks_urls_never_allow_http(url):
    with pytest.raises(ConfigurationError):
        validate_url(url, setting="Issuer", allow_loopback_http=False)


def test_secure_config_applies_url_validation():
    base = {"issuer": ISSUER, "public_key_file": "key.pem", "directory_file": "d.json"}
    with pytest.raises(ConfigurationError, match="Resource URL"):
        SecureConfig(resource_url="http://localhost.evil.example/mcp", **base)
    with pytest.raises(ConfigurationError, match="Issuer"):
        SecureConfig(**{**base, "issuer": "https://user@idp.test.invalid"}, resource_url="http://localhost/mcp")
    with pytest.raises(ConfigurationError, match="JWKS URL"):
        SecureConfig(issuer=ISSUER, resource_url="http://localhost/mcp", jwks_url="http://localhost/jwks",
                     directory_file="d.json")
    assert SecureConfig(resource_url="http://[::1]:8000/mcp", **base).resource_url == "http://[::1]:8000/mcp"
