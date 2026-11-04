"""Numeric environment settings: malformed values are configuration errors, never crashes in int()."""

import pytest
from secure_support import ISSUER, RESOURCE

from agentheist.secure import __main__ as entrypoint
from agentheist.secure.auth import ConfigurationError
from agentheist.secure.config import SecureConfig

SETTINGS = {
    "AGENTHEIST_SECURE_PORT": ("port", "must be a number"),
    "AGENTHEIST_SECURE_MAX_TOKEN_LIFETIME_SECONDS": ("max_token_lifetime_seconds", "must be a whole number of seconds"),
}
NOT_ASCII_DIGITS = [
    "²",  # superscript two: isdigit() is True, int() raises
    "8000²",
    "٨٠٠٠",  # Arabic-Indic digits: int() would quietly accept them
    "８０００",  # full-width digits
    "-1", "+8000", "8_000", "8 000", "0x1f40", "1e3", "8000.0", "", "  ", "eighty",
]


def env(name, value):
    return {"AGENTHEIST_SECURE_ISSUER": ISSUER, "AGENTHEIST_SECURE_RESOURCE_URL": RESOURCE,
            "AGENTHEIST_SECURE_PUBLIC_KEY_FILE": "k.pem", "AGENTHEIST_SECURE_DIRECTORY_FILE": "p.json", name: value}


@pytest.mark.parametrize("name", SETTINGS)
@pytest.mark.parametrize("value", NOT_ASCII_DIGITS)
def test_non_ascii_or_non_decimal_values_are_refused(name, value):
    with pytest.raises(ConfigurationError, match=f"{name} {SETTINGS[name][1]}"):
        SecureConfig.from_env(env(name, value))


@pytest.mark.parametrize("name", SETTINGS)
@pytest.mark.parametrize("value", ["1" + "0" * 18, "9" * 5000, "0" * 5000 + "9" * 19])
def test_oversized_values_are_refused_without_crashing(name, value):
    with pytest.raises(ConfigurationError, match=f"{name} is too large"):
        SecureConfig.from_env(env(name, value))


@pytest.mark.parametrize("name", SETTINGS)
@pytest.mark.parametrize("value", ["9" * 18, "0" * 5000 + "9" * 18])
def test_longest_parseable_values_reach_the_range_check(name, value):
    with pytest.raises(ConfigurationError, match="between"):
        SecureConfig.from_env(env(name, value))


@pytest.mark.parametrize("value, port", [("1", 1), ("65535", 65535), (" 8000 ", 8000), ("0008000", 8000),
                                         ("0" * 5000 + "8000", 8000)])
def test_valid_ports(value, port):
    assert SecureConfig.from_env(env("AGENTHEIST_SECURE_PORT", value)).port == port


@pytest.mark.parametrize("value", ["0", "65536", "000"])
def test_out_of_range_ports(value):
    with pytest.raises(ConfigurationError, match="between 1 and 65535"):
        SecureConfig.from_env(env("AGENTHEIST_SECURE_PORT", value))


@pytest.mark.parametrize("value, seconds", [("60", 60), ("86400", 86400), ("0000060", 60)])
def test_valid_lifetimes(value, seconds):
    assert SecureConfig.from_env(env("AGENTHEIST_SECURE_MAX_TOKEN_LIFETIME_SECONDS", value)).max_token_lifetime_seconds \
        == seconds


@pytest.mark.parametrize("name", SETTINGS)
@pytest.mark.parametrize("value", ["²", "9" * 5000])
def test_entrypoint_reports_a_configuration_error(monkeypatch, capsys, name, value):
    """The original bug: these values used to surface as 'Startup failed (ValueError)'."""
    for key, val in env(name, value).items():
        monkeypatch.setenv(key, val)
    monkeypatch.delenv("AGENTHEIST_SECURE_DEBUG", raising=False)
    assert entrypoint.main() == 1
    err = capsys.readouterr().err
    assert err.startswith(f"Configuration error: {name}") and "Startup failed" not in err and "Traceback" not in err
    assert len(err) < 200  # the oversized value is not echoed back
