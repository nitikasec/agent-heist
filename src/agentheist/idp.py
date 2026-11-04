"""A tiny simulated identity provider and downstream API for token-handling levels.

Tokens are real signed JWTs (HS256 with a lab-only key), so audience and scope checks
behave like they do in production. Nothing here talks to the network.
"""

import time
from dataclasses import dataclass

import jwt

ISSUER = "https://login.acmecloud.example/"
LAB_SIGNING_KEY = "agent-heist-lab-only-signing-key-not-a-secret"
ALGORITHM = "HS256"

MCP_SERVER_AUDIENCE = "https://mcp.billing.acmecloud.example/"
BILLING_API_AUDIENCE = "https://api.billing.acmecloud.example/"


def issue(subject: str, audience: str, scope: str, lifetime: int = 10 * 365 * 24 * 3600) -> str:
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": subject, "aud": audience, "scope": scope, "iat": now, "exp": now + lifetime}
    return jwt.encode(claims, LAB_SIGNING_KEY, algorithm=ALGORITHM)


class TokenError(Exception):
    pass


@dataclass(frozen=True)
class Claims:
    subject: str
    audience: str
    scopes: frozenset[str]


def verify(token: str, audience: str | None) -> Claims:
    """Verify signature, issuer and expiry. Check the audience only when one is given."""
    options = {"require": ["iss", "sub", "aud", "exp"], "verify_aud": audience is not None}
    try:
        claims = jwt.decode(
            token, LAB_SIGNING_KEY, algorithms=[ALGORITHM], issuer=ISSUER, audience=audience, options=options
        )
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    return Claims(claims["sub"], claims["aud"], frozenset(str(claims.get("scope", "")).split()))
