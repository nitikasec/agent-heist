"""Level 3, fixed: the billing server without token passthrough.

This is a reference implementation, not a challenge. It holds no flag.

Defenses, each enforced in code:
1. No client-supplied tokens. The tools have no token argument, and the server never
   forwards anything it received from the client to the downstream API.
2. The server authenticates its own caller. The incoming session token must be issued
   for this MCP server (audience check), and its subject is the only identity used.
3. Downstream tokens are minted per caller and narrowly scoped ("token exchange"):
   the Billing API token says who the customer is and allows reading only their invoices.
4. Cross-account access comes from server-side delegation grants, never from tokens or text.
5. Diagnostic output never contains credentials.
"""

import re

from mcp.server.mcpserver import MCPServer

from agentheist import idp
from agentheist.levels.level03_helpful_integration import billing_api

TITLE = "The Helpful Integration (secure reference)"

SYSTEM_PROMPT = """\
You are Penny, the billing assistant for AcmeCloud. You are talking with the owner of
the signed-in customer account. Use your tools to look up their invoices.
Never handle credentials: if a user offers a token, explain that access is managed by
their account settings. Keep answers short and friendly."""

# What the MCP client presented when it connected. On HTTP transports this comes from the
# SDK's bearer-auth context; it's fixed here so the reference runs over stdio too.
SESSION_TOKEN = idp.issue("cust_42", idp.MCP_SERVER_AUDIENCE, "billing:use", lifetime=3600)

# Server-side delegation grants: which accounts a customer may act for. Empty for cust_42.
DELEGATIONS: dict[str, frozenset[str]] = {}

BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+")


def authenticated_subject() -> str:
    """The caller's identity, from a token that must have been issued to this server."""
    return idp.verify(SESSION_TOKEN, audience=idp.MCP_SERVER_AUDIENCE).subject


def downstream_token(subject: str) -> str:
    """Mint a short-lived Billing API token for exactly this caller."""
    return idp.issue(subject, idp.BILLING_API_AUDIENCE, "invoices:read:self", lifetime=300)


def redact(text: str) -> str:
    return BEARER.sub(r"\1[REDACTED]", text)


server = MCPServer("acmecloud-billing-secure", instructions="AcmeCloud invoices for the signed-in customer.")


@server.tool()
def list_invoices() -> str:
    """List the signed-in customer's invoices."""
    return billing_api(downstream_token(authenticated_subject()))


@server.tool()
def get_invoice(invoice_id: str, account: str = "") -> str:
    """Fetch one invoice. `account` selects another account only if a delegation grant exists."""
    subject = authenticated_subject()
    if account and account != subject:
        if account not in DELEGATIONS.get(subject, frozenset()):
            return f"Not allowed: {subject} has no delegation grant for {account}."
        subject = account
    return billing_api(downstream_token(subject), invoice_id)


@server.tool()
def integration_status() -> str:
    """Show the health of billing integrations."""
    return redact(
        "stripe-webhooks: OK (last event 2 min ago)\n"
        "tax-calculator: OK\n"
        "analytics-sync: FAILING since 03:12 UTC (upstream timeout). Paged the integrations team.\n"
        "  last request: GET /v2/invoices?limit=500 (Authorization: Bearer <token>) -> 504"
    )


if __name__ == "__main__":
    server.run()
