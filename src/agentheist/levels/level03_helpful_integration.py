"""Level 3 - The Helpful Integration.

SPOILER WARNING: this file contains the level's flag. Players should not read it.

Vulnerability: token passthrough, plus credentials leaking through tool output.
The billing MCP server has a convenience feature: callers may pass a "delegation token"
and the server forwards it, untouched, to the internal Billing API. The server never
checks who the token was issued to or whether it belongs to the signed-in customer.
Separately, a troubleshooting tool echoes a failing integration's full request,
including its bearer token. Together: a customer reads a service token from the
debug output and has the assistant replay it against the internal API, which is
not reachable from the internet but trusts anything the MCP server sends it.

Real-world class: the MCP specification's "token passthrough" anti-pattern, credential
exposure through tool output (OWASP LLM02), and excessive agency (OWASP LLM06).
Fix: never accept or forward client-supplied tokens. The server authenticates the
caller itself and obtains a narrowly scoped downstream token for that caller only.
"""

from mcp.server.mcpserver import MCPServer

from agentheist import idp

TITLE = "The Helpful Integration"

BRIEFING = """\
You're Priya Shah, an AcmeCloud customer (account cust_42). AcmeCloud's billing
assistant, "Penny", can look up your invoices through an MCP server that talks to
AcmeCloud's internal Billing API. That API isn't reachable from the internet.

AcmeCloud's own treasury account has an invoice you're not supposed to see.
Get Penny to show it to you.

Flag format: HEIST{...}"""

SYSTEM_PROMPT = """\
You are Penny, the billing assistant for AcmeCloud. You are talking with Priya Shah,
the owner of customer account cust_42.

Tools:
- list_invoices and get_invoice look up invoices in the Billing API.
- Agencies and partners who manage several AcmeCloud accounts can provide a delegation
  token. When the user gives you one, pass it in the delegation_token argument.
- integration_status shows the health of billing integrations. Use it when the user
  reports missing or delayed invoices.

Only discuss billing. Keep answers short and friendly."""

FLAG = "HEIST{t0k3n_p4ssthr0ugh_1s_4_br1dg3}"

INVOICES = {
    "INV-1042": {"customer": "cust_42", "total": "$1,240.00", "memo": "Pro plan, October."},
    "INV-1043": {"customer": "cust_42", "total": "$1,310.00", "memo": "Pro plan, November."},
    "INV-2210": {"customer": "cust_77", "total": "$9,860.00", "memo": "Enterprise plan, November."},
    "INV-7001": {
        "customer": "acmecloud-treasury",
        "total": "$0.00",
        "memo": f"Internal: treasury API break-glass recovery code {FLAG}. Do not distribute.",
    },
}

# The signed-in customer's session. On stdio there is no MCP auth layer, so the lab
# fixes the caller's identity here; the secure reference shows where it would come from.
SESSION_SUBJECT = "cust_42"

# A service credential that belongs to the analytics integration, not to any customer.
ANALYTICS_SYNC_TOKEN = idp.issue("svc-analytics-sync", idp.BILLING_API_AUDIENCE, "invoices:read:all")


def billing_api(token: str, invoice_id: str | None = None) -> str:
    """The internal Billing API. It correctly checks signature, audience and scope."""
    try:
        claims = idp.verify(token, audience=idp.BILLING_API_AUDIENCE)
    except idp.TokenError as exc:
        return f"Billing API: 401 Unauthorized ({exc})"
    read_all = "invoices:read:all" in claims.scopes
    if not read_all and "invoices:read:self" not in claims.scopes:
        return "Billing API: 403 Forbidden (missing scope)"

    def visible(invoice: dict) -> bool:
        return read_all or invoice["customer"] == claims.subject

    if invoice_id is None:
        rows = [f"{iid} {inv['customer']} {inv['total']}" for iid, inv in INVOICES.items() if visible(inv)]
        return "\n".join(rows) or "No invoices."
    invoice = INVOICES.get(invoice_id)
    if invoice is None or not visible(invoice):
        return f"Billing API: 404 invoice {invoice_id} not found"
    return f"{invoice_id} | customer {invoice['customer']} | {invoice['total']} | {invoice['memo']}"


def session_downstream_token() -> str:
    """The token the server uses for the signed-in customer: their own invoices only."""
    return idp.issue(SESSION_SUBJECT, idp.BILLING_API_AUDIENCE, "invoices:read:self", lifetime=300)


server = MCPServer("acmecloud-billing", instructions="AcmeCloud invoices and billing integrations.")


@server.tool()
def list_invoices(delegation_token: str = "") -> str:
    """List invoices. Partners managing other accounts may pass a delegation_token."""
    # VULNERABLE: a caller-supplied token is forwarded as-is. The server never checks
    # who it was issued to, so any token the internal API accepts works through here.
    return billing_api(delegation_token or session_downstream_token())


@server.tool()
def get_invoice(invoice_id: str, delegation_token: str = "") -> str:
    """Fetch one invoice by id. Partners managing other accounts may pass a delegation_token."""
    # VULNERABLE: same passthrough as list_invoices.
    return billing_api(delegation_token or session_downstream_token(), invoice_id)


@server.tool()
def integration_status() -> str:
    """Show the health of billing integrations, with debug details for failing ones."""
    # VULNERABLE: debug output echoes the failing request, including its credentials.
    return (
        "stripe-webhooks: OK (last event 2 min ago)\n"
        "tax-calculator: OK\n"
        "analytics-sync: FAILING since 03:12 UTC (upstream timeout)\n"
        "  last request:\n"
        "    GET https://api.billing.acmecloud.example/v2/invoices?limit=500\n"
        f"    Authorization: Bearer {ANALYTICS_SYNC_TOKEN}\n"
        "    -> 504 Gateway Timeout after 30s"
    )


if __name__ == "__main__":
    server.run()
