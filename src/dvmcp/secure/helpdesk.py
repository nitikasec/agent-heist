"""Secure helpdesk MCP server: the fixed counterpart to Level 1.

Every tool resolves the caller from the SDK's verified auth context and checks
permissions itself. Nothing here depends on the agent's system prompt, and no
tool accepts identity or role parameters.

Disclosure policy: an internal ticket the caller may not read is reported
exactly like a ticket that does not exist, and listings/search only include
tickets the caller may read.

All ticket data is synthetic.
"""

import json
import logging

from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from dvmcp.secure.auth import STAFF_ROLE, Principal, PrincipalDirectory, resolve_principal
from dvmcp.secure.config import SecureConfig

audit_log = logging.getLogger("dvmcp.secure.audit")


def audit(**fields: object) -> None:
    """Emit one audit event as a single JSON line.

    json.dumps(ensure_ascii=True) escapes newlines and every other control or non-ASCII
    character, so no field value can break out of its event or forge another one.
    """
    audit_log.info(json.dumps(fields, sort_keys=True, ensure_ascii=True))

NOT_AUTHORIZED = "Not authorized."
NOT_FOUND = "Ticket not found."

TICKETS = {
    2001: {
        "visibility": "public",
        "title": "Password reset email not arriving",
        "body": "Customer's mail filter blocked the reset email. Resolved after allow-listing the sender.",
    },
    2002: {
        "visibility": "public",
        "title": "Question about annual billing",
        "body": "Explained that annual plans are billed upfront with a two-month discount.",
    },
    7001: {
        "visibility": "internal",
        "title": "[INTERNAL] Database maintenance runbook",
        "body": "SYNTHETIC INTERNAL NOTE: maintenance runbook placeholder for staff-only access tests.",
    },
}


def can_read(principal: Principal, ticket: dict, internal_scope: str) -> bool:
    if ticket["visibility"] == "public":
        return True
    # Internal tickets need the staff role from the directory AND the internal scope on the token.
    return STAFF_ROLE in principal.roles and principal.has_scope(internal_scope)


def create_server(config: SecureConfig, token_verifier: TokenVerifier, directory: PrincipalDirectory) -> MCPServer:
    server = MCPServer(
        "acmecloud-helpdesk-secure",
        instructions="AcmeCloud ticketing tools. Access is enforced by the server.",
        token_verifier=token_verifier,
        auth=AuthSettings(
            issuer_url=config.issuer,
            resource_server_url=config.resource_url,
            required_scopes=config.required_scopes,
            validate_token_resource=True,
        ),
    )

    def require_principal(tool: str) -> Principal:
        principal = resolve_principal(directory, config.issuer)
        if principal is None or not all(principal.has_scope(scope) for scope in config.required_scopes):
            audit(tool=tool, decision="deny", reason="unauthenticated")
            raise ToolError(NOT_AUTHORIZED)
        return principal

    def readable_tickets(principal: Principal) -> dict[int, dict]:
        return {
            ticket_id: ticket
            for ticket_id, ticket in TICKETS.items()
            if can_read(principal, ticket, config.internal_scope)
        }

    @server.tool()
    def list_tickets() -> str:
        """List the support tickets you are allowed to see."""
        principal = require_principal("list_tickets")
        tickets = readable_tickets(principal)
        audit(tool="list_tickets", subject=principal.subject, decision="allow", count=len(tickets))
        return "\n".join(f"#{ticket_id} {ticket['title']}" for ticket_id, ticket in tickets.items()) or "No tickets."

    @server.tool()
    def search_tickets(query: str) -> str:
        """Search the titles and bodies of the support tickets you are allowed to see."""
        principal = require_principal("search_tickets")
        needle = query.lower()
        hits = [
            f"#{ticket_id} {ticket['title']}"
            for ticket_id, ticket in readable_tickets(principal).items()
            if needle in ticket["title"].lower() or needle in ticket["body"].lower()
        ]
        audit(tool="search_tickets", subject=principal.subject, decision="allow", hits=len(hits))
        return "\n".join(hits) or "No matching tickets."

    @server.tool()
    def get_ticket(ticket_id: int) -> str:
        """Fetch a support ticket by id."""
        principal = require_principal("get_ticket")
        ticket = TICKETS.get(ticket_id)
        if ticket is None or not can_read(principal, ticket, config.internal_scope):
            audit(tool="get_ticket", subject=principal.subject, ticket=ticket_id, decision="deny")
            raise ToolError(NOT_FOUND)
        audit(tool="get_ticket", subject=principal.subject, ticket=ticket_id, decision="allow")
        return f"#{ticket_id} ({ticket['visibility']}) {ticket['title']}\n\n{ticket['body']}"

    return server


def build_server(config: SecureConfig) -> MCPServer:
    """Build the server exactly as `python -m dvmcp.secure` does, failing fast on bad configuration."""
    verifier = config.token_verifier()
    verifier.key_source.prefetch()
    return create_server(config, verifier, config.directory())
