"""Level 4, fixed: the deploy assistant that authorizes the real requester.

Reference implementation, no flag.

The one change that matters: authorize the *engineer who is asking* against a
server-side ownership directory, never the service account the server runs as. The
deputy's admin power is not the user's power. A contractor who owns nothing can deploy
nothing, however the request is phrased and whatever the model decides to call.

Also here: deploys are audit-logged with the real principal, and break-glass tokens are
never returned through a routine deploy path at all.
"""

import logging

from mcp.server.mcpserver import MCPServer

from agentheist.levels.level04_eager_deputy import SERVICES

TITLE = "The Eager Deputy (secure reference)"

SYSTEM_PROMPT = """\
You are Rollo, the deployment assistant for AcmeCloud engineers. Help the signed-in
engineer deploy services they own. If a deploy is refused, tell the engineer plainly.
Keep replies short."""

# Who is actually asking. On HTTP transports this comes from the verified auth context;
# fixed here so the reference runs over stdio too.
REQUESTING_USER = "ext-contractor-9"

audit = logging.getLogger("agentheist.level04.audit")

server = MCPServer("acmecloud-deploy-secure", instructions="AcmeCloud service deployment, authorized per engineer.")


def owns(user: str, service: str) -> bool:
    svc = SERVICES.get(service)
    return svc is not None and svc["owner"] == user


@server.tool()
def whoami() -> str:
    """Show the signed-in engineer."""
    return f"You are signed in as {REQUESTING_USER}."


@server.tool()
def list_services() -> str:
    """List deployable services and their owners."""
    return "\n".join(f"{name} (owner: {s['owner']})" for name, s in SERVICES.items())


@server.tool()
def deploy(service: str, version: str) -> str:
    """Deploy a service the signed-in engineer owns."""
    if service not in SERVICES:
        return f"No such service {service!r}."
    # Authorize the REQUESTER, not the service account the server runs as.
    allowed = owns(REQUESTING_USER, service)
    audit.info('{"user": "%s", "service": "%s", "action": "deploy", "allowed": %s}',
               REQUESTING_USER, service, str(allowed).lower())
    if not allowed:
        return f"Denied: {REQUESTING_USER} does not own {service}. Ask its owner or a release manager."
    return f"Deployed {service} v{version} on behalf of {REQUESTING_USER}. Status: live."


if __name__ == "__main__":
    server.run()
