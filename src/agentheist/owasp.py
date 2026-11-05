"""Standards mapping: each level tied to the security frameworks it teaches.

Recruiters and engineers reach for a shared vocabulary - OWASP's LLM Top 10, OWASP's
Agentic Security Initiative, and the MCP spec's own security guidance. This module is the
single source of truth for how each Agent Heist level maps onto those frameworks, plus the
root-cause weakness and the control the secure reference enforces. docs/OWASP_MAPPING.md and
`agentheist report` both render from here, so the mapping never drifts between code and docs.

Every category code and name below is quoted from the published source; where a framework
names a threat but no stable code (the Agentic Security Initiative's categories, the MCP
spec's attack sections), the name is used verbatim and no code is invented.
"""

from dataclasses import dataclass

LLM_TOP10 = "OWASP LLM Top 10 (2025)"
AGENTIC = "OWASP Agentic Security Initiative"
MCP = "MCP Security Best Practices"

SOURCES = {
    LLM_TOP10: "https://genai.owasp.org/llm-top-10/",
    AGENTIC: "https://owasp.org/www-project-agentic-security-initiative/",
    MCP: "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
}


@dataclass(frozen=True)
class Category:
    framework: str
    code: str      # a published code like "LLM06:2025", or "" when the source names no stable code
    title: str

    @property
    def url(self) -> str:
        return SOURCES[self.framework]

    @property
    def label(self) -> str:
        return f"{self.code} {self.title}".strip()


@dataclass
class LevelMapping:
    categories: list[Category]  # the first entry is the primary mapping
    weakness: str               # the root cause, in one line
    control: str                # what the secure reference enforces


# Published OWASP LLM Top 10 (2025) entries used below, quoted from the source.
PROMPT_INJECTION = Category(LLM_TOP10, "LLM01:2025", "Prompt Injection")
INFO_DISCLOSURE = Category(LLM_TOP10, "LLM02:2025", "Sensitive Information Disclosure")
SUPPLY_CHAIN = Category(LLM_TOP10, "LLM03:2025", "Supply Chain")
EXCESSIVE_AGENCY = Category(LLM_TOP10, "LLM06:2025", "Excessive Agency")

# Agentic Security Initiative categories (named taxonomy; no stable per-threat code).
AGENTIC_PLANNING = Category(AGENTIC, "", "Planning & Autonomy")
AGENTIC_TOOL_USE = Category(AGENTIC, "", "Tool Use")
AGENTIC_DEPLOY = Category(AGENTIC, "", "Deployment & Operations")

# MCP spec security sections (named attacks; no code).
MCP_CONFUSED_DEPUTY = Category(MCP, "", "Confused Deputy Problem")
MCP_TOKEN_PASSTHROUGH = Category(MCP, "", "Token Passthrough")


MAPPINGS: dict[int, LevelMapping] = {
    1: LevelMapping(
        categories=[EXCESSIVE_AGENCY, INFO_DISCLOSURE, AGENTIC_PLANNING],
        weakness="Authorization is decided by the model's judgement of a claim ('I'm on-call'), "
                 "not enforced by the system (missing server-side access control, CWE-862).",
        control="The secure reference authorizes a verified identity in code (an OAuth/JWT resource "
                "server with server-side checks and an audit log), never the model's say-so.",
    ),
    2: LevelMapping(
        categories=[PROMPT_INJECTION, INFO_DISCLOSURE, AGENTIC_TOOL_USE],
        weakness="Untrusted web content fetched by a tool is treated as trusted instructions, and "
                 "there is no egress control once a secret has been read (indirect prompt injection).",
        control="The secure reference wraps untrusted content as data, isolates secrets, and applies a "
                "taint-based egress allowlist so a read secret can never be sent to an arbitrary host.",
    ),
    3: LevelMapping(
        categories=[EXCESSIVE_AGENCY, INFO_DISCLOSURE, MCP_TOKEN_PASSTHROUGH],
        weakness="A delegation token is leaked and then accepted/forwarded downstream without checking "
                 "that it was issued for this server - the MCP spec's 'token passthrough' anti-pattern.",
        control="The secure reference validates the token's audience and subject per request and refuses "
                "to forward client-supplied tokens: 'MCP servers MUST NOT accept tokens not issued for them.'",
    ),
    4: LevelMapping(
        categories=[EXCESSIVE_AGENCY, MCP_CONFUSED_DEPUTY, AGENTIC_TOOL_USE],
        weakness="The deputy checks its own standing authority to act, not the requester's, so an "
                 "attacker's request rides the deputy's privileges (confused deputy, CWE-441).",
        control="The secure reference authorizes the requesting principal (ownership check) before acting "
                "and records the real principal in the audit log.",
    ),
    5: LevelMapping(
        categories=[PROMPT_INJECTION, SUPPLY_CHAIN, AGENTIC_TOOL_USE],
        weakness="A third-party tool's description carries hidden instructions the model follows (tool "
                 "poisoning): untrusted metadata from a supply-chain component is treated as a command.",
        control="The secure reference pins and sanitizes tool descriptions (reviewed metadata, not the "
                "author's text) and keeps secrets and egress controlled regardless of any description.",
    ),
}


def for_level(number: int) -> LevelMapping:
    return MAPPINGS[number]


def level_markdown(number: int) -> str:
    """A per-level security report section: attack, framework mapping, weakness, control."""
    from agentheist.benchmarks import TASK_SUMMARIES
    from agentheist.levels import get_level
    m = MAPPINGS[number]
    lines = [f"### Level {number}: {get_level(number).title}", ""]
    if TASK_SUMMARIES.get(number):
        lines += [f"**Attack.** {TASK_SUMMARIES[number]}", ""]
    lines.append("**Mapped to:**")
    for c in m.categories:
        lines.append(f"- {c.framework} — [{c.label}]({c.url})")
    lines += ["",
              f"**Root-cause weakness.** {m.weakness}",
              "",
              f"**Control (secure reference).** {m.control}",
              ""]
    return "\n".join(lines)


def overview_table() -> str:
    """A compact markdown table: one row per level, primary category first."""
    lines = ["| Level | Primary | Also mapped to | Root-cause weakness |",
             "|---|---|---|---|"]
    from agentheist.levels import get_level  # local import to avoid a cycle at module load
    for n in sorted(MAPPINGS):
        m = MAPPINGS[n]
        primary = m.categories[0].label
        also = "; ".join(c.label for c in m.categories[1:])
        weak = m.weakness.split(" (")[0].split(". ")[0]
        lines.append(f"| {n} {get_level(n).title} | {primary} | {also} | {weak} |")
    return "\n".join(lines)
