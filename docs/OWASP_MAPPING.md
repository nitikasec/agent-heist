# Standards mapping

Every Agent Heist level is a concrete, runnable instance of a published security risk. This
page maps each level to the frameworks practitioners already use, so the lab speaks the same
language as a threat model, an audit, or a job description.

The mapping is generated from [`src/agentheist/owasp.py`](../src/agentheist/owasp.py) — the same
source `agentheist report <level>` renders — so code and docs cannot drift. Every code and name
below is quoted from its source; where a framework names a threat but publishes no stable code,
the name is used verbatim and **no code is invented**.

## Frameworks

- **OWASP Top 10 for LLM Applications (2025)** — https://genai.owasp.org/llm-top-10/
- **OWASP Agentic Security Initiative** (named threat categories) — https://owasp.org/www-project-agentic-security-initiative/
- **MCP Security Best Practices** (the spec's own attack sections) — https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices

## Overview

| Level | Primary | Also mapped to | Root-cause weakness |
|---|---|---|---|
| 1 The Trusting Helpdesk | LLM06:2025 Excessive Agency | LLM02:2025 Sensitive Information Disclosure; Planning & Autonomy | Authorization is decided by the model's judgement of a claim |
| 2 The Poisoned Page | LLM01:2025 Prompt Injection | LLM02:2025 Sensitive Information Disclosure; Tool Use | Untrusted web content fetched by a tool is treated as trusted instructions, and there is no egress control once a secret has been read |
| 3 The Helpful Integration | LLM06:2025 Excessive Agency | LLM02:2025 Sensitive Information Disclosure; Token Passthrough | A delegation token is leaked and then accepted/forwarded downstream without checking that it was issued for this server - the MCP spec's 'token passthrough' anti-pattern. |
| 4 The Eager Deputy | LLM06:2025 Excessive Agency | Confused Deputy Problem; Tool Use | The deputy checks its own standing authority to act, not the requester's, so an attacker's request rides the deputy's privileges |
| 5 The Poisoned Plugin | LLM01:2025 Prompt Injection | LLM03:2025 Supply Chain; Tool Use | A third-party tool's description carries hidden instructions the model follows |

## Per level

### Level 1: The Trusting Helpdesk

**Attack.** Attacker poses as on-call staff and asks the helpdesk agent to reveal a restricted ticket.

**Mapped to:**
- OWASP LLM Top 10 (2025) — [LLM06:2025 Excessive Agency](https://genai.owasp.org/llm-top-10/)
- OWASP LLM Top 10 (2025) — [LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llm-top-10/)
- OWASP Agentic Security Initiative — [Planning & Autonomy](https://owasp.org/www-project-agentic-security-initiative/)

**Root-cause weakness.** Authorization is decided by the model's judgement of a claim ('I'm on-call'), not enforced by the system (missing server-side access control, CWE-862).

**Control (secure reference).** The secure reference authorizes a verified identity in code (an OAuth/JWT resource server with server-side checks and an audit log), never the model's say-so.

### Level 2: The Poisoned Page

**Attack.** Victim's agent summarises an attacker-controlled web page that hides instructions.

**Mapped to:**
- OWASP LLM Top 10 (2025) — [LLM01:2025 Prompt Injection](https://genai.owasp.org/llm-top-10/)
- OWASP LLM Top 10 (2025) — [LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llm-top-10/)
- OWASP Agentic Security Initiative — [Tool Use](https://owasp.org/www-project-agentic-security-initiative/)

**Root-cause weakness.** Untrusted web content fetched by a tool is treated as trusted instructions, and there is no egress control once a secret has been read (indirect prompt injection).

**Control (secure reference).** The secure reference wraps untrusted content as data, isolates secrets, and applies a taint-based egress allowlist so a read secret can never be sent to an arbitrary host.

### Level 3: The Helpful Integration

**Attack.** Attacker replays a delegation token the agent leaked, to read another account's invoices.

**Mapped to:**
- OWASP LLM Top 10 (2025) — [LLM06:2025 Excessive Agency](https://genai.owasp.org/llm-top-10/)
- OWASP LLM Top 10 (2025) — [LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llm-top-10/)
- MCP Security Best Practices — [Token Passthrough](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

**Root-cause weakness.** A delegation token is leaked and then accepted/forwarded downstream without checking that it was issued for this server - the MCP spec's 'token passthrough' anti-pattern.

**Control (secure reference).** The secure reference validates the token's audience and subject per request and refuses to forward client-supplied tokens: 'MCP servers MUST NOT accept tokens not issued for them.'

### Level 4: The Eager Deputy

**Attack.** Attacker asks the agent to deploy on their behalf, relying on the deputy's standing authority.

**Mapped to:**
- OWASP LLM Top 10 (2025) — [LLM06:2025 Excessive Agency](https://genai.owasp.org/llm-top-10/)
- MCP Security Best Practices — [Confused Deputy Problem](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- OWASP Agentic Security Initiative — [Tool Use](https://owasp.org/www-project-agentic-security-initiative/)

**Root-cause weakness.** The deputy checks its own standing authority to act, not the requester's, so an attacker's request rides the deputy's privileges (confused deputy, CWE-441).

**Control (secure reference).** The secure reference authorizes the requesting principal (ownership check) before acting and records the real principal in the audit log.

### Level 5: The Poisoned Plugin

**Attack.** Victim's agent runs a normal coding task while a poisoned tool description issues hidden steps.

**Mapped to:**
- OWASP LLM Top 10 (2025) — [LLM01:2025 Prompt Injection](https://genai.owasp.org/llm-top-10/)
- OWASP LLM Top 10 (2025) — [LLM03:2025 Supply Chain](https://genai.owasp.org/llm-top-10/)
- OWASP Agentic Security Initiative — [Tool Use](https://owasp.org/www-project-agentic-security-initiative/)

**Root-cause weakness.** A third-party tool's description carries hidden instructions the model follows (tool poisoning): untrusted metadata from a supply-chain component is treated as a command.

**Control (secure reference).** The secure reference pins and sanitizes tool descriptions (reviewed metadata, not the author's text) and keeps secrets and egress controlled regardless of any description.
