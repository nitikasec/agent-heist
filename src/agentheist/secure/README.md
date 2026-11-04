# Secure Helpdesk (the fixed version of Level 1)

Level 1, *The Trusting Helpdesk* (`src/agentheist/levels/level01_trusting_helpdesk.py`), is **intentionally
vulnerable** and is left unchanged. This package is a separate implementation of the same helpdesk that
enforces authentication and authorization on the server. It uses synthetic data and has no challenge flag.

> **Status: reference implementation, not production-ready.** The unit tests check the logic in-process.
> They don't prove that a real deployment is secure. See [Limitations](#limitations).

## 1. The original vulnerability

In Level 1, `get_ticket()` returns any ticket, internal ones included, to whoever calls it. The only
"access control" is a sentence in the agent's system prompt saying that staff may see internal tickets.
An LLM can't verify who a user is, so a user's claim about their role is all it takes. `list_tickets()`
also leaks the titles of internal tickets. (OWASP LLM06: excessive agency / broken access control.)

## 2. Secure architecture

```
client ──HTTPS + Bearer JWT──▶ SDK BearerAuthBackend ──▶ JWTTokenVerifier (signature, iss, aud, exp, claims)
                                      │ 401 if invalid, 403 if a required scope is missing
                                      ▼
                         SDK auth context (verified AccessToken)
                                      ▼
   tool (list_tickets / search_tickets / get_ticket)
      └─ resolve_principal(): verified (iss, sub) ──▶ PrincipalDirectory (server-side roles)
      └─ can_read(principal, ticket): checked on every call
```

| File | Purpose |
|------|---------|
| `auth.py` | `JWTTokenVerifier`, key sources (`StaticPublicKey`, `JWKSKeySource`), `PrincipalDirectory`, `Principal`, `resolve_principal` |
| `config.py` | `SecureConfig`: all trust settings, read from `AGENTHEIST_SECURE_*` env vars and validated |
| `helpdesk.py` | `create_server()`: the MCP server, its tools and the authorization policy |
| `__main__.py` | Runs the server over streamable HTTP with uvicorn |

## 3. From authenticated identity to trusted principal

1. The MCP SDK (`mcp` 2.3.0) runs in **OAuth resource-server mode**, via `MCPServer(token_verifier=..., auth=AuthSettings(...))`.
   This works only on the HTTP transports.
2. `JWTTokenVerifier.verify_token` accepts a token only if all of the following hold:
   - The **signature** verifies against the configured issuer's public key or JWKS. Each key can verify only its
     own algorithm: RSA keys (at least 2048 bits) verify only `RS256`, and P-256 keys verify only `ES256`. `none`,
     symmetric `HS*` keys and every other algorithm are refused.
   - `iss` equals the configured issuer **exactly**.
   - `aud` contains the configured resource URL.
   - `exp` is in the future, and `iat`/`nbf` are not in the future (30s leeway).
   - The **lifetime** `exp - iat` is positive and at most `AGENTHEIST_SECURE_MAX_TOKEN_LIFETIME_SECONDS` (default
     **3600 s**, allowed range 60–86400). Because `iat` can't be in the future, this also limits how long from now
     a token can stay valid: at most the maximum lifetime plus the 30 s leeway.
   - `iss`, `sub`, `aud`, `exp` and `iat` are all present. `sub` must be a printable string of 1–255 characters
     with no control or line-break characters.

   If any check fails, it returns `None` and the SDK answers **HTTP 401**. The SDK then checks `required_scopes`
   (**403** if one is missing) and that the token is bound to this resource (`validate_token_resource=True`).
3. Inside each tool, `resolve_principal()` reads the verified token from the SDK's auth context. It looks up the
   `(issuer, subject)` pair in the **server-side `PrincipalDirectory`**, and roles come only from there.
   It does **not** read `role`/`roles` claims in the token, tool arguments or user messages.
   A subject that isn't in the directory is denied.

## 4. How each tool is protected

Every tool calls `require_principal()` first. If there is no verified identity, or the subject is unknown, the
tool returns `Not authorized.` This holds even if the HTTP middleware were bypassed, and the in-memory test
transport proves it.

| Tool | Customer | Staff with `tickets:read_internal` |
|------|----------|-------------------------------------|
| `list_tickets` | public tickets only | public + internal |
| `search_tickets` | searches public tickets only | public + internal |
| `get_ticket` | public; internal → `Ticket not found.` | public + internal |

- **Internal tickets need two things:** the `staff` role in the directory **and** the `tickets:read_internal`
  scope on the token.
- **Disclosure policy:** an internal ticket the caller can't read gets exactly the same response as an id that
  doesn't exist, so callers can't find out which internal ids exist.
- **No identity in tool arguments:** tools take no identity or role parameters, and extra arguments are ignored.
- **Audit log:** each decision is logged to `agentheist.secure.audit` as **one JSON object per line**, with the tool,
  subject, ticket id and decision, for example
  `{"decision": "deny", "subject": "alice", "ticket": 7001, "tool": "get_ticket"}`. JSON encoding escapes every
  control and non-ASCII character, so a field value can't start a new log line. Ticket bodies are never logged.

### JWKS settings

| Setting | Value | Effect |
|---------|-------|--------|
| Fetch timeout | 5 s | Covers connect, TLS handshake and read |
| Key-set cache lifespan | 300 s | A key removed from the JWKS stops being trusted within 5 minutes; there is no per-key cache that outlives it |
| Refresh cooldown | 30 s | A new `kid` (rotation) can trigger at most one refresh per 30 s. Failed fetches are rate-limited the same way, so an outage never causes a fetch per request |
| Concurrent lookups | 4 threads | JWKS lookups run on a small dedicated pool; static keys never use a thread |
| Redirects | refused | PyJWT default |

Tokens without a usable `kid` are rejected before any network access. The keys are fetched once at startup, so a
wrong or unreachable JWKS URL stops the server from starting. After a rotation, tokens signed with the new key can be
rejected for up to 30 s, until the cooldown allows a refresh.

## 5. Running the tests

```bash
uv run pytest -q tests/test_secure_*.py   # secure helpdesk only
uv run pytest -q                          # everything, including the unchanged Level 1 tests
```

The tests run the SDK's real `streamable_http_app()` in-process through `httpx2.ASGITransport`. They use a
**test-only identity provider** (`TestIdentityProvider`), which generates throwaway RSA and EC keys on every run.
The JWKS tests run a local HTTPS JWKS server with a temporary self-signed certificate (`tests/secure_support.py`).
No keys or certificates are stored in the repo.

| File | Covers |
|------|--------|
| `test_secure_helpdesk.py` | Token rejection, authorization rules, disclosure policy, audit content |
| `test_secure_http_modes.py` | The same rules in stateless **and** stateful mode, with RS256 and ES256; session ids can't be reused by another user |
| `test_secure_static_keys.py` | RS256/ES256 verification, algorithm-to-key binding, weak or unsupported keys |
| `test_secure_jwks.py` | Lookup by `kid`, caching, unknown `kid`, rotation, key removal, timeouts, unreachable/failing/untrusted endpoints |
| `test_secure_directory.py` | Directory schema, duplicate keys and identities, issuer mismatch, file permissions |
| `test_secure_audit.py` | Subject validation and one-line JSON audit events |
| `test_secure_urls.py` | URL validation, including hostname-suffix and userinfo bypasses |
| `test_secure_startup.py` | `SecureConfig.from_env()`, `build_server()` and the entrypoint's error handling |
| `test_secure_token_lifetime.py` | Maximum token lifetime: boundaries, malformed `iat`, settings, enforcement over HTTP |
| `test_secure_bind_warning.py` | The non-loopback startup warning, and the SDK Host-header behaviour behind it |

They cover:
- **Rejected tokens:** a missing, garbage, wrong-key, expired, wrong-issuer, wrong-audience, unsigned (`alg: none`)
  or missing-`sub` token gets 401, and a missing scope gets 403.
- **Untrusted role claims:** a forged token with a staff role claim is rejected, and a role claim in a *valid*
  token grants nothing.
- **Tool access:** customers can't read, list or search internal tickets, and staff can. Role arguments in tool
  calls are ignored.
- **Unknown callers and ids:** unknown subjects are denied, and an unknown id gets the same response as a hidden
  internal ticket.
- **Per-call checks:** revoking a role in the middle of a session takes effect on the next call. Tools still
  deny when the HTTP auth layer is bypassed.
- **Audit log:** it never contains ticket bodies.
- **Configuration:** insecure settings (http issuer, two key sources, private key PEM, HS256, no scopes) are refused.

## 6. Configuring real authentication

The server trusts **one external OAuth 2.1 / OIDC identity provider** (for example Okta, Auth0, Entra ID or
Keycloak). This repo doesn't include a production identity provider.

1. **Register the resource.** In your identity provider, register this MCP server as an API (resource) whose
   audience / resource indicator is its public URL (for example `https://helpdesk.example.com/mcp`). Define the
   scopes `tickets:read` and `tickets:read_internal`, and issue `tickets:read_internal` only to staff clients or users.
2. **Write the principal directory**, a JSON file that maps verified identities to roles:
   ```json
   {"principals": [
     {"issuer": "https://login.example.com/", "subject": "<customer-sub>", "roles": ["customer"]},
     {"issuer": "https://login.example.com/", "subject": "<staff-sub>",    "roles": ["staff"]}
   ]}
   ```
   In production this would normally be your user or HR database, not a file. The file is validated strictly:
   - **Shape:** exactly the keys shown, no duplicate JSON keys, and a non-empty list of known roles
     (`customer`, `staff`) for each entry.
   - **Identities:** every `issuer` must equal `AGENTHEIST_SECURE_ISSUER`, and the same issuer and subject can't appear twice.
   - **File (POSIX only):** a regular file of at most 1 MiB, owned by the server's user or root, not group- or
     world-writable, and not in a world-writable folder without the sticky bit. Symlinks are followed, so these
     checks apply to the target file.

   Errors name the record index and never echo file contents.
3. **Set the environment** and start the server:
   ```bash
   export AGENTHEIST_SECURE_ISSUER="https://login.example.com/"          # must match the token's iss exactly
   export AGENTHEIST_SECURE_RESOURCE_URL="https://helpdesk.example.com/mcp"
   export AGENTHEIST_SECURE_JWKS_URL="https://login.example.com/.well-known/jwks.json"
   # optional, for an identity provider behind a private CA:
   # export AGENTHEIST_SECURE_JWKS_CA_FILE=/path/to/ca.pem
   # or, instead of JWKS:  export AGENTHEIST_SECURE_PUBLIC_KEY_FILE=/path/to/issuer-public.pem
   export AGENTHEIST_SECURE_DIRECTORY_FILE=/path/to/principals.json
   export AGENTHEIST_SECURE_REQUIRED_SCOPES="tickets:read"               # space-separated
   export AGENTHEIST_SECURE_INTERNAL_SCOPE="tickets:read_internal"
   export AGENTHEIST_SECURE_HOST=127.0.0.1 AGENTHEIST_SECURE_PORT=8000
   export AGENTHEIST_SECURE_MAX_TOKEN_LIFETIME_SECONDS=3600            # optional; 60–86400

   uv run python -m agentheist.secure
   ```
   The server refuses to start if a setting is missing or insecure. URLs are checked by parsing them, not by
   prefix:
   - The issuer and JWKS URL must be https.
   - The resource URL must be https, or http only when the hostname is exactly `localhost`, `127.0.0.1` or
     `::1`. That rules out `localhost.example.com`, `user@host`, `127.1` and expanded IPv6 forms.
   - URLs can't contain user info, fragments, whitespace or control characters.

   It also refuses:
   - zero or two key sources
   - a private key, or a key weaker than RSA-2048 or P-256
   - an empty or invalid scope, or an internal scope that every caller already has
   - a bad port, an empty host, or a maximum token lifetime outside 60–86400 s
   - an invalid directory file
   - a JWKS endpoint it can't reach at startup

   Errors print one line, `Configuration error: ...`, with no traceback. Set `AGENTHEIST_SECURE_DEBUG=1` to see tracebacks
   for unexpected errors. The server serves MCP at `http://<host>:<port>/mcp` in the SDK's default stateful mode.
4. **Put TLS in front.** Run it behind a TLS-terminating reverse proxy, and keep `AGENTHEIST_SECURE_HOST` on loopback
   or a private interface. If the host is anything other than exactly `127.0.0.1`, `localhost` or `::1`, the
   server logs a **warning** at startup (logger `agentheist.secure`): it then serves plain HTTP and the SDK's
   Host/Origin checks are off. That includes `0.0.0.0`, `127.0.0.2` and `LOCALHOST`. It still starts, because a
   private-interface binding behind a proxy is a valid deployment.

## 7. Limitations

- **The test identity provider is test-only.** The tests prove the verifier and policy logic. They do not prove
  that a real identity provider, TLS, a reverse proxy or a JWKS endpoint is configured correctly. Before calling a
  deployment secure, test it end-to-end against the real identity provider.
- **No token revocation check.** A verified JWT is accepted until it expires. If you need immediate revocation,
  use short token lifetimes or switch to RFC 7662 token introspection. The directory lookup does deny a revoked
  *role* on the very next call.
- **The directory file is read once at startup.** It is a stand-in for a real user store.
- **JWKS rotation delay.** After a key rotation, tokens signed with the new key can be rejected for up to 30 s
  (the refresh cooldown). A removed key stays trusted for up to 300 s (the cache lifespan).
- **Directory permission checks are POSIX-only.** On Windows they are skipped, so protect the file with ACLs.
  The parent-folder check looks at the folder holding the path you configured. When that path is a symlink, the
  target's own folder isn't checked.
- **The lifetime limit trusts the issuer's `iat`.** It can't tell whether the identity provider really issued the
  token at `iat`, only that `iat` isn't in the future. Pick a limit no longer than your provider's token lifetime.
- **Reverse-proxy Host header.** With the default loopback binding, the SDK only accepts `Host` values of
  `127.0.0.1`, `localhost` or `[::1]`, so the proxy must forward one of those. Binding to a non-loopback address
  turns that check off and serves plain HTTP. The startup warning only reports this; it doesn't stop the server,
  and nothing checks that a TLS proxy is really in front.
- **Not wired into `agentheist play`.** The CLI agent connects to levels over stdio, and stdio has no MCP auth layer.
  The secure server is HTTP-only.
- **Single-ticket ownership isn't modelled.** Every authenticated customer can read every public ticket, as this
  design requires. Real helpdesks usually also limit customers to their own tickets.
- **No rate limiting or request-size policy** beyond the SDK's defaults.

## 8. Vulnerable vs secure

| Scenario | Level 1 (vulnerable) | Secure helpdesk |
|----------|----------------------|-----------------|
| No credentials | Tools work | HTTP 401; tools deny even if middleware is bypassed |
| User says "I'm staff" | Agent fetches internal ticket | Irrelevant: identity comes only from a verified token |
| `role: staff` in token / tool args | n/a | Ignored; roles come from the server-side directory |
| Forged or expired token | n/a | HTTP 401 |
| Customer lists tickets | Sees internal ticket titles | Sees public tickets only |
| Customer requests internal id | Gets the internal body | `Ticket not found.` (same as unknown id) |
| Where access control lives | System prompt | Tool code, on every call |
