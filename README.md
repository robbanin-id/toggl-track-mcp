# Toggl Track MCP

A multi-tenant, OAuth 2.1 remote [MCP](https://modelcontextprotocol.io) server for [Toggl Track](https://toggl.com/track/). Each user connects **their own** Toggl account by pasting their own API token and choosing a workspace — no shared credentials.

Endpoint: `https://toggl-track-mcp.robbanin-id.workers.dev/mcp`

## How it works

This server is its own OAuth 2.1 authorization server. Because Toggl Track does not offer OAuth, the authorization page is a simple "bring your own token" form:

1. An MCP client (ChatGPT, Claude, Notion AI, etc.) connects to `/mcp` and is challenged with `401 + WWW-Authenticate`.
2. The client discovers the auth server via `/.well-known/oauth-authorization-server`, self-registers via Dynamic Client Registration (`/register`), and opens `/authorize`.
3. `/authorize` shows a page where the user pastes their **Toggl API token** and picks a **workspace** (validated live against the Toggl API).
4. The server issues its own OAuth access token (Authorization Code + PKCE). The Toggl token is encrypted at rest (AES-GCM) and mapped to the issued token server-side.
5. On each MCP call, the opaque access token resolves to the stored Toggl credentials. **The raw Toggl token never reaches the MCP client.**

## Security

- OAuth 2.1 with **PKCE (S256)** mandatory; Dynamic Client Registration (RFC 7591) with strict https-only redirect validation and rate limiting.
- Protected Resource Metadata (RFC 9728) + Authorization Server Metadata (RFC 8414).
- Toggl API tokens stored **encrypted** (AES-GCM); never logged, never returned to clients.
- Per-account isolation: cache and credentials keyed by `sha256(toggl_token + workspace_id)`.

## Caching (quota-efficient)

Toggl's free API limit is per request count, so the server minimizes upstream calls:

- **Tiered TTL** — past days cached ~30 days (immutable); the current day refreshes every ~60 minutes (mutable edge).
- **Warming** — a narrow query is widened to a 10-day block so one fetch covers more.
- **Non-shrinking cache** — accumulates entries by id and unions coverage ranges; a later narrow query never discards a wider cached range.
- **Reports API fallback** — ranges over ~90 days use the Toggl Reports API automatically.
- **force_refresh** — bypasses cache and always calls Toggl; only for when the user says data changed.
- Each response includes `meta.cache` (built_at, max_stop, coverage, freshness) and `meta.completeness` (`unverified` for windows touching today).

## Tools (16)

Read: `get_current_time_entry`, `get_time_entries_with_project_tag` (primary — entries + project map + tags in one call), `get_summary`, `get_coverage`, `browse_projects_catalog`, `browse_tags_catalog` (admin/inspection only).

Write: `create_time_entry`, `update_time_entry`, `stop_time_entry`, `delete_time_entry`, `create_project`, `update_project`, `delete_project`, `create_tag`, `update_tag`, `delete_tag`.

## Deploy

```
wrangler kv namespace create TOGGL_MCP_KV
wrangler secret put ENCRYPTION_KEY   # 32-byte hex
wrangler deploy
```

Bindings (`wrangler.toml`): KV `TOGGL_MCP_KV`, var `BASE_URL`, secret `ENCRYPTION_KEY`.
