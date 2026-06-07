# Slack MCP RSV + OAuth setup (ASS-6)

The live CrewAI × Slack demo's resource server is **Slack's MCP server fronted
by the HAAP RSV**. The RSV resolves each Slack MCP `tools/call` to a
`{provider, action, resource}` tuple (authoritatively — the caller can't
mislabel a write as a read), enforces the §45.7.2 OAuth scope-gate against the
agent's PolicySet, and only then forwards to Slack with the downstream OAuth
token. A **read-only** policy therefore lets the agent read channels but
**denies** any post/reply/reaction with `0x002B TbacScopeOAuthMismatch`.

## What's already wired (code/config — done)

- **Routing** — [`slack-mcp-routing.json`](./slack-mcp-routing.json) maps the
  standard Slack MCP tools to read/write. Mounted read-only and selected via
  `HAAP_RSV_MCP_ROUTING_FILE` in `docker-compose.yml`.
  - read  → `slack_list_channels`, `slack_get_channel_history`, `slack_get_thread_replies`, `slack_get_users`, `slack_get_user_profile`
  - write → `slack_post_message`, `slack_reply_to_thread`, `slack_add_reaction`
- **Proxy env** — `HAAP_RSV_PROXY_ALLOWLIST=slack.com` and
  `HAAP_RSV_PROXY_DOWNSTREAM_AUTH_SLACK_COM=<token>` in `.env` (see `.env.example`).

## What needs your Slack workspace (owner action)

### 1. Register a Slack OAuth app — https://api.slack.com/apps → "Create New App"

| Field | Value |
|-------|-------|
| OAuth scopes (read-only demo) | `channels:history`, `channels:read`, `users:read` |
| Authorization URL | `https://slack.com/oauth/v2/authorize` |
| Token URL | `https://slack.com/api/oauth.v2.access` |
| Redirect URI | `https://stage-agent.hawcx.com/v1/oauth/callback` (stage) — or your local callback for a laptop demo |

After creating it, send me (or paste into `.env`, never commit real values):
- **Client ID**
- **Client secret**
- For the quickest demo path, a **bot/user token** (`xoxb-…`/`xoxp-…`) with the
  read scopes above → set as `HAAP_RSV_PROXY_DOWNSTREAM_AUTH_SLACK_COM`. (The
  full OAuth consent flow via the console replaces this; the token is the
  shortcut to a working read/write-deny demo today.)

### 2. Register the app in the console (once consent rail is live)

```
POST /v1/oauth-provider-apps
{ "provider": "slack",
  "client_id": "...", "client_secret": "...",
  "auth_url": "https://slack.com/oauth/v2/authorize",
  "token_url": "https://slack.com/api/oauth.v2.access",
  "scopes": ["channels:history","channels:read","users:read"],
  "redirect_uri": "https://stage-agent.hawcx.com/v1/oauth/callback" }
```
then drive consent: `POST /v1/oauth-provider-apps/{id}/authorize` → Slack login
→ `GET /v1/oauth/callback`. (Depends on the console→CAA dispatch + EIB rail.)

## Demo end-to-end (after ASS-5 deploy + the token above)

1. Console → publish a PolicySet with **`policy_set_id = role-slack-readonly-policies`**
   and `scope_mappings`:
   ```json
   [{ "capability": "use_slack", "provider": "slack",
      "actions": ["read"], "resources": ["channels", "users"] }]
   ```
2. Console → Fleet → open alice's agent → **Role binding** → assign role
   `slack-readonly` (ASS-5 / AgentDrawer).
3. Run the CrewAI agent. Via the RSV:
   - `slack_get_channel_history` on `#general` → **ALLOW** (read).
   - `slack_post_message` → **DENY** `0x002B` (write not in the ceiling).

Workspace check (already confirmed via Slack MCP): the Hawcx workspace is
reachable; good demo channels are `#general`, `#hawcx-engineering`, `#random`.
