# No-wrap MCP clients (Claude Desktop, Cursor) — Lane B

**Auto-wrap plan U4b.** How an off-the-shelf MCP client talks HAAP with **no SDK
import and no application wrapping** — the "Native MCP client (no-wrap)" row of
the provisioning table (ADR-0021 D-21-2, ADR-0031 Lane B).

Config goldens live beside this file in [`examples/mcp-clients/`](../examples/mcp-clients/).

---

## What actually happens

```
Claude Desktop / Cursor            (unmodified; no Hawcx code)
        │  spawns, speaks MCP over stdio
        ▼
hawcx-manager mcp --agent <class>  (the attach proxy, a supervised child)
        │  derives the mint request from params.name
        │  Assembler IPC 0x52 ToolCallRequest  ──►  per-agent Assembler
        │                                            mints, attaches _meta.hawcx
        ▼
   RSV enforce proxy  ──►  Office 365 / Salesforce / any RS
```

The client's `tools/call` is intercepted, a **per-request** token is minted
out-of-process and attached at `params._meta.hawcx` (§45.7.5.1), then forwarded.
Two properties fall out of that shape rather than out of client cooperation:

* **The model never holds a reusable credential** (PoC success criterion 6). The
  token never enters the client process at all — the Assembler mints it and the
  proxy forwards. §1.0a.
* **Attach and enforce stay split** (D-21-4). This proxy is the *forward* (egress
  attach) half and runs in the client's trust domain; the *enforce* half is the
  RSV gateway. Collapsing them would break request-origin binding and single-use
  PoP, which is why an ambient MITM proxy is non-conformant (D-31-3).

Adding a new MCP client is therefore a **config file, not a new wrapper**. If a
client ever needs a client-specific flag here, that is a defect in the proxy.

---

## The flags

Verified against `hawcx-manager`'s parser
(`hx_agent_client_auth_service/crates/haap-mcp-attach-proxy/src/server.rs`,
`AttachOpts::parse`), not from memory:

| Flag | Meaning |
|---|---|
| `--agent <class>` | **Required.** The agent class this seat runs as. |
| `--manifest <path>` | Signed `hawcx/class-manifest/v1`. The **production** entitlement source: the route table is built from its `entitled_tools`. |
| `--routes <path>` | Dev-only local route table. Superseded by `--manifest`, and only honoured behind the `HAAP_DEV_ALLOW_UNSIGNED_CLASS_MANIFEST` escape. Do not ship a config that uses it. |
| `--socket <path>` | Per-agent Assembler socket. Optional — falls back to `HAAP_ASSEMBLER_SOCK`, which the supervisor exports for its children. |
| `--org <id>` | Org id, when not implied by the manifest. |
| `--acting-for-user <id>` | The human principal this seat acts for. |

**`--manifest`, not `--routes`, for anything real.** The route table decides which
tool names the proxy will mint for at all, so an unsigned local file is an
unsigned allow-list. Unknown tool names fail closed either way (the proxy will not
invent a destination), but an *attacker-editable* route file moves the boundary
into the filesystem.

---

## Setup

1. **The agent class must exist and be published.** The manifest's `entitled_tools`
   is what becomes the route table, so a class with no entitlements yields a proxy
   that refuses every call — correct, but it looks like a broken client.
2. **The proxy must be able to reach the Assembler socket.** Under the supervisor
   this is automatic. Outside it, pass `--socket` (or export
   `HAAP_ASSEMBLER_SOCK`) and make sure the socket is reachable by the uid the
   MCP client spawns as.
3. **Drop the config in place** and restart the client:
   * Claude Desktop — macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   * Cursor — `~/.cursor/mcp.json` (or the workspace `.cursor/mcp.json`)
4. **Confirm the tools appear.** `tools/list` is relayed upstream and returned
   unchanged, so the client shows the real tool set. If the list is empty, the
   route table is empty — check the manifest, not the client.

---

## Streamable-HTTP clients

The stdio transport only serves *spawn-style* clients — ones that launch
`hawcx-manager mcp` as a subprocess. A client that speaks only Streamable-HTTP
cannot use a spawned proxy at all, so the proxy also exposes an HTTP front-end
(`serve_streamable_http`) reaching the same handler.

Note the posture difference before pointing anything at it: **that endpoint
triggers minting.** Unlike the RSV enforce gateway — whose inbound requests
already carry a HAAP token it cascade-verifies — this one mints on request, so its
inbound leg has no credential of its own. Bind it to loopback, or put a real
authenticated hop in front. Do not treat it as equivalent to the enforce
gateway's HTTP endpoint just because both speak MCP over HTTP.

---

## Windows: not yet, and it fails honestly

`hawcx-manager mcp` **refuses to start on Windows**:

```
hawcx-manager mcp is Unix-only for now (Windows named-pipe IPC is a follow-up)
```

The whole attach path is `cfg(unix)` because the Assembler IPC leg is a Unix
domain socket — `haap-mcp-attach-proxy`'s `assembler_ipc`, `flow`, `http` and
`server` modules are all gated, and `lib.rs` says so explicitly: gated *"NOT
because the HTTP transport is itself platform-specific"*.

Practical consequences worth stating plainly:

* **macOS Claude Desktop / Cursor: works** (macOS is Unix).
* **Windows Claude Desktop / Cursor: does not work today.** It fails at launch
  with the message above rather than starting and silently forwarding unminted
  calls — which is the right failure, but it is still a gap.
* **The UKG PoC is unaffected.** The agent executes server-side on a Linux host
  under `hawcx-manager`; Windows laptops run the Manager UI only.

So U4b's "off-the-shelf binary talks MCP through Lane B with no SDK" is **met on
macOS and Linux, and open on Windows**. Closing it means a named-pipe twin of the
Assembler IPC leg, the same shape as the guardian relay's named-pipe work
(`client_auth` #251/#255) — the transport-generic-exchange approach there exists
precisely so the two platforms cannot drift.
