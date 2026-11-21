/**
 * Assembler IPC client — speaks the wire protocol from `crates/haap-ipc` (in `hx_agent_crypto_core`).
 *
 * Wire format (verified against `crates/haap-ipc/src/framing.rs`):
 *
 *     [msg_len: u32 BE][msg_type: u8][payload: msg_len-1 bytes]
 *
 * `msg_len` includes the `msg_type` byte. `MAX_MESSAGE_SIZE` is 64 KiB.
 *
 * On connect both sides exchange an `IpcHandshake` (msg_type `0x00`) with
 * payload `[protocol_version: u16 BE][major: u16 BE][minor: u16 BE]
 * [patch: u16 BE][role: u8]`. Per `crates/haap-ipc/src/handshake.rs`, major
 * version MUST match; minor mismatches are logged warnings on the Rust side.
 *
 * Agent ↔ Assembler messages (CS v6.0.0 §39.7 channel allowlists):
 * - `MSG_TOOL_CALL_REQUEST = 0x52`    Agent → Assembler, JSON
 * - `MSG_TOOL_CALL_RESPONSE = 0x53`   Assembler → Agent, JSON
 * - `MSG_REQUEST_REJECTED = 0x54`     Assembler → Agent, JSON
 * - `MSG_CLARIFICATION_ANSWER = 0x61` Agent → Assembler, JSON (Profile E)
 */

import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import * as process from "node:process";

import { HandshakeError, IpcError, RequestRejected } from "./errors";

// ── Protocol constants (mirror crates/haap-ipc/src/handshake.rs) ────

export const PROTOCOL_VERSION = 1;
export const SDK_VERSION_MAJOR = 0;
export const SDK_VERSION_MINOR = 5;
export const SDK_VERSION_PATCH = 0;

export const ROLE_AGENT = 0x04;
export const ROLE_ASSEMBLER = 0x05;

export const MSG_TYPE_HANDSHAKE = 0x00;
export const MSG_TOOL_CALL_REQUEST = 0x52;
export const MSG_TOOL_CALL_RESPONSE = 0x53;
export const MSG_REQUEST_REJECTED = 0x54;
export const MSG_CLARIFICATION_ANSWER = 0x61;

export const MAX_MESSAGE_SIZE = 64 * 1024;

// ── Public wire types ───────────────────────────────────────────────

/**
 * Per-call outbound transport selector.
 *
 * - `http_header` (default): token in `Authorization: HAAP <b64>` HTTP header.
 * - `mcp_meta`: standard MCP carriage accepted by Rust `haap-assembler`.
 *   Token placed in JSON-RPC `params._meta`.
 *
 * Note: shipped Rust `haap-assembler` crates accept ONLY `"http_header"` and
 * `"mcp_meta"` (they reject `"mcp_meta_v7_2_5"` with `unknown variant`).
 * `McpMetaV725` is retained as a deprecated alias to `"mcp_meta"` so existing
 * TypeScript callers continue to compile and work against shipped Assemblers.
 *
 * Values match serde `#[rename_all = "snake_case"]` on the Rust side.
 */
export enum TokenTransport {
  HttpHeader = "http_header",
  McpMeta = "mcp_meta",
  /**
   * @deprecated Shipped Rust `haap-assembler` rejects `"mcp_meta_v7_2_5"` and
   * expects `"http_header"` or `"mcp_meta"`. Aliased to `"mcp_meta"`; use
   * {@link TokenTransport.McpMeta}.
   */
  McpMetaV725 = "mcp_meta",
}

/**
 * Capability tag advertised at MCP `initialize` time when the
 * Assembler offers the v7.2.5 `_meta.hawcx` envelope to an upstream
 * MCP server. Mirrored verbatim into the JSON-RPC initialize
 * `experimental` map.
 */
export const HAWCX_HAAP_V7_2_5_CAPABILITY = "hawcx-haap-v7-2-5";

/**
 * Agent → Assembler request (msg_type `0x52`).
 *
 * Mirrors `haap_ipc::messages::assembler::ToolCallRequest`. The Assembler
 * constructs the requested scope from `tool` / `action` / `resource` /
 * `constraints` per CS §39.7; the SDK process does not see token material
 * or session keys.
 */
export interface ToolCallRequest {
  requestId: string;
  targetRsUrl: string;
  httpMethod: string;
  headers?: Record<string, string>;
  tool: string;
  /**
   * Downstream MCP tool name (kebab route) that becomes JSON-RPC `params.name`
   * on the `mcp_meta` flight. Distinct from `tool`, which is the dotted TBAC id
   * used for policy/scope matching. Omitted from the wire when undefined
   * (Assembler falls back to `tool`). Mirrors Python `ToolCallRequest.mcp_tool_name`.
   */
  mcpToolName?: string;
  action?: readonly string[];
  resource?: string;
  constraints?: Record<string, unknown>;
  body?: Buffer | null;
  claimedIntentHash?: string;
  toolArguments?: unknown;
  contentType?: string;
  transport?: TokenTransport;
  /**
   * Optional runtime principal (CS v6.9.0 line 163). When set, the
   * Assembler projects this string into `scope_json.user_principal_id`
   * on the minted token so the gateway's Cedar policy can enforce
   * `context.user_principal_id == resource.owner_user_id`. The
   * agent's pinned `subject_user_id` is NOT modified — only per-call
   * scope_json metadata. See `HawcxAgent.invokeFor`.
   */
  actingForUser?: string;
  /**
   * Optional OAuth provider id (e.g. "slack") marking this call as
   * OAuth-protected. When set, the Assembler fetches the matching bearer
   * from the EIB and attaches it to the egress request; without it the
   * Assembler treats the destination as unauthenticated and never queries
   * the EIB (so OAuth-protected destinations are rejected). Mirrors
   * `haap_ipc::messages::assembler::ToolCallRequest.provider`. (ASS-4)
   */
  provider?: string;
}

/**
 * Assembler → Agent response (msg_type `0x53`).
 *
 * Mirrors `haap_ipc::messages::assembler::ToolCallResponse`. `body` is the
 * decrypted RS response (`Buffer`).
 */
export interface ToolCallResponse {
  requestId: string;
  httpStatus: number;
  headers: Record<string, string>;
  body: Buffer;
}

function toolCallRequestToWire(req: ToolCallRequest): Record<string, unknown> {
  const wire: Record<string, unknown> = {
    request_id: req.requestId,
    target_rs_url: req.targetRsUrl,
    http_method: req.httpMethod,
    headers: req.headers ?? {},
    tool: req.tool,
    action: req.action ?? [],
    resource: req.resource ?? "*",
    constraints: req.constraints ?? {},
  };
  if (req.mcpToolName !== undefined) {
    wire.mcp_tool_name = req.mcpToolName;
  }
  if (req.body !== undefined && req.body !== null) {
    wire.plaintext_request_body = req.body.toString("base64");
  }
  if (req.claimedIntentHash !== undefined) {
    wire.claimed_intent_hash = req.claimedIntentHash;
  }
  if (req.toolArguments !== undefined) {
    wire.tool_arguments = req.toolArguments;
  }
  if (req.contentType !== undefined) {
    wire.content_type = req.contentType;
  }
  if (req.transport !== undefined) {
    wire.transport = req.transport;
  }
  if (req.actingForUser !== undefined) {
    // Top-level wire field, NOT nested in `constraints`. The Assembler
    // projects this into `scope_json.user_principal_id` per
    // CS v6.9.0 line 163.
    wire.acting_for_user = req.actingForUser;
  }
  if (req.provider !== undefined) {
    // OAuth provider id (e.g. "slack"). The Assembler uses it to fetch the
    // matching bearer from the EIB for OAuth-protected destinations. (ASS-4)
    wire.provider = req.provider;
  }
  return wire;
}

function toolCallResponseFromWire(obj: Record<string, unknown>): ToolCallResponse {
  const requestId = String(obj.request_id ?? "");
  const httpStatus = Number(obj.http_status ?? 0);
  const headers = (obj.headers as Record<string, string>) ?? {};
  const bodyB64 = (obj.body as string) ?? "";
  return {
    requestId,
    httpStatus,
    headers,
    body: bodyB64 ? Buffer.from(bodyB64, "base64") : Buffer.alloc(0),
  };
}

// ── Framing helpers ─────────────────────────────────────────────────

export function encodeFrame(msgType: number, payload: Buffer): Buffer {
  const msgLen = 1 + payload.length;
  if (msgLen > MAX_MESSAGE_SIZE) {
    throw new IpcError(
      `frame too large: ${msgLen} bytes (max ${MAX_MESSAGE_SIZE})`,
    );
  }
  const frame = Buffer.allocUnsafe(4 + msgLen);
  frame.writeUInt32BE(msgLen, 0);
  frame.writeUInt8(msgType & 0xff, 4);
  payload.copy(frame, 5);
  return frame;
}

/**
 * Async reader that hands out [msgType, payload] tuples from a Node `net.Socket`.
 *
 * Internal state: a single resolver queue. The socket's `data` events accumulate
 * into a buffer; whenever a complete frame is present, the head waiter is
 * resolved with it. `error`, `end`, and `close` events propagate to all pending
 * waiters.
 */
export class FrameReader {
  private buffer = Buffer.alloc(0);
  private waiters: Array<{
    resolve: (frame: [number, Buffer]) => void;
    reject: (err: Error) => void;
  }> = [];
  private closed = false;
  private closeError: Error | null = null;

  constructor(private readonly sock: net.Socket) {
    sock.on("data", (chunk: Buffer) => this.onData(chunk));
    sock.on("error", (err) => this.onError(err));
    sock.on("end", () => this.onClose(null));
    sock.on("close", () => this.onClose(null));
  }

  private onData(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    this.drain();
  }

  private onError(err: Error): void {
    this.onClose(err);
  }

  private onClose(err: Error | null): void {
    if (this.closed) return;
    this.closed = true;
    this.closeError =
      err ?? new IpcError("IPC peer closed connection mid-message");
    for (const w of this.waiters) {
      w.reject(this.closeError);
    }
    this.waiters = [];
  }

  private drain(): void {
    while (this.waiters.length > 0 && this.tryReadOne()) {
      // tryReadOne resolves head waiter
    }
  }

  private tryReadOne(): boolean {
    if (this.buffer.length < 4) return false;
    const msgLen = this.buffer.readUInt32BE(0);
    if (msgLen === 0) {
      const head = this.waiters.shift();
      head?.reject(new IpcError("frame length 0 (illegal)"));
      return true;
    }
    if (msgLen > MAX_MESSAGE_SIZE) {
      const head = this.waiters.shift();
      head?.reject(
        new IpcError(
          `frame too large: ${msgLen} bytes (max ${MAX_MESSAGE_SIZE})`,
        ),
      );
      return true;
    }
    if (this.buffer.length < 4 + msgLen) return false;
    const frame = this.buffer.subarray(4, 4 + msgLen);
    const msgType = frame.readUInt8(0);
    const payload = Buffer.from(frame.subarray(1));
    this.buffer = Buffer.from(this.buffer.subarray(4 + msgLen));
    const head = this.waiters.shift();
    head?.resolve([msgType, payload]);
    return true;
  }

  read(): Promise<[number, Buffer]> {
    if (this.closed) {
      return Promise.reject(
        this.closeError ?? new IpcError("connection closed"),
      );
    }
    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
      this.drain();
    });
  }
}

// ── Handshake ───────────────────────────────────────────────────────

function encodeHandshake(role: number): Buffer {
  const buf = Buffer.allocUnsafe(9);
  buf.writeUInt16BE(PROTOCOL_VERSION, 0);
  buf.writeUInt16BE(SDK_VERSION_MAJOR, 2);
  buf.writeUInt16BE(SDK_VERSION_MINOR, 4);
  buf.writeUInt16BE(SDK_VERSION_PATCH, 6);
  buf.writeUInt8(role & 0xff, 8);
  return buf;
}

interface DecodedHandshake {
  protocol: number;
  major: number;
  minor: number;
  patch: number;
  role: number;
}

function decodeHandshake(payload: Buffer): DecodedHandshake {
  if (payload.length < 9) {
    throw new IpcError(
      `handshake payload too short: ${payload.length} (want >=9)`,
    );
  }
  return {
    protocol: payload.readUInt16BE(0),
    major: payload.readUInt16BE(2),
    minor: payload.readUInt16BE(4),
    patch: payload.readUInt16BE(6),
    role: payload.readUInt8(8),
  };
}

// ── Connect + AssemblerClient ───────────────────────────────────────

/**
 * Validate the socket file's owner UID and the parent directory's
 * mode bits *before* `net.connect` (H-4 2026-05-20).
 *
 * Node's `net.createConnection({ path })` happily attaches to any UDS
 * the current UID can `connect(2)` — which on a shared `/tmp/hawcx/`
 * directory includes sockets created by entirely different daemons
 * running under a different UID. Pre-connect validation drops the
 * mismatched-UID case before any handshake bytes are exchanged.
 *
 * Skipped on Windows (Named Pipes have a different ACL model; the
 * kernel enforces the pipe's DACL at `CreateFileW` time and surfaces
 * an `EACCES` we'd map to `IpcError` anyway).
 *
 * Resolution order for the expected UID:
 *
 * 1. `HAAP_SDK_EXPECTED_PEER_UID` env var (decimal). Override for
 *    cross-UID deployments.
 * 2. The socket file's `uid` from `fs.statSync` — works for the
 *    typical "same UID on both ends" pattern.
 *
 * Additionally, refuse to use the parent dir if:
 * - the dir's uid does not equal `process.getuid()`, OR
 * - the dir's mode has any group/other bit set (mask `0o077`).
 */
export interface UnixPeerCredResult {
  uid: number;
  mechanism: "SO_PEERCRED" | "LOCAL_PEERCRED";
}

export interface WindowsPipeServerInfo {
  serverPid: number;
  ownerSid: string;
  currentUserSid: string;
}

export type UnixPeerCredQueryFn = (
  fd: number,
  platform: NodeJS.Platform,
) => UnixPeerCredResult;

export type WindowsPipeServerQueryFn = (
  endpoint: string,
) => WindowsPipeServerInfo;

const LOCAL_WINDOWS_PIPE_RE = /^\\\\\.\\pipe\\[^\\/]+$/;
const WINDOWS_SID_RE = /^S-\d+-\d+(?:-\d+)+$/i;
const WINDOWS_TRUSTED_SYSTEM_SIDS = new Set([
  "S-1-5-18",     // NT AUTHORITY\SYSTEM
  "S-1-5-19",     // NT AUTHORITY\LOCAL SERVICE
  "S-1-5-32-544", // BUILTIN\Administrators (default object owner for elevated processes)
]);

const PYTHON_LINUX_PEERCRED_SCRIPT = [
  "import socket, struct",
  "s = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)",
  "try:",
  "    raw = s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('i2I'))",
  "    _pid, uid, _gid = struct.unpack('i2I', raw)",
  "    print(uid)",
  "finally:",
  "    s.close()",
].join("\n");

const PERL_LINUX_PEERCRED_SCRIPT = [
  "use Socket qw(SOL_SOCKET);",
  "my $opt = eval { Socket::SO_PEERCRED() };",
  "$opt = 17 unless defined $opt;",
  "open(my $fh, '+<&=', 3) or die \"open fd 3: $!\";",
  "my $c = getsockopt($fh, SOL_SOCKET, $opt);",
  "die \"getsockopt SO_PEERCRED: $!\" unless defined $c;",
  "my ($pid, $uid, $gid) = unpack('iII', $c);",
  "print \"$uid\\n\";",
].join("\n");

const PYTHON_DARWIN_PEERCRED_SCRIPT = [
  "import socket, struct",
  "s = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)",
  "try:",
  "    fmt = 'IIh16I'",
  "    raw = s.getsockopt(0, 0x001, struct.calcsize(fmt))",
  "    ver, uid = struct.unpack(fmt, raw)[:2]",
  "    if ver != 0:",
  "        raise RuntimeError(f'unexpected xucred version {ver}')",
  "    print(uid)",
  "finally:",
  "    s.close()",
].join("\n");

const PERL_DARWIN_PEERCRED_SCRIPT = [
  "open(my $fh, '+<&=', 3) or die \"open fd 3: $!\";",
  "my $c = getsockopt($fh, 0, 1);",
  "die \"getsockopt LOCAL_PEERCRED: $!\" unless defined $c;",
  "die 'short xucred' if length($c) < 8;",
  "my ($ver, $uid) = unpack('II', $c);",
  "die \"unexpected xucred version $ver\" unless $ver == 0;",
  "print \"$uid\\n\";",
].join("\n");

const POWERSHELL_WIN_PIPE_VERIFY_SCRIPT = `
$ErrorActionPreference = 'Stop'
$pipePath = $env:HAAP_VERIFY_PIPE_PATH
if (-not $pipePath) { throw 'missing HAAP_VERIFY_PIPE_PATH' }
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class HaapPipeVerifier {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern IntPtr CreateFileW(
    string lpFileName, uint dwDesiredAccess, uint dwShareMode,
    IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, IntPtr hTemplateFile);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool GetNamedPipeServerProcessId(IntPtr Pipe, out uint ServerProcessId);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool CloseHandle(IntPtr hObject);
  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern uint GetSecurityInfo(
    IntPtr handle, int ObjectType, uint SecurityInfo,
    out IntPtr ppsidOwner, out IntPtr ppsidGroup,
    out IntPtr ppDacl, out IntPtr ppSacl, out IntPtr ppSecurityDescriptor);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern IntPtr LocalFree(IntPtr hMem);

  public static string Inspect(string path) {
    // READ_CONTROL (0x00020000) | FILE_READ_ATTRIBUTES (0x00000080)
    // SECURITY_SQOS_PRESENT (0x00100000) | SECURITY_IDENTIFICATION (0x00010000)
    IntPtr h = CreateFileW(path, 0x00020080u, 0u, IntPtr.Zero, 3u, 0x00110000u, IntPtr.Zero);
    if (h == new IntPtr(-1)) {
      throw new Exception("CreateFileW failed: " + Marshal.GetLastWin32Error());
    }
    try {
      uint pid = 0;
      if (!GetNamedPipeServerProcessId(h, out pid) || pid == 0) {
        throw new Exception("GetNamedPipeServerProcessId failed: " + Marshal.GetLastWin32Error());
      }
      IntPtr pOwner, pGroup, pDacl, pSacl, pSd;
      uint rc = GetSecurityInfo(h, 6 /* SE_KERNEL_OBJECT */, 1 /* OWNER_SECURITY_INFORMATION */,
                                out pOwner, out pGroup, out pDacl, out pSacl, out pSd);
      if (rc != 0) {
        throw new Exception("GetSecurityInfo failed: " + rc);
      }
      try {
        string ownerSid = new SecurityIdentifier(pOwner).Value;
        string selfSid = WindowsIdentity.GetCurrent().User.Value;
        return pid.ToString() + "|" + ownerSid + "|" + selfSid;
      } finally {
        if (pSd != IntPtr.Zero) LocalFree(pSd);
      }
    } finally {
      CloseHandle(h);
    }
  }
}
"@
[HaapPipeVerifier]::Inspect($pipePath)
`;

function parseStrictUid(raw: string, label: string): number {
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new IpcError(`${label}=${raw} is not a valid uid`);
  }
  const parsed = Number.parseInt(trimmed, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffffffff) {
    throw new IpcError(`${label}=${raw} is not a valid uid`);
  }
  return parsed;
}

function defaultQueryUnixPeerUid(
  fd: number,
  platform: NodeJS.Platform,
): UnixPeerCredResult {
  if (platform !== "linux" && platform !== "darwin") {
    throw new IpcError(
      `kernel peer-UID verification is unsupported on platform '${platform}'`,
    );
  }
  const mechanism: "SO_PEERCRED" | "LOCAL_PEERCRED" =
    platform === "linux" ? "SO_PEERCRED" : "LOCAL_PEERCRED";
  const candidates: Array<{ bin: string; args: string[] }> =
    platform === "linux"
      ? [
          { bin: "python3", args: ["-c", PYTHON_LINUX_PEERCRED_SCRIPT] },
          { bin: "perl", args: ["-e", PERL_LINUX_PEERCRED_SCRIPT] },
        ]
      : [
          { bin: "python3", args: ["-c", PYTHON_DARWIN_PEERCRED_SCRIPT] },
          { bin: "perl", args: ["-e", PERL_DARWIN_PEERCRED_SCRIPT] },
        ];

  let lastErr: Error | null = null;
  for (const { bin, args } of candidates) {
    try {
      // Pass the connected socket fd as inherited fd 3 to the helper so it
      // executes getsockopt(3, ...) on the exact connected kernel socket.
      const out = execFileSync(bin, args, {
        stdio: ["ignore", "pipe", "pipe", fd],
        encoding: "utf8",
        timeout: 5000,
      });
      const uid = parseStrictUid(out, `${mechanism} peer uid`);
      return { uid, mechanism };
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "ENOENT") {
        lastErr = e;
        continue;
      }
      throw new IpcError(
        `${mechanism} lookup via ${bin} failed: ${e.message}`,
      );
    }
  }
  throw new IpcError(
    `cannot verify ${mechanism}: neither python3 nor perl is available (${lastErr?.message ?? "ENOENT"})`,
  );
}

function defaultQueryWindowsPipeServer(endpoint: string): WindowsPipeServerInfo {
  let out: string;
  try {
    out = execFileSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", POWERSHELL_WIN_PIPE_VERIFY_SCRIPT],
      {
        stdio: ["ignore", "pipe", "pipe"],
        encoding: "utf8",
        timeout: 10000,
        env: { ...process.env, HAAP_VERIFY_PIPE_PATH: endpoint },
      },
    );
  } catch (err) {
    throw new IpcError(
      `Windows Named Pipe server verification failed for ${endpoint}: ${(err as Error).message}`,
    );
  }
  const parts = out.trim().split("|");
  if (parts.length !== 3) {
    throw new IpcError(
      `Windows Named Pipe server verification returned malformed output for ${endpoint}`,
    );
  }
  const serverPid = Number.parseInt(parts[0] ?? "", 10);
  const ownerSid = (parts[1] ?? "").trim();
  const currentUserSid = (parts[2] ?? "").trim();
  if (
    !Number.isSafeInteger(serverPid) ||
    serverPid <= 0 ||
    !WINDOWS_SID_RE.test(ownerSid) ||
    !WINDOWS_SID_RE.test(currentUserSid)
  ) {
    throw new IpcError(
      `Windows Named Pipe server verification returned invalid identity for ${endpoint}`,
    );
  }
  return { serverPid, ownerSid, currentUserSid };
}

let unixPeerCredQueryImpl: UnixPeerCredQueryFn = defaultQueryUnixPeerUid;
let windowsPipeServerQueryImpl: WindowsPipeServerQueryFn =
  defaultQueryWindowsPipeServer;

/**
 * @internal Override peer-credential query hooks in unit tests.
 */
export function _setPeerVerifiersForTesting(overrides: {
  unix?: UnixPeerCredQueryFn | null;
  windows?: WindowsPipeServerQueryFn | null;
}): void {
  if ("unix" in overrides) {
    unixPeerCredQueryImpl = overrides.unix ?? defaultQueryUnixPeerUid;
  }
  if ("windows" in overrides) {
    windowsPipeServerQueryImpl =
      overrides.windows ?? defaultQueryWindowsPipeServer;
  }
}

/**
 * Validate a Windows Named Pipe endpoint path and optional
 * `HAAP_SDK_EXPECTED_PEER_SID` env var before connecting.
 *
 * Refuses remote UNC pipes and path traversal.
 */
export function validateWindowsNamedPipePath(endpoint: string): string | null {
  if (!LOCAL_WINDOWS_PIPE_RE.test(endpoint)) {
    throw new IpcError(
      `Windows IPC endpoint '${endpoint}' must be a local Named Pipe (\\\\.\\pipe\\<name>); refusing remote or malformed pipe path`,
    );
  }
  const expectedSidEnv = process.env.HAAP_SDK_EXPECTED_PEER_SID;
  if (expectedSidEnv === undefined) {
    return null;
  }
  const trimmed = expectedSidEnv.trim();
  if (!WINDOWS_SID_RE.test(trimmed)) {
    throw new IpcError(
      `HAAP_SDK_EXPECTED_PEER_SID=${expectedSidEnv} is not a valid Windows SID`,
    );
  }
  return trimmed;
}

/**
 * Verify a Windows Named Pipe server's local PID and owner SID before
 * exchanging any IPC handshake bytes.
 */
export function verifyWindowsNamedPipeServer(
  endpoint: string,
  expectedSid: string | null,
): void {
  const info = windowsPipeServerQueryImpl(endpoint);
  if (!Number.isSafeInteger(info.serverPid) || info.serverPid <= 0) {
    throw new IpcError(
      `Windows Named Pipe ${endpoint} reported invalid server PID ${info.serverPid}; refusing the connection`,
    );
  }
  const ownerUpper = info.ownerSid.toUpperCase();
  if (expectedSid !== null) {
    if (ownerUpper !== expectedSid.toUpperCase()) {
      throw new IpcError(
        `Windows Named Pipe ${endpoint} is owned by SID ${info.ownerSid}, expected ${expectedSid}; refusing the connection`,
      );
    }
    return;
  }
  const selfUpper = info.currentUserSid.toUpperCase();
  if (ownerUpper !== selfUpper && !WINDOWS_TRUSTED_SYSTEM_SIDS.has(ownerUpper)) {
    throw new IpcError(
      `Windows Named Pipe ${endpoint} is owned by untrusted SID ${info.ownerSid} (current user SID ${info.currentUserSid}); refusing the connection`,
    );
  }
}

interface ValidatedUnixSocket {
  sockStat: fs.Stats;
  expectedUid: number;
}

function validateIpcSocketPath(endpoint: string): ValidatedUnixSocket {
  const getuid = process.getuid;
  if (typeof getuid !== "function") {
    throw new IpcError(
      "process.getuid() is unavailable on this platform; refusing to " +
        "connect to a UDS without UID validation",
    );
  }
  const ourUid = getuid();

  let sockStat: fs.Stats;
  try {
    sockStat = fs.statSync(endpoint);
  } catch (err) {
    throw new IpcError(
      `stat ${endpoint} failed: ${(err as Error).message}`,
    );
  }
  if (!sockStat.isSocket()) {
    throw new IpcError(`${endpoint} is not a Unix domain socket`);
  }

  const expectedUidEnv = process.env.HAAP_SDK_EXPECTED_PEER_UID;
  const expectedUid =
    expectedUidEnv !== undefined
      ? parseStrictUid(expectedUidEnv, "HAAP_SDK_EXPECTED_PEER_UID")
      : sockStat.uid;
  // H-4's inode-owner-vs-expected-peer comparison is REMOVED (Ravi, 2026-08-30).
  //
  // It compared a file OWNERSHIP stat against a peer-PROCESS expectation, and
  // `agent-assembler-N.sock` is the one socket where those are deliberately
  // different principals: root binds it, `bind_peer_owned_uds` fchowns it to the
  // LLM principal (ownership governs connect()), and the Assembler accepts on the
  // inherited fd as the CREDENTIAL principal -- which is what
  // HAAP_SDK_EXPECTED_PEER_UID names. See graph.rs:4318-4333 and 5781-5785.
  //
  // The comparison could never fire correctly:
  //   unset -> expectedUid = sockStat.uid, so the test is `x !== x`
  //   set   -> CAS deliberately makes the two differ: guaranteed false positive
  //
  // The surviving control is stronger and untouched: verifyPeerAfterConnect
  // reads SO_PEERCRED off the CONNECTED socket and compares it to the credential
  // principal -- kernel-attested and immune to the path swap a pre-connect stat
  // can never catch. `expectedUid` is still resolved above because that path
  // reuses the same env resolution.
  //
  // This removes a check that was structurally incapable of working; it does not
  // loosen the peer-identity guarantee.

  // Validate the parent directory. The socket's mode is necessarily
  // 0o600 (set by the supervisor at bind time, per haap-sdk-ipc's
  // IpcServer::bind), but if the parent dir is world-writable an
  // attacker can swap the socket for a same-named socket of theirs.
  const parent = path.dirname(endpoint);
  let parentStat: fs.Stats;
  try {
    parentStat = fs.statSync(parent);
  } catch (err) {
    throw new IpcError(
      `stat parent dir ${parent} failed: ${(err as Error).message}`,
    );
  }
  // Root is a trusted creator, matching the Rust side's rule.
  //
  // `validateSocketParentDir`'s Rust counterpart requires every ancestor to be
  // "owned by this process's own euid (or root)". Dropping the root allowance
  // makes this SDK strictly stricter than Rust in a way that can never succeed:
  // the supervisor creates <base>/<agentId>/ as root before dropping to the
  // per-agent uid -- and it MUST, or its own `bind_peer_owned_uds` refuses to
  // bind there -- so a supervisor-spawned agent always sees a root-owned parent.
  // The write-bit check below still rejects anything an unprivileged attacker
  // could plant.
  if (parentStat.uid !== ourUid && parentStat.uid !== 0) {
    throw new IpcError(
      `IPC parent dir ${parent} is owned by uid ${parentStat.uid}, this process is uid ${ourUid}; ` +
        "refusing to use a dir created by another user",
    );
  }
  // Stats.mode in Node includes the file type bits. Mask to permission bits.
  const parentPerms = parentStat.mode & 0o777;
  // Group/other WRITE, not group/other anything -- again matching Rust.
  //
  // `validate_socket_parent_dir` requires the chain carry "no group/other write
  // bit" (0o022). Masking 0o077 additionally rejects the execute bit, and execute
  // is exactly what the supervisor's layout needs: the per-agent dir is 0711 so
  // the agent principal can TRAVERSE to the socket without listing the directory.
  // 0700 is the configuration measured to break every consumer with EACCES, and
  // the supervisor resets the dir to 0711 on next launch anyway.
  //
  // Write is the bit that matters: it is what would let another principal plant
  // or swap a socket. Execute-only traversal grants none of that.
  if ((parentPerms & 0o022) !== 0) {
    // Allow operators to opt out for /tmp/hawcx/ with the same env flag the Rust
    // side honours, but require explicit opt-in. NOTE: this gates the mode branch
    // ONLY -- not the owner check above.
    if (process.env.HAAP_SDK_ALLOW_TMP_IPC !== "1") {
      throw new IpcError(
        `IPC parent dir ${parent} has mode ${parentPerms.toString(8)}; ` +
          "refusing to use a dir that is group- or other-WRITABLE. " +
          "Do NOT chmod 700 a supervisor-managed dir: the per-agent dir is " +
          "deliberately 0711 so the agent principal can traverse it, 0700 makes " +
          "every consumer fail with EACCES, and the supervisor resets it to 0711 " +
          "on next launch. HAAP_SDK_ALLOW_TMP_IPC=1 opts into the legacy " +
          "/tmp/hawcx/ path and does not apply here.",
      );
    }
  }
  return { sockStat, expectedUid };
}

/**
 * Verify the connected Unix domain socket peer's kernel-attested UID against
 * `expectedUid` using `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS).
 *
 * Destroys `sock` and throws `IpcError` on any mismatch or lookup failure.
 */
function verifyPeerAfterConnect(
  sock: net.Socket,
  expectedUid: number,
  endpoint: string,
): void {
  const handle = (sock as unknown as { _handle?: { fd?: number } })._handle;
  const fd = handle?.fd;
  if (typeof fd !== "number" || fd < 0) {
    sock.destroy();
    throw new IpcError(
      `connected IPC socket ${endpoint} has no underlying OS file descriptor; refusing without peer-UID verification`,
    );
  }
  let peer: UnixPeerCredResult;
  try {
    peer = unixPeerCredQueryImpl(fd, process.platform);
  } catch (err) {
    sock.destroy();
    if (err instanceof IpcError) {
      throw err;
    }
    throw new IpcError(
      `peer credential verification on ${endpoint} failed: ${(err as Error).message}`,
    );
  }
  if (peer.uid !== expectedUid) {
    sock.destroy();
    throw new IpcError(
      `IPC peer on ${endpoint} has uid ${peer.uid}, expected ${expectedUid} (${peer.mechanism}); refusing the connection`,
    );
  }
}

/**
 * Connect to the Assembler at `endpoint` and return a Node `net.Socket`.
 *
 * On Unix, `endpoint` is a filesystem path to a Unix domain socket.
 * On Windows, `endpoint` is a Named Pipe path
 * (`\\\\.\\pipe\\haap-<agent_id>-agent-assembler-<index>`). Node's `net.connect`
 * supports both via the `path` option.
 */
export function connectAssembler(
  endpoint: string,
  timeoutMs: number,
): Promise<net.Socket> {
  if (process.platform === "win32") {
    let expectedSid: string | null;
    try {
      expectedSid = validateWindowsNamedPipePath(endpoint);
      verifyWindowsNamedPipeServer(endpoint, expectedSid);
    } catch (err) {
      return Promise.reject(err);
    }
    return new Promise((resolve, reject) => {
      const sock = net.createConnection({ path: endpoint });
      const timer =
        timeoutMs > 0
          ? setTimeout(() => {
              sock.destroy();
              reject(new IpcError(`timed out connecting to ${endpoint}`));
            }, timeoutMs)
          : null;
      const onError = (err: Error) => {
        if (timer) clearTimeout(timer);
        reject(new IpcError(`connect ${endpoint} failed: ${err.message}`));
      };
      sock.once("error", onError);
      sock.once("connect", () => {
        if (timer) clearTimeout(timer);
        sock.removeListener("error", onError);
        resolve(sock);
      });
    });
  }

  let validated: ValidatedUnixSocket;
  try {
    validated = validateIpcSocketPath(endpoint);
  } catch (err) {
    return Promise.reject(err);
  }
  const { expectedUid } = validated;

  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ path: endpoint });
    const timer =
      timeoutMs > 0
        ? setTimeout(() => {
            sock.destroy();
            reject(new IpcError(`timed out connecting to ${endpoint}`));
          }, timeoutMs)
        : null;
    const onError = (err: Error) => {
      if (timer) clearTimeout(timer);
      reject(new IpcError(`connect ${endpoint} failed: ${err.message}`));
    };
    sock.once("error", onError);
    sock.once("connect", () => {
      if (timer) clearTimeout(timer);
      sock.removeListener("error", onError);
      try {
        verifyPeerAfterConnect(sock, expectedUid, endpoint);
      } catch (err) {
        reject(err);
        return;
      }
      resolve(sock);
    });
  });
}

/**
 * Synchronous-feeling, async client for the Assembler IPC channel.
 *
 * On `connect`, performs the version handshake (role = `Agent`). After that,
 * the connection is ready for ToolCallRequest / ToolCallResponse round-trips.
 *
 * Not safe to invoke concurrently. Wrap in a queue for parallel calls.
 */
export class AssemblerClient {
  private constructor(
    private readonly sock: net.Socket,
    private readonly reader: FrameReader,
    /**
     * Experimental MCP capabilities the SDK is advertising on this
     * connection. The Assembler echoes these into the `experimental`
     * field of its outbound MCP `initialize` calls, allowing the
     * upstream MCP server to negotiate features. Today the only
     * entry is `hawcx-haap-v7-2-5` (M-6).
     */
    private readonly experimentalCapabilities: readonly string[],
  ) {}

  static async connect(
    endpoint: string,
    options: {
      timeoutMs?: number;
      /**
       * Experimental MCP capabilities to advertise via the Assembler
       * to upstream MCP servers (HAAP v7.2.5 §45.7.5). The Assembler
       * includes these verbatim in its outbound MCP `initialize` as
       * `params.capabilities.experimental[cap] = {}`. Pass
       * `[HAWCX_HAAP_V7_2_5_CAPABILITY]` to enable v7.2.5 payload
       * carriage end-to-end. Empty array (default) means legacy
       * v6.7.4 carriage only.
       */
      experimentalCapabilities?: readonly string[];
    } = {},
  ): Promise<AssemblerClient> {
    const timeoutMs = options.timeoutMs ?? 5000;
    const capabilities = options.experimentalCapabilities ?? [];
    const sock = await connectAssembler(endpoint, timeoutMs);
    const reader = new FrameReader(sock);
    try {
      await write(sock, encodeFrame(MSG_TYPE_HANDSHAKE, encodeHandshake(ROLE_AGENT)));
      const [type, payload] = await reader.read();
      if (type !== MSG_TYPE_HANDSHAKE) {
        throw new IpcError(
          `expected handshake (0x00), got 0x${type.toString(16).padStart(2, "0")}`,
        );
      }
      const hs = decodeHandshake(payload);
      if (hs.major !== SDK_VERSION_MAJOR) {
        throw new HandshakeError(SDK_VERSION_MAJOR, hs.major);
      }
      if (hs.role !== ROLE_ASSEMBLER) {
        throw new IpcError(
          `expected peer role Assembler (0x05), got 0x${hs.role.toString(16).padStart(2, "0")}`,
        );
      }
    } catch (err) {
      sock.destroy();
      throw err;
    }
    return new AssemblerClient(sock, reader, capabilities);
  }

  async invoke(req: ToolCallRequest): Promise<ToolCallResponse> {
    const wire = toolCallRequestToWire(req);
    // Forward the connection-level experimental capability list on
    // every call so the Assembler can re-key its MCP initialize when
    // a new upstream server is contacted (each ToolCallRequest may
    // target a new RS / MCP server). Wire key matches the Rust-side
    // serde rename (`hawcx_experimental_capabilities`).
    if (this.experimentalCapabilities.length > 0) {
      wire.hawcx_experimental_capabilities = [
        ...this.experimentalCapabilities,
      ];
    }
    const payload = Buffer.from(JSON.stringify(wire), "utf-8");
    await write(this.sock, encodeFrame(MSG_TOOL_CALL_REQUEST, payload));

    const [type, body] = await this.reader.read();
    if (type === MSG_TOOL_CALL_RESPONSE) {
      const obj = JSON.parse(body.toString("utf-8")) as Record<string, unknown>;
      return toolCallResponseFromWire(obj);
    }
    if (type === MSG_REQUEST_REJECTED) {
      const obj = JSON.parse(body.toString("utf-8")) as Record<string, unknown>;
      throw new RequestRejected(
        String(obj.request_id ?? req.requestId),
        String(obj.reason ?? ""),
      );
    }
    throw new IpcError(
      `unexpected response msg_type 0x${type.toString(16).padStart(2, "0")}; expected 0x53 or 0x54`,
    );
  }

  async sendClarificationAnswer(args: {
    pendingId: string;
    sessionId: number | bigint;
    answerIndex?: number;
    answerText?: string;
  }): Promise<void> {
    // `session_id` is a `u64` on the Rust side
    // (`haap_ipc::messages::assembler::ClarificationAnswer`). The
    // previous code unconditionally narrowed `bigint` to `Number`
    // via `Number(args.sessionId)`, which silently truncates session
    // IDs above 2^53 (`Number.MAX_SAFE_INTEGER`). The Rust side then
    // looked up the *wrong* session and returned a "session not
    // found" rejection — a confusing failure mode rooted in JS-side
    // narrowing (M-5 hardening 2026-05-20).
    //
    // Fix: bigint inputs are emitted as a decimal string so no
    // precision is lost. Number inputs are passed through unchanged
    // (the common path — caller already chose `number`).
    //
    // BREAKING WIRE CHANGE (bigint path only): a follow-up bug filed
    // against `hx_agent_crypto_core`'s `crates/haap-ipc/src/messages/assembler.rs`
    // tracks adding a serde `deserialize_with` helper so `u64` will
    // accept both a JSON number and a string-encoded decimal. Until
    // that lands, callers passing `bigint` values above 2^53 will
    // hit a deserialiser error on the Assembler side rather than
    // silent truncation — which is the correct failure mode.
    const obj: Record<string, unknown> = {
      pending_id: args.pendingId,
      session_id: encodeSessionIdForWire(args.sessionId),
    };
    if (args.answerIndex !== undefined) obj.answer_index = args.answerIndex;
    if (args.answerText !== undefined) obj.answer_text = args.answerText;
    const payload = Buffer.from(JSON.stringify(obj), "utf-8");
    await write(this.sock, encodeFrame(MSG_CLARIFICATION_ANSWER, payload));
  }

  close(): void {
    this.sock.destroy();
  }
}

/**
 * Encode a `session_id` for the JSON wire payload.
 *
 * `bigint` inputs are emitted as a decimal string (so 64-bit values
 * above `Number.MAX_SAFE_INTEGER` round-trip without precision loss
 * once the Rust deserialiser learns to accept the string form).
 * `number` inputs are passed through unchanged (emitted as a JSON
 * number by `JSON.stringify`).
 *
 * Exported so unit tests can pin the exact wire shape.
 */
export function encodeSessionIdForWire(
  sessionId: number | bigint,
): number | string {
  return typeof sessionId === "bigint" ? sessionId.toString(10) : sessionId;
}

export function writeFrameBytes(sock: net.Socket, data: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    sock.write(data, (err) => {
      if (err) reject(new IpcError(`write failed: ${err.message}`));
      else resolve();
    });
  });
}

function write(sock: net.Socket, data: Buffer): Promise<void> {
  return writeFrameBytes(sock, data);
}
