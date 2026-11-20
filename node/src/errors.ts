/**
 * Error types raised by `@hawcx/hawcx-haap`.
 */

export class HawcxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * Local IPC transport error (connect refused, EOF, framing, etc.).
 */
export class IpcError extends HawcxError {}

/**
 * IPC version handshake failed because the Assembler's major SDK version
 * does not match this client's.
 */
export class HandshakeError extends IpcError {
  constructor(
    readonly localMajor: number,
    readonly remoteMajor: number,
  ) {
    super(
      `IPC handshake major version mismatch: local=${localMajor} remote=${remoteMajor}`,
    );
  }
}

/**
 * Assembler returned `MSG_REQUEST_REJECTED` (0x54). The `reason` is the
 * free-text string from the Assembler; callers may match on it for known
 * cases (e.g. `"destination not in allowlist"`).
 */
export class RequestRejected extends HawcxError {
  constructor(
    readonly requestId: string,
    readonly reason: string,
  ) {
    super(`HAAP request '${requestId}' rejected: ${reason}`);
  }
}

/**
 * The Authenticator rejected runtime enrollment (`Degraded` variant or generic
 * `{"error": "..."}` envelope). Mirrors Python `EnrollmentRejected`.
 */
export class EnrollmentRejected extends HawcxError {
  constructor(
    readonly reason: string,
    readonly agentInstanceId: string | null = null,
  ) {
    super(`HAAP enrollment rejected: ${reason}`);
  }
}
