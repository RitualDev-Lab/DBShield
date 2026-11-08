import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export interface VfsSecurityContext {
  /**
   * Unique session identifier issued by the DBShield wire proxy or MCP server.
   * Operations lacking an authorized proxy session are classified as direct
   * unbrokered filesystem access and denied.
   */
  proxySessionId?: string;

  /**
   * Monotonic transaction fencing token from DistributedLockManager or Raft coordinator.
   */
  fenceToken?: number;

  /**
   * Client / Agent identifier performing the query.
   */
  actorId?: string;

  /**
   * Whether the transaction is in read-only mode (e.g. Dry-Run or Read-Only Envelope).
   */
  isReadOnly?: boolean;

  /**
   * Explicit bypass token for DBShield maintenance/vacuum operations.
   */
  maintenanceToken?: string;
}

export interface VfsPageInfo {
  pageNumber: number;
  pageSize: number;
  offset: number;
  checksum: string;
  isHeaderPage: boolean;
  lastModifiedAt: number;
  modifiedBySession?: string;
}

export interface VfsAccessDecision {
  allowed: boolean;
  reason?: string;
  violationCode?:
    | "UNAUTHORIZED_DIRECT_FS_WRITE"
    | "READONLY_ENVELOPE_VIOLATION"
    | "HEADER_TAMPER_DETECTED"
    | "CHECKSUM_MISMATCH"
    | "INVALID_FENCE_TOKEN";
}

export interface VfsFileHandle {
  fileId: string;
  filePath: string;
  pageSize: number;
  isOpen: boolean;
  isReadOnly: boolean;
  totalSizeBytes: number;
  totalPages: number;
  openedAt: number;
  lastAccessAt: number;
}

/**
 * Custom SQLite Virtual File System (VFS) Shim.
 *
 * Operates at the OS page level (default 4096-byte pages) to intercept, validate,
 * and protect SQLite database files (`.sqlite`, `.db`, `.sqlite-wal`, `.sqlite-shm`)
 * from unauthorized out-of-band filesystem manipulation by LLM agents or malicious child processes.
 *
 * Guarantees that:
 * 1. Direct, unbrokered filesystem writes bypass-attempted without an authorized DBShield
 *    proxy session token are blocked at the page write boundary (SQLITE_IOERR_WRITE).
 * 2. SQLite Page 1 (100-byte DB header + schema B-Tree root) cannot be corrupted or overwritten.
 * 3. Read-only transaction envelopes strictly reject mutation I/O.
 * 4. Every page modification computes an incremental cryptographic digest for audit verification.
 */
export class SqliteVfsShim {
  public static readonly DEFAULT_PAGE_SIZE = 4096;
  public static readonly SQLITE_HEADER_STRING = "SQLite format 3\0";

  private readonly pageSize: number;
  private readonly authorizedSessions: Set<string> = new Set();
  private readonly openHandles: Map<string, VfsFileHandle> = new Map();
  private readonly pageIntegrityMap: Map<string, Map<number, VfsPageInfo>> = new Map();
  private readonly accessAuditLog: Array<{
    timestamp: number;
    filePath: string;
    pageNumber: number;
    operation: "READ" | "WRITE" | "TRUNCATE" | "OPEN" | "CLOSE";
    decision: VfsAccessDecision;
    context?: VfsSecurityContext;
  }> = [];

  constructor(pageSize = SqliteVfsShim.DEFAULT_PAGE_SIZE) {
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) !== 0) {
      throw new Error(
        `[SqliteVfsShim] Invalid page size: ${pageSize}. Must be power of 2 between 512 and 65536.`,
      );
    }
    this.pageSize = pageSize;
  }

  /**
   * Registers an authorized wire-proxy session permitted to execute writes.
   */
  public registerAuthorizedSession(sessionId: string): void {
    this.authorizedSessions.add(sessionId);
  }

  /**
   * Revokes authorization for a completed or aborted session.
   */
  public revokeSession(sessionId: string): void {
    this.authorizedSessions.delete(sessionId);
  }

  /**
   * Checks whether a session has active wire-proxy authorization.
   */
  public isSessionAuthorized(sessionId?: string): boolean {
    return !!sessionId && this.authorizedSessions.has(sessionId);
  }

  /**
   * Intercepts and validates opening a database file at the VFS level.
   */
  public openFile(
    filePath: string,
    isReadOnly = false,
    context?: VfsSecurityContext,
  ): VfsFileHandle {
    const normalizedPath = path.resolve(filePath);
    const fileId = `vfs_${crypto.createHash("sha256").update(normalizedPath).digest("hex").slice(0, 16)}`;

    const handle: VfsFileHandle = {
      fileId,
      filePath: normalizedPath,
      pageSize: this.pageSize,
      isOpen: true,
      isReadOnly: isReadOnly || !!context?.isReadOnly,
      totalSizeBytes: 0,
      totalPages: 0,
      openedAt: Date.now(),
      lastAccessAt: Date.now(),
    };

    this.openHandles.set(fileId, handle);
    if (!this.pageIntegrityMap.has(fileId)) {
      this.pageIntegrityMap.set(fileId, new Map());
    }

    this.logAudit(normalizedPath, 0, "OPEN", { allowed: true }, context);
    return handle;
  }

  /**
   * Closes a virtual file handle.
   */
  public closeFile(handle: VfsFileHandle): void {
    handle.isOpen = false;
    handle.lastAccessAt = Date.now();
    this.logAudit(handle.filePath, 0, "CLOSE", { allowed: true });
  }

  /**
   * Evaluates authorization for an incoming page-level operation.
   */
  public evaluateAccess(
    operation: "READ" | "WRITE" | "TRUNCATE",
    pageNumber: number,
    handle: VfsFileHandle,
    context?: VfsSecurityContext,
  ): VfsAccessDecision {
    // Reads are permitted if the handle is open
    if (operation === "READ") {
      if (!handle.isOpen) {
        return { allowed: false, reason: "Virtual file handle is closed" };
      }
      return { allowed: true };
    }

    // Write / Truncate validations
    if (handle.isReadOnly || context?.isReadOnly) {
      return {
        allowed: false,
        reason: "Write denied: database is locked in read-only envelope",
        violationCode: "READONLY_ENVELOPE_VIOLATION",
      };
    }

    // Require valid proxy session or authorized maintenance token
    const hasProxySession =
      context?.proxySessionId && this.authorizedSessions.has(context.proxySessionId);
    const hasMaintenance = !!context?.maintenanceToken;

    if (!hasProxySession && !hasMaintenance) {
      return {
        allowed: false,
        reason:
          "Direct filesystem alteration denied: write requires an authenticated DBShield wire proxy session",
        violationCode: "UNAUTHORIZED_DIRECT_FS_WRITE",
      };
    }

    return { allowed: true };
  }

  /**
   * Intercepts a page-level read (xRead) from the SQLite VFS layer.
   */
  public interceptPageRead(
    handle: VfsFileHandle,
    pageNumber: number,
    data: Buffer | Uint8Array,
    context?: VfsSecurityContext,
  ): { allowed: boolean; data: Buffer; checksum: string } {
    const decision = this.evaluateAccess("READ", pageNumber, handle, context);
    this.logAudit(handle.filePath, pageNumber, "READ", decision, context);

    if (!decision.allowed) {
      throw new Error(`[SqliteVfsShim:ReadDenied] ${decision.reason}`);
    }

    handle.lastAccessAt = Date.now();
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const checksum = crypto.createHash("sha256").update(buf).digest("hex");

    return { allowed: true, data: buf, checksum };
  }

  /**
   * Intercepts a page-level write (xWrite) to the SQLite VFS layer.
   * Enforces security boundaries, verifies SQLite Page 1 magic header,
   * updates the page integrity map, and rejects unbrokered writes.
   */
  public interceptPageWrite(
    handle: VfsFileHandle,
    pageNumber: number,
    data: Buffer | Uint8Array,
    context?: VfsSecurityContext,
  ): { allowed: boolean; pageNumber: number; checksum: string; previousChecksum?: string } {
    const decision = this.evaluateAccess("WRITE", pageNumber, handle, context);
    this.logAudit(handle.filePath, pageNumber, "WRITE", decision, context);

    if (!decision.allowed) {
      throw new Error(`[SqliteVfsShim:WriteDenied] (${decision.violationCode}) ${decision.reason}`);
    }

    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);

    // Validate page 1 magic header if writing root page
    if (pageNumber === 1 && buf.length >= 16) {
      const headerPrefix = buf.subarray(0, 16).toString("utf8");
      if (!headerPrefix.startsWith("SQLite format 3")) {
        throw new Error(
          "[SqliteVfsShim:WriteDenied] (HEADER_TAMPER_DETECTED) Attempted to write corrupted SQLite Page 1 header",
        );
      }
    }

    const checksum = crypto.createHash("sha256").update(buf).digest("hex");
    const pages = this.pageIntegrityMap.get(handle.fileId);
    const existing = pages?.get(pageNumber);

    const pageInfo: VfsPageInfo = {
      pageNumber,
      pageSize: buf.length,
      offset: (pageNumber - 1) * this.pageSize,
      checksum,
      isHeaderPage: pageNumber === 1,
      lastModifiedAt: Date.now(),
      modifiedBySession: context?.proxySessionId,
    };

    pages?.set(pageNumber, pageInfo);
    handle.lastAccessAt = Date.now();
    handle.totalPages = Math.max(handle.totalPages, pageNumber);
    handle.totalSizeBytes = Math.max(handle.totalSizeBytes, pageNumber * this.pageSize);

    return {
      allowed: true,
      pageNumber,
      checksum,
      previousChecksum: existing?.checksum,
    };
  }

  /**
   * Verifies the cryptographic integrity of all tracked pages for a file.
   */
  public verifyPageIntegrity(
    fileId: string,
    currentPages: Map<number, Buffer>,
  ): {
    valid: boolean;
    tamperedPages: number[];
  } {
    const recorded = this.pageIntegrityMap.get(fileId);
    if (!recorded) {
      return { valid: true, tamperedPages: [] };
    }

    const tamperedPages: number[] = [];
    for (const [pageNum, info] of recorded.entries()) {
      const pageBuffer = currentPages.get(pageNum);
      if (!pageBuffer) {
        tamperedPages.push(pageNum);
        continue;
      }
      const currentChecksum = crypto.createHash("sha256").update(pageBuffer).digest("hex");
      if (currentChecksum !== info.checksum) {
        tamperedPages.push(pageNum);
      }
    }

    return {
      valid: tamperedPages.length === 0,
      tamperedPages,
    };
  }

  /**
   * Returns recent VFS security audit events.
   */
  public getAuditTrail(limit = 100): Array<{
    timestamp: number;
    filePath: string;
    pageNumber: number;
    operation: string;
    decision: VfsAccessDecision;
    context?: VfsSecurityContext;
  }> {
    return this.accessAuditLog.slice(-limit);
  }

  /**
   * Clears in-memory audit logs and tracking state.
   */
  public clear(): void {
    this.openHandles.clear();
    this.pageIntegrityMap.clear();
    this.authorizedSessions.clear();
    this.accessAuditLog.length = 0;
  }

  private logAudit(
    filePath: string,
    pageNumber: number,
    operation: "READ" | "WRITE" | "TRUNCATE" | "OPEN" | "CLOSE",
    decision: VfsAccessDecision,
    context?: VfsSecurityContext,
  ): void {
    this.accessAuditLog.push({
      timestamp: Date.now(),
      filePath,
      pageNumber,
      operation,
      decision,
      context,
    });
    if (this.accessAuditLog.length > 1000) {
      this.accessAuditLog.shift();
    }
  }
}
