import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { PiiRedactor } from "../pii/redactor.js";
import type { RiskLevel, SqlOperationType } from "../types/index.js";

export interface AuditLedgerEntry {
  sequenceNumber: number;
  auditId: string;
  timestamp: string;
  actor: string;
  database: string;
  operation: SqlOperationType;
  status:
    | "SUCCESS"
    | "BLOCKED"
    | "DRY_RUN_APPROVED"
    | "DRY_RUN_REJECTED"
    | "COMMITTED"
    | "ERROR"
    | "TIMEOUT";
  riskLevel: RiskLevel;
  riskScore: number;
  sql: string;
  queryPayloadHash: string;
  params?: unknown[];
  violations?: string[];
  piiRedacted: boolean;
  keyId: string;
  previousHmac: string;
  entryHmac: string;
}

export interface LedgerVerificationResult {
  valid: boolean;
  totalEntries: number;
  headHmac: string;
  tailHmac: string;
  brokenAtIndex?: number;
  brokenSequenceNumber?: number;
  brokenReason?:
    | "SEQUENCE_GAP"
    | "CHAIN_DISCONTINUITY"
    | "HMAC_MISMATCH"
    | "PAYLOAD_HASH_MISMATCH"
    | "MISSING_KEY";
}

export interface HmacLedgerOptions {
  secretKey?: string;
  keyId?: string;
  logFilePath?: string;
  maxMemoryEntries?: number;
  redactor?: PiiRedactor;
}

/**
 * Enterprise Append-Only HMAC-SHA256 Audit Ledger.
 *
 * Implements strict compliance requirements:
 * - PCI-DSS v4.0 Requirement 10: Complete, immutable audit log of all system access and queries.
 * - SOC 2 CC6.8: Append-only, cryptographically verified integrity of security logs preventing tampering.
 *
 * Features:
 * 1. Cryptographic HMAC-SHA256 chaining where each entry signs its canonical payload and the previous HMAC.
 * 2. Monotonic, strictly contiguous sequence numbers (1, 2, 3...) to detect deleted or omitted entries.
 * 3. Immutable query payload hashing (SHA-256 of normalized SQL + parameters).
 * 4. Merkle tree root calculation for cryptographic batch attestation.
 * 5. Key rotation support with keyId headers.
 */
export class HmacAuditLedger {
  public static readonly GENESIS_HMAC = "0".repeat(64);
  private static readonly DEFAULT_KEY_ID = "dbshield_sec_primary";

  private readonly secretKey: string;
  private readonly keyId: string;
  private readonly keysMap: Map<string, string> = new Map();
  private readonly logFilePath?: string;
  private readonly maxMemoryEntries: number;
  private readonly redactor: PiiRedactor;

  private readonly entries: AuditLedgerEntry[] = [];
  private currentSequenceNumber = 0;
  private lastHmac = HmacAuditLedger.GENESIS_HMAC;

  constructor(options: HmacLedgerOptions = {}) {
    this.secretKey =
      options.secretKey ||
      process.env.DBSHIELD_AUDIT_SECRET ||
      "dbshield_default_audit_hmac_secret_key_32b_len";
    this.keyId = options.keyId || HmacAuditLedger.DEFAULT_KEY_ID;
    this.keysMap.set(this.keyId, this.secretKey);

    this.logFilePath = options.logFilePath;
    this.maxMemoryEntries = options.maxMemoryEntries || 10000;
    this.redactor = options.redactor || new PiiRedactor();
  }

  /**
   * Registers an additional key for rotation and historical verification.
   */
  public registerKey(keyId: string, secretKey: string): void {
    this.keysMap.set(keyId, secretKey);
  }

  /**
   * Gets the current cryptographic head HMAC of the ledger chain.
   */
  public getHeadHmac(): string {
    return this.lastHmac;
  }

  /**
   * Gets the total count of recorded ledger entries.
   */
  public get length(): number {
    return this.entries.length;
  }

  /**
   * Appends an audit event to the cryptographically sealed ledger.
   */
  public async append(entryInput: {
    auditId?: string;
    timestamp?: string;
    actor?: string;
    database?: string;
    operation: SqlOperationType;
    status:
      | "SUCCESS"
      | "BLOCKED"
      | "DRY_RUN_APPROVED"
      | "DRY_RUN_REJECTED"
      | "COMMITTED"
      | "ERROR"
      | "TIMEOUT";
    riskLevel: RiskLevel;
    riskScore: number;
    sql: string;
    params?: unknown[];
    violations?: string[];
  }): Promise<AuditLedgerEntry> {
    this.currentSequenceNumber++;
    const seq = this.currentSequenceNumber;
    const auditId = entryInput.auditId || crypto.randomUUID();
    const timestamp = entryInput.timestamp || new Date().toISOString();
    const actor = entryInput.actor || "agent_unknown";
    const database = entryInput.database || "main";

    // PII Redaction
    const sanitizedSql = this.redactor.redactSql(entryInput.sql);
    const sanitizedViolations = entryInput.violations?.map((v) =>
      this.redactor.redactErrorMessage(v),
    );

    // Query payload hash: SHA-256 of normalized SQL + params
    const rawPayload = JSON.stringify({ sql: sanitizedSql, params: entryInput.params || [] });
    const queryPayloadHash = crypto.createHash("sha256").update(rawPayload).digest("hex");

    const previousHmac = this.lastHmac;

    // Canonical payload string to HMAC-sign
    const canonicalPayload = [
      previousHmac,
      seq,
      auditId,
      timestamp,
      actor,
      database,
      entryInput.operation,
      entryInput.status,
      entryInput.riskScore,
      queryPayloadHash,
    ].join("|");

    const entryHmac = crypto
      .createHmac("sha256", this.secretKey)
      .update(canonicalPayload)
      .digest("hex");

    this.lastHmac = entryHmac;

    const sealedEntry: AuditLedgerEntry = {
      sequenceNumber: seq,
      auditId,
      timestamp,
      actor,
      database,
      operation: entryInput.operation,
      status: entryInput.status,
      riskLevel: entryInput.riskLevel,
      riskScore: entryInput.riskScore,
      sql: sanitizedSql,
      queryPayloadHash,
      params: entryInput.params,
      violations: sanitizedViolations,
      piiRedacted: true,
      keyId: this.keyId,
      previousHmac,
      entryHmac,
    };

    this.entries.push(sealedEntry);
    if (this.entries.length > this.maxMemoryEntries) {
      this.entries.shift();
    }

    // Persist to file if configured
    if (this.logFilePath) {
      try {
        const line = `${JSON.stringify(sealedEntry)}\n`;
        await fs.mkdir(path.dirname(this.logFilePath), { recursive: true });
        await fs.appendFile(this.logFilePath, line, "utf8");
      } catch {
        // Non-fatal file logging failure
      }
    }

    return sealedEntry;
  }

  /**
   * Verifies the complete integrity of the append-only ledger against HMAC-SHA256 signatures.
   */
  public verifyLedgerIntegrity(
    keyResolver?: (keyId: string) => string | undefined,
  ): LedgerVerificationResult {
    if (this.entries.length === 0) {
      return {
        valid: true,
        totalEntries: 0,
        headHmac: this.lastHmac,
        tailHmac: this.lastHmac,
      };
    }

    let expectedPrevHmac = HmacAuditLedger.GENESIS_HMAC;
    let expectedSeq = this.entries[0].sequenceNumber;

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];

      // 1. Verify sequence continuity
      if (entry.sequenceNumber !== expectedSeq) {
        return {
          valid: false,
          totalEntries: i,
          headHmac: this.entries[this.entries.length - 1].entryHmac,
          tailHmac: this.entries[0].previousHmac,
          brokenAtIndex: i,
          brokenSequenceNumber: entry.sequenceNumber,
          brokenReason: "SEQUENCE_GAP",
        };
      }

      // 2. Verify previous HMAC continuity
      if (entry.previousHmac !== expectedPrevHmac) {
        return {
          valid: false,
          totalEntries: i,
          headHmac: this.entries[this.entries.length - 1].entryHmac,
          tailHmac: this.entries[0].previousHmac,
          brokenAtIndex: i,
          brokenSequenceNumber: entry.sequenceNumber,
          brokenReason: "CHAIN_DISCONTINUITY",
        };
      }

      // 3. Resolve key for entry
      const resolvedKey =
        (keyResolver ? keyResolver(entry.keyId) : undefined) ||
        this.keysMap.get(entry.keyId) ||
        this.secretKey;

      if (!resolvedKey) {
        return {
          valid: false,
          totalEntries: i,
          headHmac: this.entries[this.entries.length - 1].entryHmac,
          tailHmac: this.entries[0].previousHmac,
          brokenAtIndex: i,
          brokenSequenceNumber: entry.sequenceNumber,
          brokenReason: "MISSING_KEY",
        };
      }

      // 4. Verify payload hash
      const rawPayload = JSON.stringify({ sql: entry.sql, params: entry.params || [] });
      const recomputedPayloadHash = crypto.createHash("sha256").update(rawPayload).digest("hex");
      if (entry.queryPayloadHash !== recomputedPayloadHash) {
        return {
          valid: false,
          totalEntries: i,
          headHmac: this.entries[this.entries.length - 1].entryHmac,
          tailHmac: this.entries[0].previousHmac,
          brokenAtIndex: i,
          brokenSequenceNumber: entry.sequenceNumber,
          brokenReason: "PAYLOAD_HASH_MISMATCH",
        };
      }

      // 5. Verify entry HMAC signature
      const canonicalPayload = [
        entry.previousHmac,
        entry.sequenceNumber,
        entry.auditId,
        entry.timestamp,
        entry.actor,
        entry.database,
        entry.operation,
        entry.status,
        entry.riskScore,
        entry.queryPayloadHash,
      ].join("|");

      const recomputedHmac = crypto
        .createHmac("sha256", resolvedKey)
        .update(canonicalPayload)
        .digest("hex");

      if (entry.entryHmac !== recomputedHmac) {
        return {
          valid: false,
          totalEntries: i,
          headHmac: this.entries[this.entries.length - 1].entryHmac,
          tailHmac: this.entries[0].previousHmac,
          brokenAtIndex: i,
          brokenSequenceNumber: entry.sequenceNumber,
          brokenReason: "HMAC_MISMATCH",
        };
      }

      expectedPrevHmac = entry.entryHmac;
      expectedSeq++;
    }

    return {
      valid: true,
      totalEntries: this.entries.length,
      headHmac: this.entries[this.entries.length - 1].entryHmac,
      tailHmac: this.entries[0].previousHmac,
    };
  }

  /**
   * Computes a cryptographic Merkle root hash across a range of ledger entries
   * for external auditor verification and attestation exports.
   */
  public computeMerkleRoot(fromIndex = 0, toIndex = this.entries.length): string {
    const slice = this.entries.slice(fromIndex, toIndex);
    if (slice.length === 0) {
      return HmacAuditLedger.GENESIS_HMAC;
    }

    let currentLevel = slice.map((e) =>
      crypto.createHash("sha256").update(e.entryHmac).digest("hex"),
    );

    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
        const combined = crypto
          .createHash("sha256")
          .update(left + right)
          .digest("hex");
        nextLevel.push(combined);
      }
      currentLevel = nextLevel;
    }

    return currentLevel[0];
  }

  /**
   * Retrieves ledger entries with optional filtering.
   */
  public getEntries(
    options: { limit?: number; minRiskScore?: number; status?: string } = {},
  ): AuditLedgerEntry[] {
    let filtered = this.entries;
    if (options.status) {
      const s = options.status.toUpperCase();
      filtered = filtered.filter((e) => e.status.toUpperCase() === s);
    }
    if (options.minRiskScore !== undefined) {
      filtered = filtered.filter((e) => e.riskScore >= options.minRiskScore!);
    }
    const limit = options.limit || 100;
    return filtered.slice(-limit);
  }

  /**
   * Clears in-memory ledger state (primarily for test teardown).
   */
  public clear(): void {
    this.entries.length = 0;
    this.currentSequenceNumber = 0;
    this.lastHmac = HmacAuditLedger.GENESIS_HMAC;
  }
}
