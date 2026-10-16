import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { stripSqlComments } from "../guard/ast.js";

export interface TokenContext {
  databaseIdentity?: string;
  safetyTier?: string;
}

export interface CommitTokenPayload {
  tokenId: string;
  operationHash: string;
  sqlHash: string;
  paramsHash: string;
  affectedRows: number;
  issuedAt: number;
  expiresAt: number;
  targetTables: string[];
  databaseIdentity?: string;
  safetyTier?: string;
}

export interface VerificationResult {
  valid: boolean;
  error?:
    | "TOKEN_NOT_FOUND"
    | "TOKEN_EXPIRED"
    | "TOKEN_ALREADY_USED"
    | "QUERY_TAMPERED"
    | "PARAMS_MISMATCH";
  payload?: CommitTokenPayload;
}

export class CommitTokenManager {
  private readonly secret: string;
  private readonly ttlMs: number;
  private readonly activeTokens = new Map<string, CommitTokenPayload>();
  private readonly consumedTokens = new Map<string, number>(); // tokenId -> expiresAt

  constructor(secret?: string, ttlSeconds = 60) {
    this.secret = secret || randomBytes(32).toString("hex");
    this.ttlMs = ttlSeconds * 1000;
  }

  /**
   * Deterministically hashes the SQL query text preserving string literal contents and internal whitespace.
   * Strips outer comments so trivial comment differences do not falsely invalidate authorized mutations.
   */
  public static hashQuery(sql: string): string {
    const cleanSql = stripSqlComments(sql.trim());
    return createHmac("sha256", "dbshield-sql-salt").update(cleanSql).digest("hex");
  }

  /**
   * Deterministically hashes typed query parameters to prevent bound parameter tampering.
   */
  public static hashParams(params: unknown[] = []): string {
    const serialized = JSON.stringify(params ?? []);
    return createHmac("sha256", "dbshield-params-salt").update(serialized).digest("hex");
  }

  /**
   * Generates a compound operation hash binding the SQL, parameter values, database identity, and policy tier.
   */
  public static hashOperation(sql: string, params: unknown[] = [], context?: TokenContext): string {
    const sqlHash = CommitTokenManager.hashQuery(sql);
    const paramsHash = CommitTokenManager.hashParams(params);
    const dbId = context?.databaseIdentity || "default";
    const tier = context?.safetyTier || "BALANCED";

    return createHmac("sha256", "dbshield-operation-salt")
      .update(`${sqlHash}:${paramsHash}:${dbId}:${tier}`)
      .digest("hex");
  }

  public issueToken(
    sql: string,
    affectedRows: number,
    targetTables: string[],
    params: unknown[] = [],
    context?: TokenContext,
  ): {
    token: string;
    expiresAt: string;
    expiresInSeconds: number;
  } {
    this.cleanupExpired();

    const tokenId = `dbs_${randomUUID().replace(/-/g, "")}`;
    const now = Date.now();
    const expiresAtMs = now + this.ttlMs;

    const sqlHash = CommitTokenManager.hashQuery(sql);
    const paramsHash = CommitTokenManager.hashParams(params);
    const operationHash = CommitTokenManager.hashOperation(sql, params, context);

    const payload: CommitTokenPayload = {
      tokenId,
      operationHash,
      sqlHash,
      paramsHash,
      affectedRows,
      issuedAt: now,
      expiresAt: expiresAtMs,
      targetTables,
      databaseIdentity: context?.databaseIdentity,
      safetyTier: context?.safetyTier,
    };

    const signature = this.signPayload(payload);
    const token = `${tokenId}.${signature}`;

    this.activeTokens.set(tokenId, payload);

    return {
      token,
      expiresAt: new Date(expiresAtMs).toISOString(),
      expiresInSeconds: Math.round(this.ttlMs / 1000),
    };
  }

  public verifyAndConsume(
    token: string,
    sql: string,
    params: unknown[] = [],
    context?: TokenContext,
  ): VerificationResult {
    const parts = token.split(".");
    if (parts.length !== 2) {
      return { valid: false, error: "TOKEN_NOT_FOUND" };
    }

    const [tokenId, signature] = parts;

    // Check if token was already consumed
    if (this.consumedTokens.has(tokenId)) {
      return { valid: false, error: "TOKEN_ALREADY_USED" };
    }

    const payload = this.activeTokens.get(tokenId);

    if (!payload) {
      return { valid: false, error: "TOKEN_NOT_FOUND" };
    }

    // Check expiration before signature verification
    if (Date.now() > payload.expiresAt) {
      return { valid: false, error: "TOKEN_EXPIRED" };
    }

    // Verify cryptographic signature
    const expectedSig = this.signPayload(payload);
    if (signature !== expectedSig) {
      return { valid: false, error: "TOKEN_NOT_FOUND" };
    }

    // Verify SQL query hash strictly matches (tamper-proofing)
    const currentSqlHash = CommitTokenManager.hashQuery(sql);
    if (currentSqlHash !== payload.sqlHash) {
      return { valid: false, error: "QUERY_TAMPERED" };
    }

    // Verify parameters hash strictly matches
    const currentParamsHash = CommitTokenManager.hashParams(params);
    if (currentParamsHash !== payload.paramsHash) {
      return { valid: false, error: "PARAMS_MISMATCH" };
    }

    // Verify compound operation hash (including database identity and policy tier)
    const currentOpHash = CommitTokenManager.hashOperation(sql, params, {
      databaseIdentity: payload.databaseIdentity ?? context?.databaseIdentity,
      safetyTier: payload.safetyTier ?? context?.safetyTier,
    });
    if (currentOpHash !== payload.operationHash) {
      return { valid: false, error: "QUERY_TAMPERED" };
    }

    // Mark token as consumed immediately
    this.activeTokens.delete(tokenId);
    this.consumedTokens.set(tokenId, payload.expiresAt);

    return {
      valid: true,
      payload,
    };
  }

  private signPayload(payload: CommitTokenPayload): string {
    const data = `${payload.tokenId}:${payload.operationHash}:${payload.affectedRows}:${payload.expiresAt}`;
    return createHmac("sha256", this.secret).update(data).digest("hex").slice(0, 32);
  }

  private cleanupExpired(): void {
    const now = Date.now();
    // Keep a 5-minute tombstone grace period so expired or used tokens return clear errors
    const tombstoneLimit = 5 * 60 * 1000;

    for (const [id, payload] of this.activeTokens.entries()) {
      if (now > payload.expiresAt + tombstoneLimit) {
        this.activeTokens.delete(id);
      }
    }

    for (const [id, expiresAt] of this.consumedTokens.entries()) {
      if (now > expiresAt + tombstoneLimit) {
        this.consumedTokens.delete(id);
      }
    }
  }
}
