import type { SqlGuardEngine } from "../guard/engine.js";
import type { DBShieldConfig, DatabaseAdapter, DryRunResult, QueryResult } from "../types/index.js";
import { CommitTokenManager } from "./tokens.js";

export class SandboxEngine {
  private readonly adapter: DatabaseAdapter;
  private readonly guard: SqlGuardEngine;
  private readonly config: DBShieldConfig;
  private readonly tokenManager: CommitTokenManager;

  constructor(
    adapter: DatabaseAdapter,
    guard: SqlGuardEngine,
    config: DBShieldConfig,
    tokenManager?: CommitTokenManager,
  ) {
    this.adapter = adapter;
    this.guard = guard;
    this.config = config;
    this.tokenManager = tokenManager || new CommitTokenManager();
  }

  public getTokenManager(): CommitTokenManager {
    return this.tokenManager;
  }

  public async dryRun(sql: string, params: unknown[] = []): Promise<DryRunResult> {
    const evaluation = this.guard.evaluate(sql);

    // If AST guardrail outright blocks the query (unconstrained delete, tautology, DROP)
    if (!evaluation.allowed && evaluation.riskLevel === "CRITICAL") {
      return {
        safe: false,
        simulatedAffectedRows: 0,
        targetTables: evaluation.targetTables,
        executionTimeMs: 0,
        warnings: evaluation.violations.map((v) => `[${v.code}] ${v.message}`),
        rollbackVerified: false,
      };
    }

    const adapterResult = await this.adapter.executeDryRun(sql, params);

    if (!adapterResult.safe) {
      return adapterResult;
    }

    const affectedRows = adapterResult.simulatedAffectedRows;
    const warnings = [...adapterResult.warnings, ...evaluation.warnings];

    // Blast Radius Limit Checking
    if (affectedRows > this.config.maxRowsPerMutation) {
      const blastWarning = `Simulated row impact (${affectedRows} rows) exceeds maximum threshold (${this.config.maxRowsPerMutation} rows).`;
      if (this.config.safetyTier === "STRICT") {
        return {
          safe: false,
          simulatedAffectedRows: affectedRows,
          targetTables: evaluation.targetTables,
          executionTimeMs: adapterResult.executionTimeMs,
          warnings: [
            ...warnings,
            `[EXCESSIVE_BLAST_RADIUS] ${blastWarning} Blocked under STRICT safety tier.`,
          ],
          rollbackVerified: adapterResult.rollbackVerified,
        };
      }
      warnings.push(`[BLAST_RADIUS_WARNING] ${blastWarning}`);
    }

    // Issue single-use commit authorization token
    const tokenInfo = this.tokenManager.issueToken(sql, affectedRows, evaluation.targetTables);

    return {
      safe: true,
      simulatedAffectedRows: affectedRows,
      targetTables: evaluation.targetTables,
      executionTimeMs: adapterResult.executionTimeMs,
      commitToken: tokenInfo.token,
      expiresAt: tokenInfo.expiresAt,
      warnings,
      rollbackVerified: adapterResult.rollbackVerified,
    };
  }

  public async commit(token: string, sql: string, params: unknown[] = []): Promise<QueryResult> {
    const verification = this.tokenManager.verifyAndConsume(token, sql);

    if (!verification.valid) {
      switch (verification.error) {
        case "TOKEN_NOT_FOUND":
          throw new Error(
            "Authorization token not found or invalid. Please execute 'db_dry_run' first to generate a token.",
          );
        case "TOKEN_EXPIRED":
          throw new Error(
            "Authorization token has expired (TTL is 60s). Please run 'db_dry_run' again to obtain a fresh token.",
          );
        case "TOKEN_ALREADY_USED":
          throw new Error(
            "Security alert: Authorization token has already been consumed (single-use replay prevention).",
          );
        case "QUERY_TAMPERED":
          throw new Error(
            "Security violation: The SQL query does not match the exact query authorized during dry-run simulation.",
          );
        default:
          throw new Error("Authorization token verification failed.");
      }
    }

    // Execute atomic commit
    return await this.adapter.executeCommit(sql, params);
  }
}
