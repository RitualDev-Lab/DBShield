import { randomUUID } from "node:crypto";
import { InMemoryRedisAdapter } from "../adapters/redis.js";
import type {
  DBShieldConfig,
  DatabaseAdapter,
  DistributedCommitResult,
  DistributedDryRunResult,
  DistributedStoreDryRunResult,
  DistributedStoreOperation,
} from "../types/index.js";
import { DistributedCommitTokenManager } from "./distributed-tokens.js";

export type AnyStoreAdapter = DatabaseAdapter | InMemoryRedisAdapter;

export class DistributedSandboxEngine {
  private readonly stores: Map<string, AnyStoreAdapter> = new Map();
  private readonly config: DBShieldConfig;
  private readonly tokenManager: DistributedCommitTokenManager;

  constructor(config: DBShieldConfig, tokenManager?: DistributedCommitTokenManager) {
    this.config = config;
    this.tokenManager = tokenManager || new DistributedCommitTokenManager();
  }

  public registerStore(storeId: string, adapter: AnyStoreAdapter): void {
    this.stores.set(storeId, adapter);
  }

  public getStore(storeId: string): AnyStoreAdapter | undefined {
    return this.stores.get(storeId);
  }

  public getTokenManager(): DistributedCommitTokenManager {
    return this.tokenManager;
  }

  /**
   * Execute coordinated dry-run across multi-store environment with atomic rollback verification.
   */
  public async dryRun(operations: DistributedStoreOperation[]): Promise<DistributedDryRunResult> {
    if (!operations || operations.length === 0) {
      return {
        safe: false,
        totalAffectedEntities: 0,
        storeResults: {},
        warnings: ["No distributed operations provided for dry-run simulation."],
        rollbackVerified: true,
      };
    }

    const storeResults: Record<string, DistributedStoreDryRunResult> = {};
    let totalAffected = 0;
    let allSafe = true;
    const globalWarnings: string[] = [];

    // Simulate dry-run across all stores
    for (const op of operations) {
      const store = this.stores.get(op.storeId);
      if (!store) {
        allSafe = false;
        storeResults[op.storeId] = {
          storeId: op.storeId,
          storeType: op.storeType,
          safe: false,
          rollbackVerified: false,
          warnings: [
            `Target store '${op.storeId}' is not registered with DistributedSandboxEngine.`,
          ],
          error: `Store '${op.storeId}' not found`,
        };
        continue;
      }

      try {
        if (op.storeType === "redis" || store instanceof InMemoryRedisAdapter) {
          const redisStore = store as InMemoryRedisAdapter;
          const dryRes = await redisStore.executeDryRun(op.action, op.queryOrKey, op.paramsOrValue);
          totalAffected += dryRes.simulatedAffectedKeys;

          storeResults[op.storeId] = {
            storeId: op.storeId,
            storeType: "redis",
            safe: dryRes.safe,
            affectedKeys: dryRes.simulatedAffectedKeys,
            rollbackVerified: dryRes.rollbackVerified,
            warnings: dryRes.warnings,
          };
        } else {
          // SQL store adapter (PostgreSQL or SQLite)
          const sqlStore = store as DatabaseAdapter;
          const params = Array.isArray(op.paramsOrValue) ? op.paramsOrValue : [];
          const dryRes = await sqlStore.executeDryRun(op.queryOrKey, params);
          totalAffected += dryRes.simulatedAffectedRows;

          if (!dryRes.safe) {
            allSafe = false;
          }

          storeResults[op.storeId] = {
            storeId: op.storeId,
            storeType: op.storeType,
            safe: dryRes.safe,
            affectedRows: dryRes.simulatedAffectedRows,
            rollbackVerified: dryRes.rollbackVerified,
            warnings: dryRes.warnings,
          };
        }
      } catch (err) {
        allSafe = false;
        storeResults[op.storeId] = {
          storeId: op.storeId,
          storeType: op.storeType,
          safe: false,
          rollbackVerified: false,
          warnings: [
            `Dry-run simulation thrown on store '${op.storeId}': ${(err as Error).message}`,
          ],
          error: (err as Error).message,
        };
      }
    }

    // Blast Radius Limit Checking across distributed stores
    const maxEntities = this.config.maxRowsPerMutation || 50;
    if (totalAffected > maxEntities) {
      allSafe = false;
      globalWarnings.push(
        `[DISTRIBUTED_BLAST_RADIUS_EXCEEDED] Total simulated entities (${totalAffected}) across all stores exceeds maximum ceiling of ${maxEntities}.`,
      );
    }

    if (!allSafe) {
      return {
        safe: false,
        totalAffectedEntities: totalAffected,
        storeResults,
        warnings: globalWarnings,
        rollbackVerified: true,
      };
    }

    // Issue distributed single-use commit authorization token
    const tokenInfo = this.tokenManager.issueToken(operations, totalAffected);

    return {
      safe: true,
      distributedCommitToken: tokenInfo.token,
      expiresAt: tokenInfo.expiresAt,
      totalAffectedEntities: totalAffected,
      storeResults,
      warnings: globalWarnings,
      rollbackVerified: true,
    };
  }

  /**
   * Two-phase distributed commit across multi-store environment.
   */
  public async commit(
    token: string,
    operations: DistributedStoreOperation[],
  ): Promise<DistributedCommitResult> {
    const distributedAuditId = randomUUID();

    // Phase 1 (Verification): Cryptographically verify token and tamper-resistance
    const verification = this.tokenManager.verifyAndConsume(token, operations);
    if (!verification.valid) {
      throw new Error(`[DISTRIBUTED_COMMIT_REJECTED] Invalid commit token: ${verification.error}`);
    }

    // Phase 2 (Execution): Apply mutations to participating stores
    const storeResults: Record<
      string,
      { success: boolean; affectedRows?: number; affectedKeys?: number; error?: string }
    > = {};

    let allSuccess = true;

    for (const op of operations) {
      const store = this.stores.get(op.storeId);
      if (!store) {
        allSuccess = false;
        storeResults[op.storeId] = {
          success: false,
          error: `Store '${op.storeId}' is not connected during commit phase.`,
        };
        continue;
      }

      try {
        if (op.storeType === "redis" || store instanceof InMemoryRedisAdapter) {
          const redisStore = store as InMemoryRedisAdapter;
          const res = await redisStore.executeCommit(op.action, op.queryOrKey, op.paramsOrValue);
          storeResults[op.storeId] = {
            success: res.success,
            affectedKeys: res.affectedKeys,
          };
        } else {
          const sqlStore = store as DatabaseAdapter;
          const params = Array.isArray(op.paramsOrValue) ? op.paramsOrValue : [];
          const res = await sqlStore.executeCommit(op.queryOrKey, params);
          storeResults[op.storeId] = {
            success: true,
            affectedRows: res.rowCount,
          };
        }
      } catch (err) {
        allSuccess = false;
        storeResults[op.storeId] = {
          success: false,
          error: (err as Error).message,
        };
      }
    }

    return {
      committed: allSuccess,
      storeResults,
      distributedAuditId,
    };
  }
}
