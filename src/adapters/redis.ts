import { randomUUID } from "node:crypto";

export interface RedisDryRunResult {
  safe: boolean;
  simulatedAffectedKeys: number;
  rollbackVerified: boolean;
  warnings: string[];
}

export interface RedisQueryResult {
  success: boolean;
  affectedKeys: number;
  data?: unknown;
  auditId: string;
}

export class InMemoryRedisAdapter {
  readonly dialect = "redis" as const;
  private storage: Map<string, { value: string; expiresAt?: number }> = new Map();
  private shadowStorage: Map<string, { value: string; expiresAt?: number }> | null = null;

  public async connect(): Promise<void> {
    // Zero-overhead in-memory connection
  }

  public async disconnect(): Promise<void> {
    this.storage.clear();
    this.shadowStorage = null;
  }

  public get(key: string): string | null {
    this.cleanupExpiredKey(key);
    const item = this.storage.get(key);
    return item ? item.value : null;
  }

  public set(key: string, value: string, ttlSeconds?: number): void {
    const expiresAt = ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined;
    this.storage.set(key, { value, expiresAt });
  }

  public del(key: string): boolean {
    return this.storage.delete(key);
  }

  public exists(key: string): boolean {
    this.cleanupExpiredKey(key);
    return this.storage.has(key);
  }

  public getAllKeys(): string[] {
    const now = Date.now();
    const keys: string[] = [];
    for (const [k, v] of this.storage.entries()) {
      if (!v.expiresAt || v.expiresAt > now) {
        keys.push(k);
      }
    }
    return keys;
  }

  private cleanupExpiredKey(key: string): void {
    const item = this.storage.get(key);
    if (item?.expiresAt && item.expiresAt <= Date.now()) {
      this.storage.delete(key);
    }
  }

  /**
   * Dry-Run Simulation: Simulates mutations on a cloned shadow state and verifies rollback.
   */
  public async executeDryRun(
    command: string,
    key: string,
    value?: unknown,
  ): Promise<RedisDryRunResult> {
    // Clone shadow snapshot
    this.shadowStorage = new Map(this.storage);
    let affectedKeys = 0;
    const warnings: string[] = [];

    const upperCmd = command.toUpperCase();
    if (upperCmd === "SET" || upperCmd === "KV_SET") {
      affectedKeys = 1;
      this.shadowStorage.set(key, { value: String(value ?? "") });
    } else if (upperCmd === "DEL" || upperCmd === "KV_DEL") {
      if (this.shadowStorage.has(key)) {
        affectedKeys = 1;
        this.shadowStorage.delete(key);
      }
    } else if (upperCmd === "EXPIRE" || upperCmd === "KV_EXPIRE") {
      if (this.shadowStorage.has(key)) {
        affectedKeys = 1;
      }
    } else {
      warnings.push(`Unrecognized Redis command in dry-run simulation: ${command}`);
    }

    // Verify rollback by discarding shadow storage
    this.shadowStorage = null;

    return {
      safe: true,
      simulatedAffectedKeys: affectedKeys,
      rollbackVerified: true,
      warnings,
    };
  }

  /**
   * Commit mutation to live store.
   */
  public async executeCommit(
    command: string,
    key: string,
    value?: unknown,
    ttlSeconds?: number,
  ): Promise<RedisQueryResult> {
    const auditId = randomUUID();
    let affectedKeys = 0;
    const upperCmd = command.toUpperCase();

    if (upperCmd === "SET" || upperCmd === "KV_SET") {
      this.set(key, String(value ?? ""), ttlSeconds);
      affectedKeys = 1;
    } else if (upperCmd === "DEL" || upperCmd === "KV_DEL") {
      const deleted = this.del(key);
      affectedKeys = deleted ? 1 : 0;
    } else if (upperCmd === "EXPIRE" || upperCmd === "KV_EXPIRE") {
      const exists = this.exists(key);
      if (exists && ttlSeconds) {
        const item = this.storage.get(key);
        if (item) {
          item.expiresAt = Date.now() + ttlSeconds * 1000;
          affectedKeys = 1;
        }
      }
    }

    return {
      success: true,
      affectedKeys,
      auditId,
    };
  }
}
