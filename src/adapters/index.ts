import type { DBShieldConfig, DatabaseAdapter } from "../types/index.js";
import { PostgresAdapter } from "./postgres.js";
import { SqliteAdapter } from "./sqlite.js";

export * from "./sqlite.js";
export * from "./postgres.js";

export function createDatabaseAdapter(config: DBShieldConfig): DatabaseAdapter {
  switch (config.dialect) {
    case "sqlite":
      return new SqliteAdapter(
        config.storagePath || ":memory:",
        config.maxRowsPerRead,
        config.maxRowsPerMutation,
        config.statementTimeoutMs,
      );
    case "postgres":
      return new PostgresAdapter(
        config.connectionString || process.env.DATABASE_URL || "postgres://localhost:5432/postgres",
        config.maxRowsPerRead,
        config.maxRowsPerMutation,
        config.statementTimeoutMs,
      );
    case "mysql":
      // Fallback or upcoming driver adapter
      throw new Error(
        `Dialect 'mysql' driver will be enabled in upcoming multi-dialect packaging. Native PostgreSQL and SQLite adapters are active.`,
      );
    default: {
      const unsupported = (config as { dialect: string }).dialect;
      throw new Error(`Unsupported database dialect: ${unsupported}`);
    }
  }
}
