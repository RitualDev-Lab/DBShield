import type { DBShieldConfig, DatabaseAdapter } from "../types/index.js";
import { SqliteAdapter } from "./sqlite.js";

export * from "./sqlite.js";

export function createDatabaseAdapter(config: DBShieldConfig): DatabaseAdapter {
  switch (config.dialect) {
    case "sqlite":
      return new SqliteAdapter(config.storagePath || ":memory:", config.maxRowsPerRead);
    case "postgres":
    case "mysql":
      // Fallback or external driver adapter
      throw new Error(
        `Dialect '${config.dialect}' driver will be enabled in multi-dialect packaging. Currently SQLite zero-config adapter is active.`,
      );
    default: {
      const unsupported = (config as { dialect: string }).dialect;
      throw new Error(`Unsupported database dialect: ${unsupported}`);
    }
  }
}
