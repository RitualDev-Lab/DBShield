import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import type { DBShieldConfig, SafetyTier } from "../types/index.js";

export const ConfigSchema = z.object({
  dialect: z.enum(["sqlite", "postgres", "mysql"]).default("sqlite"),
  connectionString: z.string().optional(),
  storagePath: z.string().optional().default("./dbshield.sqlite"),
  safetyTier: z.enum(["STRICT", "BALANCED", "PERMISSIVE"]).default("BALANCED"),
  maxRowsPerMutation: z.number().int().positive().default(50),
  warnRowsPerMutation: z.number().int().positive().optional().default(10),
  maxRowsPerRead: z.number().int().positive().default(500),
  allowDestructiveDDL: z.boolean().default(false),
  enablePiiMasking: z.boolean().default(true),
  customPiiColumns: z.array(z.string()).default([]),
  auditLogPath: z.string().optional(),
});

export const DEFAULT_CONFIG: DBShieldConfig = {
  dialect: "sqlite",
  storagePath: "./dbshield.sqlite",
  safetyTier: "BALANCED",
  maxRowsPerMutation: 50,
  warnRowsPerMutation: 10,
  maxRowsPerRead: 500,
  allowDestructiveDDL: false,
  enablePiiMasking: true,
  customPiiColumns: [],
};

export async function loadConfig(configPath?: string): Promise<DBShieldConfig> {
  let fileConfig: Record<string, unknown> = {};

  const targetPath = configPath || path.resolve(process.cwd(), "dbshield.config.json");
  try {
    const raw = await fs.readFile(targetPath, "utf8");
    fileConfig = JSON.parse(raw);
  } catch {
    // Configuration file not found, fallback to env & defaults
  }

  // Environment variable overrides
  const envConfig: Record<string, unknown> = {};
  if (process.env.DBSHIELD_DIALECT) {
    envConfig.dialect = process.env.DBSHIELD_DIALECT;
  }
  if (process.env.DBSHIELD_STORAGE_PATH) {
    envConfig.storagePath = process.env.DBSHIELD_STORAGE_PATH;
  }
  if (process.env.DATABASE_URL) {
    envConfig.connectionString = process.env.DATABASE_URL;
  }
  if (process.env.DBSHIELD_SAFETY_TIER) {
    envConfig.safetyTier = process.env.DBSHIELD_SAFETY_TIER;
  }
  if (process.env.DBSHIELD_MAX_MUTATION_ROWS) {
    envConfig.maxRowsPerMutation = Number.parseInt(process.env.DBSHIELD_MAX_MUTATION_ROWS, 10);
  }
  if (process.env.DBSHIELD_MAX_READ_ROWS) {
    envConfig.maxRowsPerRead = Number.parseInt(process.env.DBSHIELD_MAX_READ_ROWS, 10);
  }
  if (process.env.DBSHIELD_ALLOW_DESTRUCTIVE_DDL) {
    envConfig.allowDestructiveDDL = process.env.DBSHIELD_ALLOW_DESTRUCTIVE_DDL === "true";
  }
  if (process.env.DBSHIELD_ENABLE_PII_MASKING) {
    envConfig.enablePiiMasking = process.env.DBSHIELD_ENABLE_PII_MASKING !== "false";
  }

  const merged = {
    ...DEFAULT_CONFIG,
    ...fileConfig,
    ...envConfig,
  };

  // Adjust maxRowsPerMutation if default tier is strictly applied and not custom set
  if (!fileConfig.maxRowsPerMutation && !envConfig.maxRowsPerMutation) {
    if (merged.safetyTier === "STRICT") {
      merged.maxRowsPerMutation = 1;
    } else if (merged.safetyTier === "PERMISSIVE") {
      merged.maxRowsPerMutation = 500;
    }
  }

  // Adjust maxRowsPerRead if default tier is strictly applied and not custom set
  if (!fileConfig.maxRowsPerRead && !envConfig.maxRowsPerRead) {
    if (merged.safetyTier === "STRICT") {
      merged.maxRowsPerRead = 100;
    } else if (merged.safetyTier === "PERMISSIVE") {
      merged.maxRowsPerRead = 2000;
    }
  }

  return ConfigSchema.parse(merged) as DBShieldConfig;
}
