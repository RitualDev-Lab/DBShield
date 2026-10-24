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
  enableCostGate: z.boolean().default(true),
  maxEstimatedCost: z.number().int().positive().default(50000),
  warnEstimatedCost: z.number().int().positive().optional().default(10000),
  maxEstimatedRows: z.number().int().positive().default(100000),
  warnEstimatedRows: z.number().int().positive().optional().default(20000),
  blockUnindexedSeqScan: z.boolean().default(false),
  statementTimeoutMs: z.number().int().positive().default(5000),
  enableMigrationGate: z.boolean().default(true),
  enforceConcurrentIndexCreation: z.boolean().default(false),
  disallowBreakingRenames: z.boolean().default(true),
  enableSemanticGuard: z.boolean().default(true),
  customSensitiveColumns: z.array(z.string()).default([]),
  requireIntentForSensitiveColumns: z.boolean().default(false),
  proxyPort: z.number().int().positive().default(5433),
  proxyHost: z.string().default("127.0.0.1"),
  upstreamHost: z.string().default("127.0.0.1"),
  upstreamPort: z.number().int().positive().default(5432),
  metricsPort: z.number().int().positive().default(9090),
  metricsHost: z.string().default("0.0.0.0"),
  enableMetrics: z.boolean().default(true),
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
  enableCostGate: true,
  maxEstimatedCost: 50000,
  warnEstimatedCost: 10000,
  maxEstimatedRows: 100000,
  warnEstimatedRows: 20000,
  blockUnindexedSeqScan: false,
  statementTimeoutMs: 5000,
  enableMigrationGate: true,
  enforceConcurrentIndexCreation: false,
  disallowBreakingRenames: true,
  enableSemanticGuard: true,
  customSensitiveColumns: [],
  requireIntentForSensitiveColumns: false,
  proxyPort: 5433,
  proxyHost: "127.0.0.1",
  upstreamHost: "127.0.0.1",
  upstreamPort: 5432,
  metricsPort: 9090,
  metricsHost: "0.0.0.0",
  enableMetrics: true,
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
  if (process.env.DBSHIELD_ENABLE_COST_GATE) {
    envConfig.enableCostGate = process.env.DBSHIELD_ENABLE_COST_GATE !== "false";
  }
  if (process.env.DBSHIELD_MAX_ESTIMATED_COST) {
    envConfig.maxEstimatedCost = Number.parseInt(process.env.DBSHIELD_MAX_ESTIMATED_COST, 10);
  }
  if (process.env.DBSHIELD_WARN_ESTIMATED_COST) {
    envConfig.warnEstimatedCost = Number.parseInt(process.env.DBSHIELD_WARN_ESTIMATED_COST, 10);
  }
  if (process.env.DBSHIELD_MAX_ESTIMATED_ROWS) {
    envConfig.maxEstimatedRows = Number.parseInt(process.env.DBSHIELD_MAX_ESTIMATED_ROWS, 10);
  }
  if (process.env.DBSHIELD_WARN_ESTIMATED_ROWS) {
    envConfig.warnEstimatedRows = Number.parseInt(process.env.DBSHIELD_WARN_ESTIMATED_ROWS, 10);
  }
  if (process.env.DBSHIELD_BLOCK_UNINDEXED_SEQ_SCAN) {
    envConfig.blockUnindexedSeqScan = process.env.DBSHIELD_BLOCK_UNINDEXED_SEQ_SCAN === "true";
  }
  if (process.env.DBSHIELD_STATEMENT_TIMEOUT_MS) {
    envConfig.statementTimeoutMs = Number.parseInt(process.env.DBSHIELD_STATEMENT_TIMEOUT_MS, 10);
  }
  if (process.env.DBSHIELD_ENABLE_MIGRATION_GATE) {
    envConfig.enableMigrationGate = process.env.DBSHIELD_ENABLE_MIGRATION_GATE !== "false";
  }
  if (process.env.DBSHIELD_ENFORCE_CONCURRENT_INDEX) {
    envConfig.enforceConcurrentIndexCreation =
      process.env.DBSHIELD_ENFORCE_CONCURRENT_INDEX === "true";
  }
  if (process.env.DBSHIELD_DISALLOW_BREAKING_RENAMES) {
    envConfig.disallowBreakingRenames = process.env.DBSHIELD_DISALLOW_BREAKING_RENAMES !== "false";
  }
  if (process.env.DBSHIELD_ENABLE_SEMANTIC_GUARD) {
    envConfig.enableSemanticGuard = process.env.DBSHIELD_ENABLE_SEMANTIC_GUARD !== "false";
  }
  if (process.env.DBSHIELD_REQUIRE_INTENT_FOR_SENSITIVE) {
    envConfig.requireIntentForSensitiveColumns =
      process.env.DBSHIELD_REQUIRE_INTENT_FOR_SENSITIVE === "true";
  }
  if (process.env.DBSHIELD_PROXY_PORT) {
    envConfig.proxyPort = Number.parseInt(process.env.DBSHIELD_PROXY_PORT, 10);
  }
  if (process.env.DBSHIELD_PROXY_HOST) {
    envConfig.proxyHost = process.env.DBSHIELD_PROXY_HOST;
  }
  if (process.env.DBSHIELD_UPSTREAM_HOST) {
    envConfig.upstreamHost = process.env.DBSHIELD_UPSTREAM_HOST;
  }
  if (process.env.DBSHIELD_UPSTREAM_PORT) {
    envConfig.upstreamPort = Number.parseInt(process.env.DBSHIELD_UPSTREAM_PORT, 10);
  }
  if (process.env.DBSHIELD_METRICS_PORT) {
    envConfig.metricsPort = Number.parseInt(process.env.DBSHIELD_METRICS_PORT, 10);
  }
  if (process.env.DBSHIELD_METRICS_HOST) {
    envConfig.metricsHost = process.env.DBSHIELD_METRICS_HOST;
  }
  if (process.env.DBSHIELD_ENABLE_METRICS) {
    envConfig.enableMetrics = process.env.DBSHIELD_ENABLE_METRICS !== "false";
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

  // Adjust cost gate thresholds by safety tier if not custom set
  if (!fileConfig.maxEstimatedCost && !envConfig.maxEstimatedCost) {
    if (merged.safetyTier === "STRICT") {
      merged.maxEstimatedCost = 10000;
    } else if (merged.safetyTier === "PERMISSIVE") {
      merged.maxEstimatedCost = 200000;
    }
  }

  if (!fileConfig.maxEstimatedRows && !envConfig.maxEstimatedRows) {
    if (merged.safetyTier === "STRICT") {
      merged.maxEstimatedRows = 20000;
    } else if (merged.safetyTier === "PERMISSIVE") {
      merged.maxEstimatedRows = 500000;
    }
  }

  if (!fileConfig.blockUnindexedSeqScan && !envConfig.blockUnindexedSeqScan) {
    if (merged.safetyTier === "STRICT") {
      merged.blockUnindexedSeqScan = true;
    }
  }

  if (!fileConfig.statementTimeoutMs && !envConfig.statementTimeoutMs) {
    if (merged.safetyTier === "STRICT") {
      merged.statementTimeoutMs = 3000;
    } else if (merged.safetyTier === "PERMISSIVE") {
      merged.statementTimeoutMs = 15000;
    }
  }

  if (!fileConfig.enforceConcurrentIndexCreation && !envConfig.enforceConcurrentIndexCreation) {
    if (merged.safetyTier === "STRICT") {
      merged.enforceConcurrentIndexCreation = true;
    }
  }

  if (!fileConfig.disallowBreakingRenames && !envConfig.disallowBreakingRenames) {
    if (merged.safetyTier === "PERMISSIVE") {
      merged.disallowBreakingRenames = false;
    }
  }

  if (
    fileConfig.requireIntentForSensitiveColumns === undefined &&
    envConfig.requireIntentForSensitiveColumns === undefined
  ) {
    if (merged.safetyTier === "STRICT") {
      merged.requireIntentForSensitiveColumns = true;
    }
  }

  return ConfigSchema.parse(merged) as DBShieldConfig;
}
