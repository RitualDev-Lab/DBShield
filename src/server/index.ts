import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createDatabaseAdapter } from "../adapters/index.js";
import { AuditLogger } from "../audit/index.js";
import { loadConfig } from "../config/index.js";
import { CostGateEngine } from "../cost/index.js";
import { QueryExplainer } from "../explain/index.js";
import { SqlGuardEngine } from "../guard/index.js";
import { MigrationSafetyEngine } from "../migration/index.js";
import { type PiiRedactionReport, PiiRedactor } from "../pii/index.js";
import { SandboxEngine } from "../sandbox/index.js";
import type { DBShieldConfig, DatabaseAdapter } from "../types/index.js";

export interface McpServerInstance {
  server: McpServer;
  adapter: DatabaseAdapter;
  config: DBShieldConfig;
  guardEngine: SqlGuardEngine;
  sandboxEngine: SandboxEngine;
  piiRedactor: PiiRedactor;
  auditLogger: AuditLogger;
  explainer: QueryExplainer;
  costGateEngine: CostGateEngine;
  migrationEngine: MigrationSafetyEngine;
  start(): Promise<void>;
  stop(): Promise<void>;
}

export async function createMcpServer(
  customConfig?: Partial<DBShieldConfig>,
): Promise<McpServerInstance> {
  const baseConfig = await loadConfig();
  const config: DBShieldConfig = { ...baseConfig, ...customConfig };

  const adapter = createDatabaseAdapter(config);
  await adapter.connect();

  const guardEngine = new SqlGuardEngine(config);
  const sandboxEngine = new SandboxEngine(adapter, guardEngine, config);
  const piiRedactor = new PiiRedactor(config.customPiiColumns);
  const auditLogger = new AuditLogger(config.auditLogPath, 500, piiRedactor);
  const explainer = new QueryExplainer(adapter);
  const costGateEngine = new CostGateEngine(config, explainer);
  const migrationEngine = new MigrationSafetyEngine(config);

  const server = new McpServer({
    name: "dbshield",
    version: "0.1.0",
  });

  // Base ping / status tool
  server.tool(
    "db_status",
    "Check DBShield security gateway status, active safety tier, and database connection.",
    {},
    async () => {
      const schemas = await adapter.getSchema();
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: "ONLINE",
                shieldVersion: "0.1.0",
                dialect: config.dialect,
                safetyTier: config.safetyTier,
                piiMaskingEnabled: config.enablePiiMasking,
                costGateEnabled: config.enableCostGate,
                maxEstimatedCost: config.maxEstimatedCost,
                maxEstimatedRows: config.maxEstimatedRows,
                statementTimeoutMs: config.statementTimeoutMs,
                migrationGateEnabled: config.enableMigrationGate,
                enforceConcurrentIndexCreation: config.enforceConcurrentIndexCreation,
                maxRowsPerMutation: config.maxRowsPerMutation,
                maxRowsPerRead: config.maxRowsPerRead,
                allowDestructiveDDL: config.allowDestructiveDDL,
                totalTables: schemas.length,
                tables: schemas.map((s) => s.tableName),
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Schema introspection tool
  server.tool(
    "db_describe_schema",
    "Safely introspect database tables, column types, nullable flags, primary keys, and foreign key relationships.",
    {
      tableName: z
        .string()
        .optional()
        .describe("Optional specific table name to inspect. If omitted, returns all tables."),
    },
    async ({ tableName }) => {
      if (tableName) {
        const schema = await adapter.getTableSchema(tableName);
        if (!schema) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({ error: `Table '${tableName}' not found.` }),
              },
            ],
          };
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(schema, null, 2),
            },
          ],
        };
      }

      const schemas = await adapter.getSchema();
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(schemas, null, 2),
          },
        ],
      };
    },
  );

  // Safe Query Execution tool with AST Guardrail
  server.tool(
    "db_query",
    "Safely execute a SQL query through DBShield guardrails. Destructive DDL and unconstrained mutations without WHERE clauses are automatically intercepted and blocked.",
    {
      sql: z.string().describe("The SQL query to execute."),
      params: z
        .array(z.union([z.string(), z.number(), z.boolean(), z.null()]))
        .optional()
        .describe("Optional parameterized query values."),
    },
    async ({ sql, params }) => {
      const evaluation = guardEngine.evaluate(sql);

      if (!evaluation.allowed) {
        await auditLogger.log({
          auditId: randomUUID(),
          timestamp: new Date().toISOString(),
          sql,
          operation: evaluation.operation,
          status: "BLOCKED",
          riskLevel: evaluation.riskLevel,
          riskScore: evaluation.riskScore,
          violations: evaluation.violations.map((v) => v.code),
        });

        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "BLOCKED",
                  blockedBy: "DBShield AST Guardrail Engine",
                  riskLevel: evaluation.riskLevel,
                  riskScore: evaluation.riskScore,
                  operation: evaluation.operation,
                  targetTables: evaluation.targetTables,
                  violations: evaluation.violations,
                  warnings: evaluation.warnings,
                  suggestion:
                    evaluation.violations[0]?.suggestion ||
                    "Please revise your SQL statement to satisfy DBShield safety guardrails.",
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      if (evaluation.requiresDryRun) {
        await auditLogger.log({
          auditId: randomUUID(),
          timestamp: new Date().toISOString(),
          sql,
          operation: evaluation.operation,
          status: "DRY_RUN_REJECTED",
          riskLevel: evaluation.riskLevel,
          riskScore: evaluation.riskScore,
        });

        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "DRY_RUN_REQUIRED",
                  message: `Under '${config.safetyTier}' safety tier, this mutation requires a pre-flight dry run simulation before direct execution.`,
                  riskLevel: evaluation.riskLevel,
                  riskScore: evaluation.riskScore,
                  operation: evaluation.operation,
                  targetTables: evaluation.targetTables,
                  suggestion:
                    "Use the 'db_dry_run' tool to preview row impact and obtain an execution authorization token.",
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      // Phase 3: Non-Destructive Migration & DDL Lock Safety Gate
      if (
        config.enableMigrationGate &&
        (evaluation.operation.startsWith("DDL") ||
          sql.toUpperCase().includes("ALTER TABLE") ||
          sql.toUpperCase().includes("CREATE INDEX") ||
          sql.toUpperCase().includes("DROP TABLE"))
      ) {
        const migrationValidation = migrationEngine.validateMigration(sql, config.dialect);
        if (!migrationValidation.safe && !config.allowDestructiveDDL) {
          await auditLogger.log({
            auditId: randomUUID(),
            timestamp: new Date().toISOString(),
            sql,
            operation: evaluation.operation,
            status: "BLOCKED",
            riskLevel: "BLOCKED",
            riskScore: migrationValidation.riskScore,
            violations: migrationValidation.violations.map((v) => v.code),
          });

          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "BLOCKED",
                    blockedBy: "DBShield Migration Safety Gate",
                    code: "MIGRATION_SAFETY_VIOLATION",
                    riskScore: migrationValidation.riskScore,
                    highestLockLevel: migrationValidation.highestLockLevel,
                    violations: migrationValidation.violations,
                    warnings: migrationValidation.warnings,
                    safeMigrationPlan: migrationValidation.safeMigrationPlan,
                    suggestion:
                      migrationValidation.safeMigrationPlan[0] ||
                      "Destructive or lock-inducing DDL is blocked by DBShield to protect production availability.",
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }
      }

      // Phase 2: Pre-Execution Cost & Runaway Query Interception
      const costEvaluation = await costGateEngine.evaluate(sql, params);
      if (!costEvaluation.allowed) {
        await auditLogger.log({
          auditId: randomUUID(),
          timestamp: new Date().toISOString(),
          sql,
          operation: evaluation.operation,
          status: "BLOCKED",
          riskLevel: costEvaluation.riskLevel,
          riskScore: 75,
          violations: [costEvaluation.code || "EXCESSIVE_QUERY_COST"],
        });

        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "BLOCKED",
                  blockedBy: "DBShield Cost & Performance Gate",
                  code: costEvaluation.code,
                  riskLevel: costEvaluation.riskLevel,
                  operation: evaluation.operation,
                  targetTables: evaluation.targetTables,
                  estimatedCost: costEvaluation.estimatedCost,
                  maxAllowedCost: costEvaluation.maxAllowedCost,
                  estimatedRows: costEvaluation.estimatedRows,
                  maxAllowedRows: costEvaluation.maxAllowedRows,
                  bottlenecks: costEvaluation.bottlenecks,
                  suggestions: costEvaluation.suggestions,
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      try {
        const result = await adapter.query(sql, params, {
          maxRows: config.maxRowsPerRead,
          maxMutationRows: config.maxRowsPerMutation,
          timeoutMs: config.statementTimeoutMs,
        });
        let finalRows = result.rows;
        let piiReport: PiiRedactionReport | undefined;

        if (config.enablePiiMasking && finalRows.length > 0) {
          piiReport = piiRedactor.redactRows(finalRows, config.customPiiColumns);
          finalRows = piiReport.sanitizedRows;
        }

        await auditLogger.log({
          auditId: result.auditId,
          timestamp: new Date().toISOString(),
          sql,
          operation: evaluation.operation,
          status: "SUCCESS",
          riskLevel: evaluation.riskLevel,
          riskScore: evaluation.riskScore,
          rowCount: result.rowCount,
          executionTimeMs: result.executionTimeMs,
          piiRedacted: (piiReport?.totalFieldsRedacted || 0) > 0,
        });

        const combinedWarnings = [...evaluation.warnings, ...costEvaluation.warnings];

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "SUCCESS",
                  riskLevel: evaluation.riskLevel,
                  riskScore: evaluation.riskScore,
                  operation: evaluation.operation,
                  targetTables: evaluation.targetTables,
                  rowCount: result.rowCount,
                  executionTimeMs: result.executionTimeMs,
                  columns: result.columns,
                  rows: finalRows,
                  warnings: combinedWarnings.length > 0 ? combinedWarnings : undefined,
                  pagination: result.meta ?? {
                    totalReturned: result.rowCount,
                    isTruncated: false,
                    maxAllowedRows: config.maxRowsPerRead,
                  },
                  piiRedaction: config.enablePiiMasking
                    ? {
                        enabled: true,
                        redactedColumns: piiReport?.redactedColumns || [],
                        categoriesDetected: piiReport?.categoriesDetected || [],
                        totalFieldsRedacted: piiReport?.totalFieldsRedacted || 0,
                      }
                    : { enabled: false },
                  costMetrics: config.enableCostGate
                    ? {
                        estimatedCost: costEvaluation.estimatedCost,
                        estimatedRows: costEvaluation.estimatedRows,
                        isIndexed: costEvaluation.explainReport?.isIndexed ?? true,
                      }
                    : undefined,
                  auditId: result.auditId,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (err) {
        const rawMessage = (err as Error).message;
        const sanitizedMessage = piiRedactor.redactErrorMessage(rawMessage);
        const isTimeout = rawMessage.includes("[QUERY_TIMEOUT_EXCEEDED]");

        await auditLogger.log({
          auditId: randomUUID(),
          timestamp: new Date().toISOString(),
          sql,
          operation: evaluation.operation,
          status: isTimeout ? "TIMEOUT" : "ERROR",
          riskLevel: isTimeout ? "BLOCKED" : evaluation.riskLevel,
          riskScore: isTimeout ? 80 : evaluation.riskScore,
          violations: [isTimeout ? "QUERY_TIMEOUT_EXCEEDED" : sanitizedMessage],
        });

        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: isTimeout ? "TIMEOUT" : "DATABASE_ERROR",
                  error: sanitizedMessage,
                  suggestion: isTimeout
                    ? `Query execution exceeded statement timeout limit (${config.statementTimeoutMs}ms). Consider optimizing filters, indexes, or adding LIMIT.`
                    : undefined,
                },
                null,
                2,
              ),
            },
          ],
        };
      }
    },
  );

  // Dry-Run Sandbox Tool
  server.tool(
    "db_dry_run",
    "Simulate a database mutation inside an auto-rollback transaction sandbox. Calculates blast radius, affected row count, and returns a short-lived authorization token if safe.",
    {
      sql: z.string().describe("The SQL mutation (UPDATE, INSERT, DELETE) to simulate."),
      params: z
        .array(z.union([z.string(), z.number(), z.boolean(), z.null()]))
        .optional()
        .describe("Optional parameterized query values."),
    },
    async ({ sql, params }) => {
      const dryRunRes = await sandboxEngine.dryRun(sql, params);

      await auditLogger.log({
        auditId: randomUUID(),
        timestamp: new Date().toISOString(),
        sql,
        operation: "UPDATE",
        status: dryRunRes.safe ? "DRY_RUN_APPROVED" : "DRY_RUN_REJECTED",
        riskLevel: dryRunRes.safe ? "CAUTION" : "BLOCKED",
        riskScore: dryRunRes.safe ? 25 : 80,
        rowCount: dryRunRes.simulatedAffectedRows,
        executionTimeMs: dryRunRes.executionTimeMs,
        violations: dryRunRes.warnings,
      });

      if (!dryRunRes.safe) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "DRY_RUN_REJECTED",
                  safe: false,
                  simulatedAffectedRows: dryRunRes.simulatedAffectedRows,
                  targetTables: dryRunRes.targetTables,
                  warnings: dryRunRes.warnings,
                  instruction:
                    "This mutation was rejected during dry-run simulation or violated security thresholds.",
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: "DRY_RUN_APPROVED",
                safe: true,
                simulatedAffectedRows: dryRunRes.simulatedAffectedRows,
                targetTables: dryRunRes.targetTables,
                rollbackVerified: dryRunRes.rollbackVerified,
                executionTimeMs: dryRunRes.executionTimeMs,
                commitToken: dryRunRes.commitToken,
                expiresAt: dryRunRes.expiresAt,
                warnings: dryRunRes.warnings,
                instruction:
                  "To apply these changes permanently to the database, call 'db_commit' with this commitToken and the identical SQL query within 60 seconds.",
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Commit Verified Mutation Tool
  server.tool(
    "db_commit",
    "Permanently execute and commit a mutation previously authorized by 'db_dry_run'. Requires a valid, single-use commitToken.",
    {
      commitToken: z
        .string()
        .describe("The single-use authorization token obtained from 'db_dry_run'."),
      sql: z.string().describe("The exact SQL query that was dry-run and authorized."),
      params: z
        .array(z.union([z.string(), z.number(), z.boolean(), z.null()]))
        .optional()
        .describe("Optional parameterized query values."),
    },
    async ({ commitToken, sql, params }) => {
      try {
        const result = await sandboxEngine.commit(commitToken, sql, params);

        await auditLogger.log({
          auditId: result.auditId,
          timestamp: new Date().toISOString(),
          sql,
          operation: "UPDATE",
          status: "COMMITTED",
          riskLevel: "SAFE",
          riskScore: 20,
          rowCount: result.rowCount,
          executionTimeMs: result.executionTimeMs,
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "COMMITTED",
                  message: "Transaction successfully committed to the database.",
                  rowCount: result.rowCount,
                  executionTimeMs: result.executionTimeMs,
                  auditId: result.auditId,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (err) {
        const rawMessage = (err as Error).message;
        const sanitizedMessage = piiRedactor.redactErrorMessage(rawMessage);

        await auditLogger.log({
          auditId: randomUUID(),
          timestamp: new Date().toISOString(),
          sql,
          operation: "UPDATE",
          status: "ERROR",
          riskLevel: "BLOCKED",
          riskScore: 70,
          violations: [sanitizedMessage],
        });

        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "COMMIT_FAILED",
                  error: sanitizedMessage,
                },
                null,
                2,
              ),
            },
          ],
        };
      }
    },
  );

  // Query Explain & Index Recommender Tool
  server.tool(
    "db_explain_query",
    "Analyze query execution plan (EXPLAIN) to detect sequential full-table scans, missing indexes, and performance bottlenecks.",
    {
      sql: z.string().describe("The SQL query to explain."),
      params: z
        .array(z.union([z.string(), z.number(), z.boolean(), z.null()]))
        .optional()
        .describe("Optional parameterized query values."),
    },
    async ({ sql, params }) => {
      const report = await explainer.explainQuery(sql, params);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: "EXPLAINED",
                isOptimized: report.isIndexed && report.bottlenecks.length === 0,
                isIndexed: report.isIndexed,
                estimatedCost: report.estimatedCost,
                estimatedRows: report.estimatedRows,
                hasSeqScan: report.hasSeqScan,
                costThresholdExceeded:
                  report.estimatedCost !== undefined &&
                  report.estimatedCost > config.maxEstimatedCost,
                rowThresholdExceeded:
                  report.estimatedRows !== undefined &&
                  report.estimatedRows > config.maxEstimatedRows,
                bottlenecks: report.bottlenecks,
                indexingSuggestions: report.suggestions,
                executionPlan: report.rawPlan,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Audit Log Introspection Tool
  server.tool(
    "db_audit_log",
    "Retrieve the security and compliance query audit trail, including blocked operations, risk scores, and PII redactions.",
    {
      limit: z
        .number()
        .int()
        .positive()
        .optional()
        .describe("Number of entries to retrieve (default: 20)."),
      status: z
        .string()
        .optional()
        .describe(
          "Filter by status: SUCCESS, BLOCKED, DRY_RUN_APPROVED, DRY_RUN_REJECTED, COMMITTED, ERROR.",
        ),
      minRiskScore: z
        .number()
        .optional()
        .describe("Filter for queries with riskScore >= minRiskScore."),
    },
    async ({ limit, status, minRiskScore }) => {
      const entries = auditLogger.getEntries({
        limit: limit || 20,
        status,
        minRiskScore,
      });

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: "AUDIT_LOG",
                totalRetrieved: entries.length,
                entries,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Phase 3: Migration Safety & DDL Lock Validator Tool
  server.tool(
    "db_validate_migration",
    "Analyze DDL migrations against zero-downtime safety rules, detect table-level locking risks (e.g. non-concurrent index creation), dangerous NOT NULL columns, and destructive column/table drops.",
    {
      sql: z
        .string()
        .describe("The DDL SQL statement or multi-statement migration script to validate."),
    },
    async ({ sql }) => {
      const report = migrationEngine.validateMigration(sql, config.dialect);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: "VALIDATED",
                safe: report.safe,
                riskScore: report.riskScore,
                highestLockLevel: report.highestLockLevel,
                violationsCount: report.violations.length,
                violations: report.violations,
                warnings: report.warnings,
                safeMigrationPlan: report.safeMigrationPlan,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Phase 3: Schema Health & Unindexed Foreign Keys Drift Tool
  server.tool(
    "db_check_schema_drift",
    "Inspect database schema health, identify unindexed foreign keys causing cascade locks, and detect schema drift.",
    {},
    async () => {
      const liveSchemas = await adapter.getSchema();
      const report = migrationEngine.analyzeSchemaHealth(liveSchemas);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: "HEALTH_CHECK",
                inSync: report.inSync,
                totalTables: report.totalTables,
                unindexedForeignKeysCount: report.unindexedForeignKeys.length,
                unindexedForeignKeys: report.unindexedForeignKeys,
                differences: report.differences,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  return {
    server,
    adapter,
    config,
    guardEngine,
    sandboxEngine,
    piiRedactor,
    auditLogger,
    explainer,
    costGateEngine,
    migrationEngine,
    async start() {
      const transport = new StdioServerTransport();
      await server.connect(transport);
      console.error(
        `🛡️ [DBShield] Security Guardrail Active on stdio (Dialect: ${config.dialect}, Tier: ${config.safetyTier})`,
      );
    },
    async stop() {
      await adapter.disconnect();
      await server.close();
    },
  };
}
