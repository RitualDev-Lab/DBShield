import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createDatabaseAdapter } from "../adapters/index.js";
import { AuditLogger } from "../audit/index.js";
import { loadConfig } from "../config/index.js";
import { QueryExplainer } from "../explain/index.js";
import { SqlGuardEngine } from "../guard/index.js";
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
  const auditLogger = new AuditLogger(config.auditLogPath);
  const explainer = new QueryExplainer(adapter);

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

      try {
        const result = await adapter.query(sql, params, {
          maxRows: config.maxRowsPerRead,
          maxMutationRows: config.maxRowsPerMutation,
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
                  auditId: result.auditId,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (err) {
        await auditLogger.log({
          auditId: randomUUID(),
          timestamp: new Date().toISOString(),
          sql,
          operation: evaluation.operation,
          status: "ERROR",
          riskLevel: evaluation.riskLevel,
          riskScore: evaluation.riskScore,
          violations: [(err as Error).message],
        });

        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "DATABASE_ERROR",
                  error: (err as Error).message,
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
        await auditLogger.log({
          auditId: randomUUID(),
          timestamp: new Date().toISOString(),
          sql,
          operation: "UPDATE",
          status: "ERROR",
          riskLevel: "BLOCKED",
          riskScore: 70,
          violations: [(err as Error).message],
        });

        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "COMMIT_FAILED",
                  error: (err as Error).message,
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

  return {
    server,
    adapter,
    config,
    guardEngine,
    sandboxEngine,
    piiRedactor,
    auditLogger,
    explainer,
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
