import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createDatabaseAdapter } from "../adapters/index.js";
import { loadConfig } from "../config/index.js";
import { SqlGuardEngine } from "../guard/index.js";
import type { DBShieldConfig, DatabaseAdapter } from "../types/index.js";

export interface McpServerInstance {
  server: McpServer;
  adapter: DatabaseAdapter;
  config: DBShieldConfig;
  guardEngine: SqlGuardEngine;
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
        const result = await adapter.query(sql, params);
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
                  rows: result.rows,
                  auditId: result.auditId,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (err) {
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

  return {
    server,
    adapter,
    config,
    guardEngine,
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
