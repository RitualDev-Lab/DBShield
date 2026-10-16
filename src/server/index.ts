import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createDatabaseAdapter } from "../adapters/index.js";
import { loadConfig } from "../config/index.js";
import type { DBShieldConfig, DatabaseAdapter } from "../types/index.js";

export interface McpServerInstance {
  server: McpServer;
  adapter: DatabaseAdapter;
  config: DBShieldConfig;
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

  return {
    server,
    adapter,
    config,
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
