import fs from "node:fs/promises";
import path from "node:path";
import { loadConfig } from "./config/index.js";
import { installClaude, installCursor } from "./configurator/index.js";
import { createMcpServer } from "./server/index.js";

const VERSION = "0.1.0";

const HELP_TEXT = `
  🛡️  DBShield - Database Guardrail & Sandboxing MCP Server v${VERSION}
  ─────────────────────────────────────────────────────────────
  The intelligent safety firewall between AI coding agents and databases.

  USAGE:
    dbshield [command] [options]

  COMMANDS:
    start            Launch the MCP server on stdio transport (default)
    status           Inspect database connection and active security parameters
    init             Generate a default dbshield.config.json in the current directory
    install-claude   Automatically configure Claude Desktop to use DBShield
    install-cursor   Automatically configure Cursor (.cursor/mcp.json) to use DBShield
    help             Display this help message

  OPTIONS:
    --dialect <sqlite|postgres|mysql>   Specify database dialect (default: sqlite)
    --storage <path>                    SQLite database file path (default: ./dbshield.sqlite)
    --tier <STRICT|BALANCED|PERMISSIVE> Security enforcement level (default: BALANCED)
    --version, -v                       Display DBShield version
    --help, -h                          Display this help message

  INTEGRATION EXAMPLES:
    Add to Claude Desktop (claude_desktop_config.json):
    {
      "mcpServers": {
        "dbshield": {
          "command": "npx",
          "args": ["-y", "@ritualdev-lab/dbshield", "start"]
        }
      }
    }

    Add to Cursor (.cursor/mcp.json):
    {
      "mcpServers": {
        "dbshield": {
          "command": "npx",
          "args": ["-y", "@ritualdev-lab/dbshield", "start"]
        }
      }
    }
`;

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || "start";

  if (args.includes("--help") || args.includes("-h") || command === "help") {
    console.log(HELP_TEXT);
    process.exit(0);
  }

  if (args.includes("--version") || args.includes("-v") || command === "version") {
    console.log(`dbshield v${VERSION}`);
    process.exit(0);
  }

  switch (command) {
    case "start": {
      const serverInstance = await createMcpServer();
      await serverInstance.start();
      break;
    }

    case "status": {
      const config = await loadConfig();
      console.log(`
🛡️  DBShield Security Gateway Status
─────────────────────────────────────
Version:           v${VERSION}
Dialect:           ${config.dialect}
Storage Path:      ${config.storagePath || "N/A"}
Safety Tier:       ${config.safetyTier}
Max Mutation Rows: ${config.maxRowsPerMutation}
PII Masking:       ${config.enablePiiMasking ? "ENABLED" : "DISABLED"}
Destructive DDL:   ${config.allowDestructiveDDL ? "ALLOWED" : "BLOCKED"}
`);
      const serverInstance = await createMcpServer();
      const schemas = await serverInstance.adapter.getSchema();
      console.log(`Detected Tables (${schemas.length}):`);
      for (const t of schemas) {
        console.log(`  - ${t.tableName} (${t.columns.length} columns)`);
      }
      await serverInstance.adapter.disconnect();
      break;
    }

    case "init": {
      const configPath = path.resolve(process.cwd(), "dbshield.config.json");
      const starterConfig = {
        $schema: "https://raw.githubusercontent.com/RitualDev-Lab/DBShield/main/schema.json",
        dialect: "sqlite",
        storagePath: "./dev.db",
        safetyTier: "BALANCED",
        maxRowsPerMutation: 50,
        allowDestructiveDDL: false,
        enablePiiMasking: true,
        customPiiColumns: ["token", "ssn", "secret_key"],
      };
      await fs.writeFile(configPath, JSON.stringify(starterConfig, null, 2), "utf8");
      console.log(`✅ Created dbshield.config.json at ${configPath}`);
      break;
    }

    case "install-claude": {
      const result = await installClaude();
      console.log(`
🎉 Successfully configured Claude Desktop for DBShield!
Config File: ${result.configPath}
Status:      ${result.alreadyConfigured ? "Updated existing configuration" : "Added fresh configuration"}

Restart Claude Desktop to start using DBShield database tools!
`);
      break;
    }

    case "install-cursor": {
      const result = await installCursor();
      console.log(`
🎉 Successfully configured Cursor IDE for DBShield!
Config File: ${result.configPath}
Status:      ${result.alreadyConfigured ? "Updated existing configuration" : "Added fresh configuration"}

Reload Cursor to activate DBShield tools in Agent mode!
`);
      break;
    }

    default:
      console.error(`Unknown command '${command}'. Run 'dbshield --help' for usage.`);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("❌ Fatal Error in DBShield CLI:", err);
  process.exit(1);
});
