import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export interface ConfiguratorResult {
  success: boolean;
  configPath: string;
  alreadyConfigured: boolean;
}

export function getClaudeConfigPath(): string {
  const platform = os.platform();
  const homedir = os.homedir();

  if (platform === "win32") {
    const appData = process.env.APPDATA || path.join(homedir, "AppData", "Roaming");
    return path.join(appData, "Claude", "claude_desktop_config.json");
  }

  if (platform === "darwin") {
    return path.join(
      homedir,
      "Library",
      "Application Support",
      "Claude",
      "claude_desktop_config.json",
    );
  }

  // Linux and default
  return path.join(homedir, ".config", "Claude", "claude_desktop_config.json");
}

export function getCursorConfigPath(projectDir = process.cwd()): string {
  return path.join(projectDir, ".cursor", "mcp.json");
}

export async function installClaude(customPath?: string): Promise<ConfiguratorResult> {
  const targetPath = customPath || getClaudeConfigPath();
  return await patchMcpConfigFile(targetPath);
}

export async function installCursor(projectDir = process.cwd()): Promise<ConfiguratorResult> {
  const targetPath = getCursorConfigPath(projectDir);
  return await patchMcpConfigFile(targetPath);
}

async function patchMcpConfigFile(targetPath: string): Promise<ConfiguratorResult> {
  let existingConfig: { mcpServers?: Record<string, unknown> } = {};
  let alreadyConfigured = false;

  try {
    const raw = await fs.readFile(targetPath, "utf8");
    existingConfig = JSON.parse(raw);
  } catch {
    // Config file doesn't exist yet, create fresh structure
  }

  if (!existingConfig.mcpServers) {
    existingConfig.mcpServers = {};
  }

  if (existingConfig.mcpServers.dbshield) {
    alreadyConfigured = true;
  }

  existingConfig.mcpServers.dbshield = {
    command: "npx",
    args: ["-y", "@ritualdev-lab/dbshield", "start"],
  };

  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.writeFile(targetPath, JSON.stringify(existingConfig, null, 2), "utf8");

  return {
    success: true,
    configPath: targetPath,
    alreadyConfigured,
  };
}
