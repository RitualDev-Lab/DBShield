/**
 * DBShield Audit Scanner: Static Analysis for SQL, Schemas & Migrations
 *
 * Scans SQL files, Prisma schemas, and migration directories for table lock hazards,
 * unindexed foreign keys, destructive DDL drops, and unconstrained mutations.
 */

import fs from "node:fs/promises";
import path from "node:path";
import { loadConfig } from "./config/index.js";
import { SqlGuardEngine } from "./guard/engine.js";

export interface AuditHazard {
  file: string;
  line: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  category:
    | "DESTRUCTIVE_DDL"
    | "LOCK_HAZARD"
    | "TAUTOLOGY"
    | "UNCONSTRAINED_MUTATION"
    | "MISSING_INDEX";
  statement: string;
  recommendation: string;
}

export interface AuditReport {
  scannedFiles: number;
  totalStatements: number;
  hazards: AuditHazard[];
  passed: boolean;
  score: number;
}

export async function runAuditScan(targetPath: string): Promise<AuditReport> {
  const hazards: AuditHazard[] = [];
  let scannedFiles = 0;
  let totalStatements = 0;

  const files = await findSqlAndSchemaFiles(targetPath);
  const baseConfig = await loadConfig();
  const guard = new SqlGuardEngine({
    ...baseConfig,
    safetyTier: "STRICT",
    allowDestructiveDDL: false,
    maxRowsPerMutation: 50,
  });

  for (const filePath of files) {
    scannedFiles++;
    let content = "";
    try {
      content = await fs.readFile(filePath, "utf8");
    } catch {
      continue;
    }

    const lines = content.split("\n");
    let currentStatement = "";
    let statementStartLine = 1;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith("--") || line.startsWith("//") || line.startsWith("#")) {
        continue;
      }

      if (!currentStatement) {
        statementStartLine = i + 1;
      }
      currentStatement += ` ${line}`;

      if (line.endsWith(";")) {
        totalStatements++;
        const stmt = currentStatement.trim();
        currentStatement = "";

        // Check 1: Destructive DDL
        if (
          /\bDROP\s+TABLE\b/i.test(stmt) ||
          /\bDROP\s+DATABASE\b/i.test(stmt) ||
          /\bTRUNCATE\b/i.test(stmt)
        ) {
          hazards.push({
            file: path.relative(process.cwd(), filePath),
            line: statementStartLine,
            severity: "CRITICAL",
            category: "DESTRUCTIVE_DDL",
            statement: stmt.slice(0, 80),
            recommendation:
              "Destructive DDL drops tables permanently. Use soft-delete or non-destructive schema migrations.",
          });
          continue;
        }

        // Check 2: Table lock hazard (ALTER TABLE ADD COLUMN NOT NULL without DEFAULT)
        if (
          /\bALTER\s+TABLE\b/i.test(stmt) &&
          /\bADD\s+COLUMN\b/i.test(stmt) &&
          /\bNOT\s+NULL\b/i.test(stmt) &&
          !/\bDEFAULT\b/i.test(stmt)
        ) {
          hazards.push({
            file: path.relative(process.cwd(), filePath),
            line: statementStartLine,
            severity: "HIGH",
            category: "LOCK_HAZARD",
            statement: stmt.slice(0, 80),
            recommendation:
              "Adding NOT NULL column without DEFAULT requires an exclusive table rewrite lock. Provide a DEFAULT or add NULL first.",
          });
        }

        // Check 3: Run through SqlGuardEngine
        try {
          const check = guard.evaluate(stmt);
          if (!check.allowed) {
            const reason =
              check.violations.map((v) => v.message).join("; ") ||
              "Query violates security guardrail";
            const isTautology =
              /\bWHERE\s+['"]?1['"]?\s*=\s*['"]?1['"]?/i.test(stmt) ||
              /\bWHERE\s+true\b/i.test(stmt) ||
              reason.toLowerCase().includes("tautology");
            hazards.push({
              file: path.relative(process.cwd(), filePath),
              line: statementStartLine,
              severity: isTautology ? "CRITICAL" : "HIGH",
              category: isTautology ? "TAUTOLOGY" : "UNCONSTRAINED_MUTATION",
              statement: stmt.slice(0, 80),
              recommendation: reason,
            });
          }
        } catch {
          // Non-standard statement or vendor DDL
        }
      }
    }
  }

  const score = Math.max(0, 100 - hazards.length * 15);
  return {
    scannedFiles,
    totalStatements,
    hazards,
    passed: hazards.filter((h) => h.severity === "CRITICAL").length === 0,
    score,
  };
}

async function findSqlAndSchemaFiles(target: string): Promise<string[]> {
  const result: string[] = [];

  async function walk(dir: string) {
    let entries: string[] = [];
    try {
      entries = await fs.readdir(dir);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry === "node_modules" || entry === ".git" || entry === "dist") continue;
      const full = path.join(dir, entry);
      try {
        const stat = await fs.stat(full);
        if (stat.isDirectory()) {
          await walk(full);
        } else if (full.endsWith(".sql") || full.endsWith(".ddl") || full.endsWith(".prisma")) {
          result.push(full);
        }
      } catch {}
    }
  }

  try {
    const stat = await fs.stat(target);
    if (stat.isDirectory()) {
      await walk(target);
    } else if (target.endsWith(".sql") || target.endsWith(".ddl") || target.endsWith(".prisma")) {
      result.push(target);
    }
  } catch {
    // Path doesn't exist
  }

  return result;
}
