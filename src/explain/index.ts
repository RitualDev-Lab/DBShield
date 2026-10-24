import { stripSqlComments } from "../guard/ast.js";
import type { DatabaseAdapter } from "../types/index.js";

export interface ExplainReport {
  rawPlan: Record<string, unknown>[];
  bottlenecks: string[];
  suggestions: string[];
  isIndexed: boolean;
}

export class QueryExplainer {
  private readonly adapter: DatabaseAdapter;

  constructor(adapter: DatabaseAdapter) {
    this.adapter = adapter;
  }

  public async explainQuery(sql: string, params: unknown[] = []): Promise<ExplainReport> {
    const trimmed = sql.trim().replace(/;+$/, "");
    const isPostgres = this.adapter.dialect === "postgres";
    const explainSql = isPostgres ? `EXPLAIN ${trimmed};` : `EXPLAIN QUERY PLAN ${trimmed};`;

    const bottlenecks: string[] = [];
    const suggestions: string[] = [];
    let isIndexed = true;

    try {
      const result = await this.adapter.query(explainSql, params);
      const rows = result.rows;

      if (isPostgres) {
        // PostgreSQL text explain output returns rows like { "QUERY PLAN": "Seq Scan on users (cost=... rows=...)" }
        for (const row of rows) {
          const planLine = String(
            row["QUERY PLAN"] || row["query plan"] || Object.values(row)[0] || "",
          );

          if (planLine.includes("Seq Scan on ")) {
            isIndexed = false;
            const match = planLine.match(/Seq Scan on\s+([a-zA-Z0-9_]+)/i);
            const tableName = match ? match[1] : "table";

            bottlenecks.push(
              `Full table sequential scan detected on '${tableName}' (${planLine}).`,
            );
            suggestions.push(
              `Create an index on the column(s) filtered in the WHERE or JOIN condition of '${tableName}' to prevent table-level locks.`,
            );
          }

          if (planLine.includes("Sort Method: external merge") || planLine.includes("Disk")) {
            bottlenecks.push(
              `Disk-based sorting detected (${planLine}) due to unindexed ORDER BY or insufficient work_mem.`,
            );
            suggestions.push(
              "Consider adding an index on sorting columns or tuning work_mem to keep sorts in memory.",
            );
          }
        }
      } else {
        // SQLite EXPLAIN QUERY PLAN format
        for (const row of rows) {
          const detail = String(row.detail || "");

          // Detect full table sequential scans
          if (detail.includes("SCAN ") && !detail.includes("USING INDEX")) {
            isIndexed = false;
            const match = detail.match(/SCAN\s+(?:TABLE\s+)?([a-zA-Z0-9_]+)/i);
            const tableName = match ? match[1] : "table";

            bottlenecks.push(`Full table sequential scan detected on '${tableName}' (${detail}).`);
            suggestions.push(
              `Create an index on the column(s) filtered in the WHERE or JOIN condition of '${tableName}' to prevent table-level locks.`,
            );
          }

          // Detect temporary B-Trees used for sorting or grouping
          if (detail.includes("USE TEMP B-TREE")) {
            bottlenecks.push(
              `Temporary B-Tree created in memory (${detail}) due to sorting/grouping without an index.`,
            );
            suggestions.push(
              "Consider ordering or grouping by indexed columns to avoid temporary disk/memory sorting structures.",
            );
          }
        }
      }

      // Check if SELECT or CTE query lacks a LIMIT clause
      const strippedUpper = stripSqlComments(trimmed).toUpperCase();
      const isSelectOrCte = strippedUpper.startsWith("SELECT") || strippedUpper.startsWith("WITH");
      if (isSelectOrCte && !strippedUpper.includes("LIMIT ") && !isIndexed) {
        bottlenecks.push("Unbounded full-table scan query lacks a LIMIT clause.");
        suggestions.push(
          "Add a LIMIT clause (e.g. LIMIT 50) to protect database memory and connection pool limits.",
        );
      }

      if (bottlenecks.length === 0) {
        suggestions.push(
          "Query execution plan is optimized and utilizes existing index structures.",
        );
      }

      return {
        rawPlan: rows,
        bottlenecks,
        suggestions,
        isIndexed,
      };
    } catch (err) {
      return {
        rawPlan: [],
        bottlenecks: [`Failed to generate EXPLAIN plan: ${(err as Error).message}`],
        suggestions: ["Ensure the SQL syntax is valid for EXPLAIN execution."],
        isIndexed: false,
      };
    }
  }
}
