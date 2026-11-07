import { parseSql, stripSqlComments } from "../guard/ast.js";
import type {
  DatabaseDialect,
  ExplainReport,
  MissingIndexAdvice,
  QueryPlanAdvisorReport,
} from "../types/index.js";

export class QueryPlanAdvisor {
  /**
   * Extract columns used in WHERE predicates and JOIN conditions for a specific table.
   */
  public static extractPredicateColumns(
    sql: string,
    targetTable: string,
    dialect: DatabaseDialect = "sqlite",
  ): string[] {
    const columns = new Set<string>();
    const cleanTbl = targetTable.toLowerCase();

    // 1. Try AST traversal
    try {
      const parsed = parseSql(sql, dialect);
      if (parsed.statements.length > 0) {
        for (const stmt of parsed.statements) {
          const ast = stmt.ast as {
            where?: unknown;
            from?: Array<{ on?: unknown; db?: string; table?: string; as?: string }>;
            orderby?: Array<{ expr?: { column?: string; table?: string } }>;
          };

          // Traverse WHERE clause
          if (ast.where) {
            QueryPlanAdvisor.traverseAstForColumns(ast.where, cleanTbl, columns);
          }

          // Traverse JOIN ON clauses
          if (Array.isArray(ast.from)) {
            for (const f of ast.from) {
              if (f.on) {
                QueryPlanAdvisor.traverseAstForColumns(f.on, cleanTbl, columns);
              }
            }
          }

          // Traverse ORDER BY clause
          if (Array.isArray(ast.orderby)) {
            for (const o of ast.orderby) {
              if (o.expr?.column) {
                if (!o.expr.table || o.expr.table.toLowerCase() === cleanTbl) {
                  columns.add(o.expr.column.toLowerCase());
                }
              }
            }
          }
        }
      }
    } catch {
      // Fallback to regex
    }

    // 2. Fallback if AST returned empty
    if (columns.size === 0) {
      const stripped = stripSqlComments(sql);

      // Extract WHERE clause using linear index search to eliminate ReDoS
      const whereIdx = stripped.search(/\bWHERE\b/i);
      if (whereIdx !== -1) {
        const afterWhere = stripped.slice(whereIdx + 5);
        const endMatch = afterWhere.match(/\b(ORDER\s+BY|GROUP\s+BY|LIMIT)\b|;/i);
        const whereText =
          endMatch && endMatch.index !== undefined
            ? afterWhere.slice(0, endMatch.index)
            : afterWhere;

        // Match table.column or bare column with comparison operators
        const predMatches = whereText.matchAll(
          /\b(?:([a-zA-Z0-9_]+)\.)?([a-zA-Z0-9_]+)\s*(=|!=|<>|<=|>=|<|>|\bIN\b|\bLIKE\b|\bILIKE\b|\bBETWEEN\b|\bIS\b)/gi,
        );
        for (const pm of predMatches) {
          const tablePrefix = pm[1]?.toLowerCase();
          const colName = pm[2]?.toLowerCase();
          if (!tablePrefix || tablePrefix === cleanTbl) {
            // Ignore SQL keywords
            if (!/^(and|or|not|select|null|true|false)$/i.test(colName)) {
              columns.add(colName);
            }
          }
        }
      }
    }

    return Array.from(columns);
  }

  private static traverseAstForColumns(
    node: unknown,
    targetTable: string,
    columns: Set<string>,
  ): void {
    if (!node || typeof node !== "object") return;

    const n = node as {
      type?: string;
      column?: string;
      table?: string;
      left?: unknown;
      right?: unknown;
      expr?: unknown;
    };

    if (n.column) {
      if (!n.table || n.table.toLowerCase() === targetTable) {
        columns.add(n.column.toLowerCase());
      }
    }

    if (n.left) QueryPlanAdvisor.traverseAstForColumns(n.left, targetTable, columns);
    if (n.right) QueryPlanAdvisor.traverseAstForColumns(n.right, targetTable, columns);
    if (n.expr) QueryPlanAdvisor.traverseAstForColumns(n.expr, targetTable, columns);
  }

  /**
   * Generates optimal CREATE INDEX DDL statement based on dialect and columns.
   */
  public static generateIndexDdl(
    tableName: string,
    columns: string[],
    dialect: DatabaseDialect = "sqlite",
  ): { indexName: string; ddl: string } {
    const colSuffix = columns.join("_").replace(/[^a-zA-Z0-9_]/g, "");
    const indexName = `idx_${tableName}_${colSuffix}`;
    const quotedCols = columns.map((c) => `"${c}"`).join(", ");

    if (dialect === "postgres") {
      return {
        indexName,
        ddl: `CREATE INDEX CONCURRENTLY ${indexName} ON ${tableName} (${quotedCols});`,
      };
    }

    return {
      indexName,
      ddl: `CREATE INDEX ${indexName} ON ${tableName} (${quotedCols});`,
    };
  }

  /**
   * Analyzes an EXPLAIN report and generates missing index alerts and DDL suggestions.
   */
  public static analyze(
    sql: string,
    report: ExplainReport,
    dialect: DatabaseDialect = "sqlite",
  ): QueryPlanAdvisorReport {
    const advice: MissingIndexAdvice[] = [];
    const alerts: string[] = [];
    const suggestedDdls: string[] = [];

    // Scan bottlenecks for sequential scan tables
    const seqScanTables = new Set<string>();

    for (const b of report.bottlenecks) {
      const match = b.match(
        /(?:sequential scan detected on|Full table sequential scan detected on)\s+'?([a-zA-Z0-9_]+)'?/i,
      );
      if (match) {
        seqScanTables.add(match[1]);
      }
    }

    // If report hasSeqScan is true but no table extracted from bottlenecks, check rawPlan
    if (seqScanTables.size === 0 && report.hasSeqScan) {
      for (const row of report.rawPlan) {
        const rowStr = JSON.stringify(row);
        const match = rowStr.match(/(?:Seq Scan on|SCAN\s+(?:TABLE\s+)?)([a-zA-Z0-9_]+)/i);
        if (match) {
          seqScanTables.add(match[1]);
        }
      }
    }

    for (const tableName of seqScanTables) {
      const predicateCols = QueryPlanAdvisor.extractPredicateColumns(sql, tableName, dialect);

      // If no explicit predicate columns identified, fall back to "id" or primary lookup
      const targetCols = predicateCols.length > 0 ? predicateCols : ["id"];
      const { indexName, ddl } = QueryPlanAdvisor.generateIndexDdl(tableName, targetCols, dialect);

      // Determine regressive severity
      const estimatedCost = report.estimatedCost;
      const estimatedRows = report.estimatedRows;
      let severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" = "MEDIUM";

      if ((estimatedRows && estimatedRows > 50000) || (estimatedCost && estimatedCost > 10000)) {
        severity = "CRITICAL";
      } else if (
        (estimatedRows && estimatedRows > 5000) ||
        (estimatedCost && estimatedCost > 2000)
      ) {
        severity = "HIGH";
      }

      const costText = estimatedCost ? ` (est. planner cost: ${estimatedCost.toFixed(0)})` : "";
      const rowsText = estimatedRows ? ` (est. rows: ${estimatedRows.toLocaleString()})` : "";

      const reason = `Query executes full-table sequential scan on '${tableName}' across predicate column(s) [${targetCols.join(", ")}]${rowsText}${costText}. Adding an index converts scan to O(log N) indexed lookup.`;

      advice.push({
        tableName,
        columns: targetCols,
        suggestedIndexName: indexName,
        suggestedDdl: ddl,
        regressiveSeverity: severity,
        reason,
        estimatedCost,
        estimatedRows,
      });

      suggestedDdls.push(ddl);
      alerts.push(
        `[MISSING_INDEX_${severity}] Table '${tableName}' scanned sequentially on [${targetCols.join(", ")}]. Suggested fix: ${ddl}`,
      );
    }

    return {
      hasRegression: advice.length > 0,
      advice,
      alerts,
      suggestedDdls,
    };
  }
}
