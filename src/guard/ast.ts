import type { AST } from "node-sql-parser";
import nodeSqlParser from "node-sql-parser";
import type { DatabaseDialect, SqlOperationType } from "../types/index.js";

const ParserClass = (
  nodeSqlParser as unknown as {
    Parser: new () => {
      astify: (sql: string, opt?: Record<string, unknown>) => AST | AST[];
    };
  }
).Parser;

export interface ParsedStatement {
  ast: AST;
  operation: SqlOperationType;
  targetTables: string[];
  rawSql: string;
}

export interface ParseResult {
  statements: ParsedStatement[];
  isMultiStatement: boolean;
  parseError?: string;
}

/**
 * Safely strips single-line (-- ...) and multi-line (/* ... *\/) SQL comments,
 * properly respecting single and double quoted string literals and escapes.
 */
export function stripSqlComments(sql: string): string {
  if (!sql) return "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inLineComment = false;
  let inBlockComment = false;
  let result = "";

  for (let i = 0; i < sql.length; i++) {
    const char = sql[i];
    const next = sql[i + 1];

    if (inLineComment) {
      if (char === "\n" || char === "\r") {
        inLineComment = false;
        result += char;
      }
      continue;
    }

    if (inBlockComment) {
      if (char === "*" && next === "/") {
        inBlockComment = false;
        i++; // skip /
      }
      continue;
    }

    if (inSingleQuote) {
      result += char;
      if (char === "'" && next === "'") {
        result += next;
        i++;
      } else if (char === "'") {
        inSingleQuote = false;
      }
      continue;
    }

    if (inDoubleQuote) {
      result += char;
      if (char === '"' && next === '"') {
        result += next;
        i++;
      } else if (char === '"') {
        inDoubleQuote = false;
      }
      continue;
    }

    if (char === "-" && next === "-") {
      inLineComment = true;
      i++;
      continue;
    }

    if (char === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }

    if (char === "'") {
      inSingleQuote = true;
      result += char;
      continue;
    }

    if (char === '"') {
      inDoubleQuote = true;
      result += char;
      continue;
    }

    result += char;
  }

  return result.trim();
}

function mapDialect(dialect: DatabaseDialect): string {
  switch (dialect) {
    case "sqlite":
      return "sqlite";
    case "postgres":
      return "postgresql";
    case "mysql":
      return "mysql";
    default:
      return "sqlite";
  }
}

export function parseSql(sql: string, dialect: DatabaseDialect = "sqlite"): ParseResult {
  const stripped = stripSqlComments(sql);
  if (!stripped) {
    return {
      statements: [],
      isMultiStatement: false,
    };
  }

  const parser = new ParserClass();
  const sqlDialect = mapDialect(dialect);

  try {
    const astResult = parser.astify(sql, { database: sqlDialect });
    const astList = Array.isArray(astResult) ? astResult : [astResult];

    if (astList.length === 0) {
      return {
        statements: [],
        isMultiStatement: false,
      };
    }

    const statements: ParsedStatement[] = astList.map((ast) => {
      const operation = determineOperation(ast);
      const targetTables = extractTables(ast);
      return {
        ast,
        operation,
        targetTables,
        rawSql: sql,
      };
    });

    return {
      statements,
      isMultiStatement: astList.length > 1,
    };
  } catch (err) {
    return {
      statements: [],
      isMultiStatement: false,
      parseError: (err as Error).message,
    };
  }
}

export function determineOperation(ast: unknown): SqlOperationType {
  if (!ast || typeof ast !== "object") return "UNKNOWN";

  const node = ast as { type?: string; stmt?: unknown; with?: unknown };
  const type = (node.type || "").toLowerCase();

  // If top-level statement is a CTE container or wrapper
  if ((!type || type === "with") && node.stmt) {
    return determineOperation(node.stmt);
  }

  switch (type) {
    case "select":
      return "SELECT";
    case "insert":
      return "INSERT";
    case "update":
      return "UPDATE";
    case "delete":
      return "DELETE";
    case "create":
      return "DDL_CREATE";
    case "alter":
      return "DDL_ALTER";
    case "drop":
      return "DDL_DROP";
    case "truncate":
      return "DDL_TRUNCATE";
    default:
      return "UNKNOWN";
  }
}

export function extractTables(ast: unknown): string[] {
  if (!ast || typeof ast !== "object") return [];

  const node = ast as {
    table?: Array<{ table?: string }> | { table?: string };
    from?: Array<{ table?: string }>;
    name?: Array<{ table?: string }>;
    with?: Array<{ name?: { value?: string }; stmt?: { ast?: unknown } }>;
  };

  const tables = new Set<string>();
  const cteNames = new Set<string>();

  // Check CTE (WITH clauses) for underlying target tables
  if (Array.isArray(node.with)) {
    for (const w of node.with) {
      if (w.name?.value) {
        cteNames.add(w.name.value);
      }
      if (w?.stmt?.ast) {
        const innerTables = extractTables(w.stmt.ast);
        for (const it of innerTables) {
          tables.add(it);
        }
      }
    }
  }

  // Check direct table property
  if (Array.isArray(node.table)) {
    for (const t of node.table) {
      if (t?.table) tables.add(t.table);
    }
  } else if (node.table?.table) {
    tables.add(node.table.table);
  }

  // Check from clauses
  if (Array.isArray(node.from)) {
    for (const f of node.from) {
      if (f?.table) tables.add(f.table);
    }
  }

  // Check name property for DDL (DROP, TRUNCATE)
  if (Array.isArray(node.name)) {
    for (const n of node.name) {
      if (n?.table) tables.add(n.table);
    }
  }

  // Filter out temporary CTE aliases if real underlying tables exist
  const nonCteTables = Array.from(tables).filter((t) => !cteNames.has(t));
  if (nonCteTables.length > 0) {
    return nonCteTables;
  }

  return Array.from(tables);
}
