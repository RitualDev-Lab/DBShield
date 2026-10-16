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
  const parser = new ParserClass();
  const sqlDialect = mapDialect(dialect);

  try {
    const astResult = parser.astify(sql, { database: sqlDialect });
    const astList = Array.isArray(astResult) ? astResult : [astResult];

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

  const node = ast as { type?: string };
  const type = (node.type || "").toLowerCase();

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
  };

  const tables = new Set<string>();

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

  return Array.from(tables);
}
