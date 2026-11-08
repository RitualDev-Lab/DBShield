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

export interface SqlNormalizationResult {
  normalizedSql: string;
  hasMultiStatement: boolean;
  hasCommentEvasion: boolean;
  hasUnicodeSmuggling: boolean;
  tokens: string[];
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

/**
 * Normalizes SQL for AST analysis, security auditing, and tamper inspection.
 * Strips zero-width unicode smuggling characters, neutralizes inline comment evasion (e.g. SEL/*...*\/ECT),
 * detects multi-statement chaining via unquoted semicolons, and canonicalizes whitespace.
 */
export function normalizeSqlForAudit(sql: string): SqlNormalizationResult {
  if (!sql) {
    return {
      normalizedSql: "",
      hasMultiStatement: false,
      hasCommentEvasion: false,
      hasUnicodeSmuggling: false,
      tokens: [],
    };
  }

  // 1. Detect zero-width and invisible unicode characters (Unicode smuggling)
  const zeroWidthPattern = /(?:\u200B|\u200C|\u200D|\uFEFF)/g;
  const abnormalSpacePattern = /[\u00A0\u2028\u2029\u2000-\u200A]/g;
  const hasUnicodeSmuggling = zeroWidthPattern.test(sql) || abnormalSpacePattern.test(sql);
  const cleanUnicode = sql.replace(zeroWidthPattern, "").replace(abnormalSpacePattern, " ");

  // 2. Detect inline comment evasion (e.g. SEL/**/ECT, UN/**/ION, DR/**/OP)
  const commentEvasionPattern = /[a-zA-Z0-9_]\/\*[\s\S]*?\*\/[a-zA-Z0-9_]/;
  const hasCommentEvasion = commentEvasionPattern.test(cleanUnicode);

  // 3. Strip SQL comments safely while preserving string literals
  const stripped = stripSqlComments(cleanUnicode);

  // 4. Multi-statement injection detection:
  // Count unquoted semicolons that separate non-empty statements
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let statementCount = 0;
  let currentStmt = "";
  const statements: string[] = [];

  for (let i = 0; i < stripped.length; i++) {
    const char = stripped[i];
    const next = stripped[i + 1];

    if (inSingleQuote) {
      currentStmt += char;
      if (char === "'" && next === "'") {
        currentStmt += next;
        i++;
      } else if (char === "'") {
        inSingleQuote = false;
      }
      continue;
    }

    if (inDoubleQuote) {
      currentStmt += char;
      if (char === '"' && next === '"') {
        currentStmt += next;
        i++;
      } else if (char === '"') {
        inDoubleQuote = false;
      }
      continue;
    }

    if (char === "'") {
      inSingleQuote = true;
      currentStmt += char;
      continue;
    }

    if (char === '"') {
      inDoubleQuote = true;
      currentStmt += char;
      continue;
    }

    if (char === ";") {
      const trimmed = currentStmt.trim();
      if (trimmed) {
        statements.push(trimmed);
        statementCount++;
      }
      currentStmt = "";
      continue;
    }

    currentStmt += char;
  }

  const trailing = currentStmt.trim();
  if (trailing) {
    statements.push(trailing);
    statementCount++;
  }

  const hasMultiStatement = statementCount > 1;
  const normalizedSql = statements.join("; ").replace(/\s+/g, " ").trim();
  const tokens = normalizedSql.split(/\s+/).filter(Boolean);

  return {
    normalizedSql,
    hasMultiStatement,
    hasCommentEvasion,
    hasUnicodeSmuggling,
    tokens,
  };
}

export function parseSql(sql: string, dialect: DatabaseDialect = "sqlite"): ParseResult {
  const norm = normalizeSqlForAudit(sql);
  const stripped = norm.normalizedSql;
  if (!stripped) {
    return {
      statements: [],
      isMultiStatement: false,
    };
  }

  const parser = new ParserClass();
  const sqlDialect = mapDialect(dialect);

  try {
    const astResult = parser.astify(stripped, { database: sqlDialect });
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
      isMultiStatement: astList.length > 1 || norm.hasMultiStatement,
    };
  } catch (err) {
    return {
      statements: [],
      isMultiStatement: norm.hasMultiStatement,
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
