import { stripSqlComments } from "../guard/ast.js";
import type {
  DBShieldConfig,
  DatabaseDialect,
  MigrationValidationReport,
  MigrationViolation,
  RiskLevel,
  SchemaDriftDifference,
  SchemaDriftReport,
  TableSchema,
} from "../types/index.js";

export class MigrationSafetyEngine {
  private config: DBShieldConfig;

  constructor(config: DBShieldConfig) {
    this.config = config;
  }

  public updateConfig(newConfig: Partial<DBShieldConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Validate a single DDL statement or full migration script.
   */
  public validateMigration(
    sql: string,
    dialect: DatabaseDialect = this.config.dialect,
  ): MigrationValidationReport {
    const stripped = stripSqlComments(sql).trim();
    if (!stripped) {
      return {
        safe: true,
        riskScore: 0,
        highestLockLevel: "NONE",
        violations: [],
        warnings: [],
        safeMigrationPlan: [],
      };
    }

    if (!this.config.enableMigrationGate) {
      return {
        safe: true,
        riskScore: 0,
        highestLockLevel: "NONE",
        violations: [],
        warnings: [],
        safeMigrationPlan: [],
      };
    }

    // Split statements if migration script contains multiple statements
    const statements = splitSqlStatements(stripped);
    const violations: MigrationViolation[] = [];
    const warnings: string[] = [];
    const safeMigrationPlan: string[] = [];
    let riskScore = 0;
    let highestLockLevel: MigrationValidationReport["highestLockLevel"] = "NONE";

    for (const stmt of statements) {
      const stmtResult = this.inspectStatement(stmt, dialect);
      violations.push(...stmtResult.violations);
      warnings.push(...stmtResult.warnings);
      safeMigrationPlan.push(...stmtResult.safeAlternatives);

      if (stmtResult.riskScore > riskScore) {
        riskScore = stmtResult.riskScore;
      }

      if (isHigherLock(stmtResult.lockType, highestLockLevel)) {
        highestLockLevel = stmtResult.lockType;
      }
    }

    const hasBlockedOrCritical = violations.some(
      (v) => v.severity === "CRITICAL" || v.severity === "BLOCKED",
    );

    return {
      safe: !hasBlockedOrCritical,
      riskScore: Math.min(riskScore, 100),
      highestLockLevel,
      violations,
      warnings,
      safeMigrationPlan: Array.from(new Set(safeMigrationPlan)),
    };
  }

  /**
   * Inspect a single DDL statement for dangerous migration anti-patterns.
   */
  private inspectStatement(
    sql: string,
    dialect: DatabaseDialect,
  ): {
    violations: MigrationViolation[];
    warnings: string[];
    safeAlternatives: string[];
    riskScore: number;
    lockType: MigrationValidationReport["highestLockLevel"];
  } {
    const violations: MigrationViolation[] = [];
    const warnings: string[] = [];
    const safeAlternatives: string[] = [];
    let riskScore = 0;
    let lockType: MigrationValidationReport["highestLockLevel"] = "NONE";

    const upper = sql.trim().toUpperCase();

    // 1. DANGEROUS_NOT_NULL_COLUMN: Adding NOT NULL column without a DEFAULT
    // Pattern: ALTER TABLE <tbl> ADD [COLUMN] <col> <type> NOT NULL (without DEFAULT)
    if (upper.includes("ALTER TABLE") && upper.includes("ADD ") && upper.includes("NOT NULL")) {
      const hasDefault = upper.includes("DEFAULT");
      if (!hasDefault) {
        const tableMatch = sql.match(/ALTER\s+TABLE\s+(?:ONLY\s+)?([a-zA-Z0-9_."]+)/i);
        const colMatch = sql.match(
          /ADD\s+(?:COLUMN\s+)?([a-zA-Z0-9_."]+)\s+[^,;]+?\bNOT\s+NULL\b/i,
        );
        const table = tableMatch ? tableMatch[1].replace(/["`]/g, "") : "target_table";
        const column = colMatch ? colMatch[1].replace(/["`]/g, "") : "new_column";

        riskScore = Math.max(riskScore, 85);
        lockType = "ACCESS_EXCLUSIVE";
        const alternative = `Zero-Downtime Safe Column Addition:\n  1. ALTER TABLE ${table} ADD COLUMN ${column} <type>; (nullable)\n  2. Backfill existing rows with non-null values.\n  3. Add NOT NULL constraint (e.g. ALTER TABLE ${table} ADD CONSTRAINT ${table}_${column}_nn CHECK (${column} IS NOT NULL) NOT VALID; then VALIDATE).`;

        violations.push({
          code: "DANGEROUS_NOT_NULL_COLUMN",
          statement: sql,
          targetTable: table,
          targetColumn: column,
          severity: "BLOCKED",
          lockType: "ACCESS_EXCLUSIVE",
          message: `Adding NOT NULL column '${column}' to table '${table}' without a DEFAULT clause will fail or hold an exclusive table lock if rows exist.`,
          safeAlternative: alternative,
        });
        safeAlternatives.push(alternative);
      }
    }

    // 2. DESTRUCTIVE_COLUMN_DROP: ALTER TABLE DROP COLUMN
    if (
      upper.includes("ALTER TABLE") &&
      (upper.includes("DROP COLUMN") || upper.match(/DROP\s+[a-zA-Z0-9_"]+/i))
    ) {
      const dropColMatch = sql.match(/DROP\s+(?:COLUMN\s+)?([a-zA-Z0-9_."]+)/i);
      const tableMatch = sql.match(/ALTER\s+TABLE\s+(?:ONLY\s+)?([a-zA-Z0-9_."]+)/i);
      if (dropColMatch && tableMatch && !upper.includes("DROP CONSTRAINT")) {
        const table = tableMatch[1].replace(/["`]/g, "");
        const column = dropColMatch[1].replace(/["`]/g, "");

        riskScore = Math.max(riskScore, 90);
        lockType = "ACCESS_EXCLUSIVE";
        const alternative = `Expand-and-Contract Column Deprecation:\n  1. Stop writing to '${column}' in application code.\n  2. In the next release, remove all read queries referencing '${column}'.\n  3. Only drop '${column}' after verifying zero live queries reference it.`;

        violations.push({
          code: "DESTRUCTIVE_COLUMN_DROP",
          statement: sql,
          targetTable: table,
          targetColumn: column,
          severity: this.config.allowDestructiveDDL ? "CAUTION" : "BLOCKED",
          lockType: "ACCESS_EXCLUSIVE",
          message: `Dropping column '${column}' from table '${table}' causes instant production breakage for active services referencing the column.`,
          safeAlternative: alternative,
        });
        safeAlternatives.push(alternative);
      }
    }

    // 3. DESTRUCTIVE_TABLE_DROP: DROP TABLE or TRUNCATE TABLE
    if (upper.startsWith("DROP TABLE") || upper.startsWith("TRUNCATE")) {
      const tableMatch = sql.match(
        /(?:DROP\s+TABLE(?:\s+IF\s+EXISTS)?|TRUNCATE(?:\s+TABLE)?)\s+([a-zA-Z0-9_.",\s]+)/i,
      );
      const tables = tableMatch ? tableMatch[1].trim().replace(/["`]/g, "") : "table";

      riskScore = Math.max(riskScore, 95);
      lockType = "ACCESS_EXCLUSIVE";
      const alternative = `Table Deprecation Lifecycle:\n  1. Rename table to '${tables}_deprecated'.\n  2. Verify no active queries fail.\n  3. Archive table data before drop.`;

      violations.push({
        code: "DESTRUCTIVE_TABLE_DROP",
        statement: sql,
        targetTable: tables,
        severity: this.config.allowDestructiveDDL ? "CAUTION" : "CRITICAL",
        lockType: "ACCESS_EXCLUSIVE",
        message: `Dropping or truncating table(s) '${tables}' irreversibly destroys schema structure and data.`,
        safeAlternative: alternative,
      });
      safeAlternatives.push(alternative);
    }

    // 4. TABLE_LOCKING_INDEX_CREATION: Non-concurrent index creation in PostgreSQL
    if (upper.includes("CREATE ") && upper.includes("INDEX ") && dialect === "postgres") {
      const isConcurrent = upper.includes("CONCURRENTLY");
      if (!isConcurrent) {
        const tableMatch = sql.match(/ON\s+([a-zA-Z0-9_."]+)/i);
        const indexMatch = sql.match(/INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_."]+)/i);
        const table = tableMatch ? tableMatch[1].replace(/["`]/g, "") : "target_table";
        const indexName = indexMatch ? indexMatch[1].replace(/["`]/g, "") : "new_index";

        riskScore = Math.max(riskScore, 65);
        lockType = isHigherLock("SHARE", lockType) ? "SHARE" : lockType;

        const alternative = `Non-Locking Index Creation:\n  Use: CREATE INDEX CONCURRENTLY ${indexName} ON ${table}(...); to avoid blocking writes during index build.`;

        const severity: RiskLevel = this.config.enforceConcurrentIndexCreation
          ? "BLOCKED"
          : "CAUTION";

        violations.push({
          code: "TABLE_LOCKING_INDEX_CREATION",
          statement: sql,
          targetTable: table,
          severity,
          lockType: "SHARE",
          message: `In PostgreSQL, 'CREATE INDEX' without 'CONCURRENTLY' acquires a ShareLock on '${table}', blocking concurrent INSERT, UPDATE, and DELETE operations.`,
          safeAlternative: alternative,
        });
        safeAlternatives.push(alternative);
      }
    }

    // 5. BREAKING_RENAME: RENAME COLUMN or RENAME TABLE
    if (
      upper.includes("RENAME COLUMN") ||
      upper.includes("RENAME TO") ||
      upper.includes("RENAME TABLE")
    ) {
      const tableMatch = sql.match(/ALTER\s+TABLE\s+(?:ONLY\s+)?([a-zA-Z0-9_."]+)/i);
      const renameMatch = sql.match(
        /RENAME\s+(?:COLUMN\s+)?([a-zA-Z0-9_."]+)\s+TO\s+([a-zA-Z0-9_."]+)/i,
      );
      const table = tableMatch ? tableMatch[1].replace(/["`]/g, "") : "target_table";
      const oldName = renameMatch ? renameMatch[1].replace(/["`]/g, "") : "old_name";
      const newName = renameMatch ? renameMatch[2].replace(/["`]/g, "") : "new_name";

      riskScore = Math.max(riskScore, 75);
      lockType = "ACCESS_EXCLUSIVE";
      const alternative = `Zero-Downtime Safe Rename:\n  1. Add new column '${newName}'.\n  2. Dual-write to both '${oldName}' and '${newName}' or create a view.\n  3. Backfill data and migrate application references.\n  4. Deprecate '${oldName}'.`;

      const severity: RiskLevel = this.config.disallowBreakingRenames ? "BLOCKED" : "CAUTION";

      violations.push({
        code: "BREAKING_RENAME",
        statement: sql,
        targetTable: table,
        targetColumn: oldName,
        severity,
        lockType: "ACCESS_EXCLUSIVE",
        message: `Renaming '${oldName}' to '${newName}' on table '${table}' breaks active application queries that reference '${oldName}'.`,
        safeAlternative: alternative,
      });
      safeAlternatives.push(alternative);
    }

    // 6. TABLE_REWRITE_TYPE_CHANGE: Altering column data type
    if (
      upper.includes("ALTER TABLE") &&
      (upper.includes("TYPE ") || upper.includes("SET DATA TYPE"))
    ) {
      const tableMatch = sql.match(/ALTER\s+TABLE\s+(?:ONLY\s+)?([a-zA-Z0-9_."]+)/i);
      const colMatch = sql.match(
        /ALTER\s+(?:COLUMN\s+)?([a-zA-Z0-9_."]+)\s+(?:SET\s+DATA\s+)?TYPE\s+([a-zA-Z0-9_()]+)/i,
      );
      const table = tableMatch ? tableMatch[1].replace(/["`]/g, "") : "target_table";
      const column = colMatch ? colMatch[1].replace(/["`]/g, "") : "column";
      const newType = colMatch ? colMatch[2] : "new_type";

      riskScore = Math.max(riskScore, 70);
      lockType = "ACCESS_EXCLUSIVE";
      const alternative = `Zero-Downtime Type Change:\n  1. Add column '${column}_new' with type ${newType}.\n  2. Dual-write to both columns.\n  3. Backfill existing rows asynchronously.\n  4. Switch application reads to '${column}_new'.`;

      violations.push({
        code: "TABLE_REWRITE_TYPE_CHANGE",
        statement: sql,
        targetTable: table,
        targetColumn: column,
        severity: "CAUTION",
        lockType: "ACCESS_EXCLUSIVE",
        message: `Altering data type of '${column}' in '${table}' requires a full table rewrite holding an AccessExclusiveLock.`,
        safeAlternative: alternative,
      });
      safeAlternatives.push(alternative);
    }

    return {
      violations,
      warnings,
      safeAlternatives,
      riskScore,
      lockType,
    };
  }

  /**
   * Health and schema drift analysis: compares current schemas and finds unindexed foreign keys.
   */
  public analyzeSchemaHealth(
    schemas: TableSchema[],
    expectedSchemas?: TableSchema[],
  ): SchemaDriftReport {
    const differences: SchemaDriftDifference[] = [];
    const unindexedForeignKeys: SchemaDriftReport["unindexedForeignKeys"] = [];

    // 1. Audit unindexed foreign keys (critical performance lock guard)
    for (const schema of schemas) {
      for (const fk of schema.foreignKeys) {
        const isIndexed = schema.indexes.some((idx) => idx.columns.includes(fk.column));
        if (!isIndexed) {
          unindexedForeignKeys.push({
            table: schema.tableName,
            column: fk.column,
            referencedTable: fk.referencedTable,
          });
          differences.push({
            type: "MISSING_INDEX",
            table: schema.tableName,
            column: fk.column,
            recommendation: `Create an index on '${schema.tableName}(${fk.column})' to prevent full table scans during cascade deletes or updates from '${fk.referencedTable}'.`,
          });
        }
      }
    }

    // 2. If expected schemas provided, detect table and column drift
    if (expectedSchemas && expectedSchemas.length > 0) {
      const liveTableMap = new Map<string, TableSchema>(schemas.map((s) => [s.tableName, s]));
      const expectedTableMap = new Map<string, TableSchema>(
        expectedSchemas.map((s) => [s.tableName, s]),
      );

      for (const [tableName, expected] of expectedTableMap.entries()) {
        const live = liveTableMap.get(tableName);
        if (!live) {
          differences.push({
            type: "MISSING_TABLE",
            table: tableName,
            recommendation: `Table '${tableName}' is defined in expected schema but does not exist in live database.`,
          });
          continue;
        }

        const liveColMap = new Map(live.columns.map((c) => [c.name, c]));
        for (const expCol of expected.columns) {
          const liveCol = liveColMap.get(expCol.name);
          if (!liveCol) {
            differences.push({
              type: "MISSING_COLUMN",
              table: tableName,
              column: expCol.name,
              recommendation: `Column '${expCol.name}' is missing on table '${tableName}'.`,
            });
          } else if (
            expCol.type.toLowerCase() !== liveCol.type.toLowerCase() &&
            !areTypesCompatible(expCol.type, liveCol.type)
          ) {
            differences.push({
              type: "TYPE_MISMATCH",
              table: tableName,
              column: expCol.name,
              expected: expCol.type,
              actual: liveCol.type,
              recommendation: `Column '${expCol.name}' type mismatch: expected '${expCol.type}', live is '${liveCol.type}'.`,
            });
          }
        }
      }

      for (const liveTable of schemas) {
        if (!expectedTableMap.has(liveTable.tableName)) {
          differences.push({
            type: "UNEXPECTED_TABLE",
            table: liveTable.tableName,
            recommendation: `Table '${liveTable.tableName}' exists in live database but is not defined in expected schema.`,
          });
        }
      }
    }

    return {
      inSync: differences.length === 0,
      totalTables: schemas.length,
      differences,
      unindexedForeignKeys,
    };
  }
}

function areTypesCompatible(typeA: string, typeB: string): boolean {
  const a = typeA.toLowerCase();
  const b = typeB.toLowerCase();
  if (a === b) return true;
  if ((a.includes("int") && b.includes("int")) || (a.includes("text") && b.includes("varchar"))) {
    return true;
  }
  return false;
}

function splitSqlStatements(sql: string): string[] {
  return sql
    .split(/;(?=(?:(?:[^']*'){2})*[^']*$)(?=(?:(?:[^"]*"){2})*[^"]*$)/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => (s.endsWith(";") ? s : `${s};`));
}

function isHigherLock(
  lockA: MigrationValidationReport["highestLockLevel"],
  lockB: MigrationValidationReport["highestLockLevel"],
): boolean {
  const priority: Record<MigrationValidationReport["highestLockLevel"], number> = {
    NONE: 0,
    SHARE_UPDATE_EXCLUSIVE: 1,
    SHARE: 2,
    ACCESS_EXCLUSIVE: 3,
  };
  return (priority[lockA] || 0) > (priority[lockB] || 0);
}
