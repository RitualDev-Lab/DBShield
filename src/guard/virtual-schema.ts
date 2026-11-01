import type {
  DatabaseDialect,
  GuardrailViolation,
  TableSchema,
  VirtualSchemaConfig,
} from "../types/index.js";
import { extractTables, parseSql, stripSqlComments } from "./ast.js";

export class VirtualSchemaManager {
  private config: VirtualSchemaConfig;

  constructor(config?: VirtualSchemaConfig) {
    this.config = config || {
      enabled: false,
      hiddenTables: [],
      hiddenColumns: {},
      roles: {},
      defaultRole: "agent",
    };
  }

  public updateConfig(config: VirtualSchemaConfig): void {
    this.config = config;
  }

  public isEnabled(): boolean {
    return this.config.enabled === true;
  }

  /**
   * Converts a wildcard glob pattern (e.g. "admin_*", "*_audit", "secret*") to a RegExp.
   */
  private matchPattern(pattern: string, target: string): boolean {
    const cleanPattern = pattern.trim().toLowerCase();
    const cleanTarget = target.trim().toLowerCase();

    if (cleanPattern === cleanTarget) {
      return true;
    }

    if (cleanPattern.includes("*")) {
      const regexStr = `^${cleanPattern.replace(/[-/\\^$+?.()|[\]{}]/g, "\\$&").replace(/\*/g, ".*")}$`;
      return new RegExp(regexStr, "i").test(cleanTarget);
    }

    return false;
  }

  /**
   * Determine if a table is hidden for a given role (or default role).
   */
  public isTableHidden(tableName: string, role?: string): boolean {
    if (!this.config.enabled) return false;

    const activeRole = role || this.config.defaultRole || "agent";
    const roleConfig = this.config.roles?.[activeRole];

    // If role has an explicit allowedTables whitelist, anything not whitelisted is hidden
    if (roleConfig?.allowedTables && roleConfig.allowedTables.length > 0) {
      const isAllowed = roleConfig.allowedTables.some((p) => this.matchPattern(p, tableName));
      if (!isAllowed) {
        return true;
      }
    }

    // If role has an explicit deniedTables list
    if (roleConfig?.deniedTables && roleConfig.deniedTables.length > 0) {
      if (roleConfig.deniedTables.some((p) => this.matchPattern(p, tableName))) {
        return true;
      }
    }

    // Check global hiddenTables list
    if (this.config.hiddenTables && this.config.hiddenTables.length > 0) {
      if (this.config.hiddenTables.some((p) => this.matchPattern(p, tableName))) {
        return true;
      }
    }

    return false;
  }

  /**
   * Determine if a specific column is hidden for a table and role.
   */
  public isColumnHidden(tableName: string, columnName: string, role?: string): boolean {
    if (!this.config.enabled) return false;

    // If table itself is hidden, all its columns are hidden
    if (this.isTableHidden(tableName, role)) {
      return true;
    }

    const activeRole = role || this.config.defaultRole || "agent";
    const roleConfig = this.config.roles?.[activeRole];
    const cleanCol = columnName.trim().toLowerCase();
    const cleanTbl = tableName.trim().toLowerCase();

    // Check role-specific denied columns
    if (roleConfig?.deniedColumns) {
      for (const [tableKey, deniedCols] of Object.entries(roleConfig.deniedColumns)) {
        if (this.matchPattern(tableKey, cleanTbl)) {
          if (deniedCols.some((c) => this.matchPattern(c, cleanCol))) {
            return true;
          }
        }
      }
    }

    // Check global hiddenColumns
    if (this.config.hiddenColumns) {
      for (const [tableKey, hiddenCols] of Object.entries(this.config.hiddenColumns)) {
        if (this.matchPattern(tableKey, cleanTbl)) {
          if (hiddenCols.some((c) => this.matchPattern(c, cleanCol))) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Filter an array of TableSchemas to hide restricted tables and mask restricted columns.
   */
  public filterTableSchemas(schemas: TableSchema[], role?: string): TableSchema[] {
    if (!this.config.enabled) return schemas;

    const visible: TableSchema[] = [];

    for (const schema of schemas) {
      const filtered = this.filterSingleTableSchema(schema, role);
      if (filtered) {
        visible.push(filtered);
      }
    }

    return visible;
  }

  /**
   * Filter a single TableSchema. Returns null if table is hidden.
   */
  public filterSingleTableSchema(schema: TableSchema, role?: string): TableSchema | null {
    if (!this.config.enabled) return schema;

    if (this.isTableHidden(schema.tableName, role)) {
      return null;
    }

    // Filter columns
    const filteredColumns = schema.columns.filter(
      (col) => !this.isColumnHidden(schema.tableName, col.name, role),
    );

    const visibleColNames = new Set(filteredColumns.map((c) => c.name.toLowerCase()));

    // Filter indexes referencing hidden columns
    const filteredIndexes = schema.indexes
      .map((idx) => ({
        ...idx,
        columns: idx.columns.filter((c) => visibleColNames.has(c.toLowerCase())),
      }))
      .filter((idx) => idx.columns.length > 0);

    // Filter foreign keys referencing hidden columns or hidden tables
    const filteredFks = schema.foreignKeys.filter((fk) => {
      if (!visibleColNames.has(fk.column.toLowerCase())) return false;
      if (this.isTableHidden(fk.referencedTable, role)) return false;
      return true;
    });

    return {
      tableName: schema.tableName,
      columns: filteredColumns,
      indexes: filteredIndexes,
      foreignKeys: filteredFks,
    };
  }

  /**
   * Filters raw introspection query rows (e.g. from information_schema, sqlite_master, pg_tables).
   */
  public filterIntrospectionRows(
    rows: Record<string, unknown>[],
    _dialect: DatabaseDialect = "sqlite",
    role?: string,
  ): Record<string, unknown>[] {
    if (!this.config.enabled || !rows || rows.length === 0) return rows;

    return rows.filter((row) => {
      // Find table name key in row
      const tableKey = Object.keys(row).find((k) =>
        /^(table_name|tablename|name|relname|table)$/i.test(k),
      );
      const tableName = tableKey ? String(row[tableKey] || "") : "";

      if (tableName && this.isTableHidden(tableName, role)) {
        return false;
      }

      // Find column name key in row
      const columnKey = Object.keys(row).find((k) => /^(column_name|columnname|field)$/i.test(k));
      const columnName = columnKey ? String(row[columnKey] || "") : "";

      if (tableName && columnName && this.isColumnHidden(tableName, columnName, role)) {
        return false;
      }

      return true;
    });
  }

  /**
   * Checks whether a SQL query is attempting to introspect system catalog or information_schema.
   */
  public isIntrospectionQuery(sql: string): boolean {
    const clean = stripSqlComments(sql).toLowerCase();
    return (
      clean.includes("information_schema") ||
      clean.includes("sqlite_master") ||
      clean.includes("sqlite_schema") ||
      clean.includes("pg_catalog") ||
      clean.includes("pg_tables") ||
      clean.includes("pg_class") ||
      clean.includes("pragma table_info")
    );
  }

  /**
   * Evaluate a SQL query against Virtual Schema & Column RBAC policies.
   */
  public evaluateAccess(
    sql: string,
    dialect: DatabaseDialect = "sqlite",
    role?: string,
  ): { allowed: boolean; violations: GuardrailViolation[] } {
    if (!this.config.enabled) {
      return { allowed: true, violations: [] };
    }

    const violations: GuardrailViolation[] = [];
    const activeRole = role || this.config.defaultRole || "agent";

    // Extract target tables
    let targetTables: string[] = [];
    try {
      const parsed = parseSql(sql, dialect);
      if (parsed.statements.length > 0) {
        for (const stmt of parsed.statements) {
          targetTables.push(...stmt.targetTables);
        }
      }
    } catch {
      // Fallback table extraction regex
      const matches = sql.matchAll(/(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+["`]?([a-zA-Z0-9_]+)["`]?/gi);
      for (const m of matches) {
        if (m[1]) targetTables.push(m[1]);
      }
    }

    targetTables = Array.from(new Set(targetTables));

    // 1. Check table-level access
    for (const tbl of targetTables) {
      if (this.isTableHidden(tbl, activeRole)) {
        violations.push({
          code: "RBAC_TABLE_ACCESS_DENIED",
          message: `Access to table '${tbl}' is denied under role '${activeRole}' by virtual schema RBAC policy.`,
          severity: "CRITICAL",
          suggestion: `Table '${tbl}' is masked or does not exist in the virtual schema view for role '${activeRole}'.`,
        });
      }
    }

    // 2. Check column-level access across visible tables
    for (const tbl of targetTables) {
      if (this.isTableHidden(tbl, activeRole)) continue;

      // Extract referenced columns for this table from SQL
      const hiddenCols = this.getHiddenColumnsForTable(tbl, activeRole);
      for (const col of hiddenCols) {
        // Regex word boundary check for column presence in SQL
        const colRegex = new RegExp(`(?:\\b${tbl}\\b\\.)?\\b${col}\\b`, "i");
        if (colRegex.test(sql)) {
          violations.push({
            code: "RBAC_COLUMN_ACCESS_DENIED",
            message: `Access to column '${col}' on table '${tbl}' is denied under role '${activeRole}' by column-level RBAC policy.`,
            severity: "CRITICAL",
            suggestion: `Omit restricted column '${col}' from query projections, filters, and mutations.`,
          });
        }
      }
    }

    return {
      allowed: violations.length === 0,
      violations,
    };
  }

  private getHiddenColumnsForTable(tableName: string, role?: string): string[] {
    const hidden: string[] = [];
    const activeRole = role || this.config.defaultRole || "agent";
    const roleConfig = this.config.roles?.[activeRole];

    if (this.config.hiddenColumns) {
      for (const [t, cols] of Object.entries(this.config.hiddenColumns)) {
        if (this.matchPattern(t, tableName)) {
          hidden.push(...cols);
        }
      }
    }

    if (roleConfig?.deniedColumns) {
      for (const [t, cols] of Object.entries(roleConfig.deniedColumns)) {
        if (this.matchPattern(t, tableName)) {
          hidden.push(...cols);
        }
      }
    }

    return Array.from(new Set(hidden));
  }
}
