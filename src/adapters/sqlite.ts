import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { stripSqlComments } from "../guard/ast.js";
import type {
  ColumnDefinition,
  DatabaseAdapter,
  DatabaseDialect,
  DryRunResult,
  ForeignKeyDefinition,
  IndexDefinition,
  QueryResult,
  TableSchema,
} from "../types/index.js";

type SqliteParam = string | number | bigint | null | Uint8Array;

export class SqliteAdapter implements DatabaseAdapter {
  public readonly dialect: DatabaseDialect = "sqlite";
  private db: DatabaseSync | null = null;
  private readonly storagePath: string;
  private readonly defaultMaxRows: number;

  constructor(storagePath = ":memory:", defaultMaxRows = 500) {
    this.storagePath = storagePath;
    this.defaultMaxRows = defaultMaxRows;
  }

  async connect(): Promise<void> {
    if (!this.db) {
      this.db = new DatabaseSync(this.storagePath);
    }
  }

  async disconnect(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  private ensureConnected(): DatabaseSync {
    if (!this.db) {
      this.db = new DatabaseSync(this.storagePath);
    }
    return this.db;
  }

  async query(
    sql: string,
    params: unknown[] = [],
    options?: { maxRows?: number },
  ): Promise<QueryResult> {
    const db = this.ensureConnected();
    const startTime = performance.now();
    const auditId = randomUUID();

    const stripped = stripSqlComments(sql);
    if (!stripped) {
      return {
        rows: [],
        rowCount: 0,
        columns: [],
        executionTimeMs: 0,
        redactedColumns: [],
        auditId,
      };
    }

    const stmt = db.prepare(sql);
    let isRowReturning = false;
    let cols: Array<{ name: string }> = [];

    try {
      cols = stmt.columns() as Array<{ name: string }>;
      isRowReturning = cols.length > 0;
    } catch {
      // Handled as non-row-returning / finalized command
      isRowReturning = false;
    }

    if (isRowReturning) {
      const maxRows = options?.maxRows ?? this.defaultMaxRows ?? 500;
      const rows: Record<string, unknown>[] = [];
      let isTruncated = false;

      // Stream rows using stmt.iterate() to avoid materializing unbounded rows in memory
      const iterator = stmt.iterate(...(params as SqliteParam[])) as IterableIterator<
        Record<string, unknown>
      >;
      for (const row of iterator) {
        if (rows.length < maxRows) {
          rows.push(row);
        } else {
          isTruncated = true;
          break;
        }
      }

      const executionTimeMs = Number((performance.now() - startTime).toFixed(2));
      const columns = rows.length > 0 ? Object.keys(rows[0]) : cols.map((c) => c.name);

      return {
        rows,
        rowCount: rows.length,
        columns,
        executionTimeMs,
        redactedColumns: [],
        auditId,
        meta: {
          totalReturned: rows.length,
          isTruncated,
          maxAllowedRows: maxRows,
          hasMore: isTruncated,
          ...(isTruncated
            ? {
                warning: `Query results were capped at ${maxRows} rows to prevent memory exhaustion and context window bloat. Use LIMIT and OFFSET to paginate.`,
              }
            : {}),
        },
      };
    }

    // Mutation or DDL
    const result = stmt.run(...(params as SqliteParam[]));
    const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

    return {
      rows: [],
      rowCount: Number(result.changes || 0),
      columns: [],
      executionTimeMs,
      redactedColumns: [],
      auditId,
    };
  }

  async executeDryRun(sql: string, params: unknown[] = []): Promise<DryRunResult> {
    const db = this.ensureConnected();
    const startTime = performance.now();
    const warnings: string[] = [];

    let affectedRows = 0;
    let rollbackVerified = false;

    db.exec("BEGIN TRANSACTION;");
    try {
      const stmt = db.prepare(sql);
      const res = stmt.run(...(params as SqliteParam[]));
      affectedRows = Number(res.changes || 0);

      // Verify transaction rollback
      db.exec("ROLLBACK;");
      rollbackVerified = true;
    } catch (error) {
      try {
        db.exec("ROLLBACK;");
      } catch {
        // Already rolled back or failed before begin
      }
      warnings.push(`Dry-run execution failed: ${(error as Error).message}`);
      return {
        safe: false,
        simulatedAffectedRows: 0,
        targetTables: [],
        executionTimeMs: Number((performance.now() - startTime).toFixed(2)),
        warnings,
        rollbackVerified: false,
      };
    }

    const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

    return {
      safe: true,
      simulatedAffectedRows: affectedRows,
      targetTables: [],
      executionTimeMs,
      warnings,
      rollbackVerified,
    };
  }

  async executeCommit(sql: string, params: unknown[] = []): Promise<QueryResult> {
    const db = this.ensureConnected();
    const startTime = performance.now();
    const auditId = randomUUID();

    db.exec("BEGIN TRANSACTION;");
    try {
      const stmt = db.prepare(sql);
      const res = stmt.run(...(params as SqliteParam[]));
      db.exec("COMMIT;");

      const executionTimeMs = Number((performance.now() - startTime).toFixed(2));
      return {
        rows: [],
        rowCount: Number(res.changes || 0),
        columns: [],
        executionTimeMs,
        redactedColumns: [],
        auditId,
      };
    } catch (err) {
      try {
        db.exec("ROLLBACK;");
      } catch {
        // Rollback on failure
      }
      throw err;
    }
  }

  async getSchema(): Promise<TableSchema[]> {
    const db = this.ensureConnected();
    const tablesQuery = `
      SELECT name FROM sqlite_schema 
      WHERE type='table' AND name NOT LIKE 'sqlite_%';
    `;
    const tableRows = db.prepare(tablesQuery).all() as Array<{ name: string }>;
    const schemas: TableSchema[] = [];

    for (const row of tableRows) {
      const schema = await this.getTableSchema(row.name);
      if (schema) {
        schemas.push(schema);
      }
    }

    return schemas;
  }

  async getTableSchema(tableName: string): Promise<TableSchema | null> {
    const db = this.ensureConnected();
    const safeName = tableName.replace(/[^a-zA-Z0-9_]/g, "");

    try {
      const colRows = db.prepare(`PRAGMA table_info("${safeName}")`).all() as Array<{
        cid: number;
        name: string;
        type: string;
        notnull: number;
        dflt_value: string | null;
        pk: number;
      }>;

      if (!colRows || colRows.length === 0) {
        return null;
      }

      const columns: ColumnDefinition[] = colRows.map((c) => ({
        name: c.name,
        type: c.type,
        nullable: c.notnull === 0,
        primaryKey: c.pk > 0,
        defaultValue: c.dflt_value,
      }));

      const fkRows = db.prepare(`PRAGMA foreign_key_list("${safeName}")`).all() as Array<{
        from: string;
        table: string;
        to: string;
      }>;

      const foreignKeys: ForeignKeyDefinition[] = fkRows.map((f) => ({
        column: f.from,
        referencedTable: f.table,
        referencedColumn: f.to,
      }));

      const idxRows = db.prepare(`PRAGMA index_list("${safeName}")`).all() as Array<{
        name: string;
        unique: number;
      }>;

      const indexes: IndexDefinition[] = [];
      for (const idx of idxRows) {
        const safeIdxName = idx.name.replace(/[^a-zA-Z0-9_]/g, "");
        const idxCols = db.prepare(`PRAGMA index_info("${safeIdxName}")`).all() as Array<{
          name: string;
        }>;
        indexes.push({
          name: idx.name,
          unique: idx.unique === 1,
          columns: idxCols.map((ic) => ic.name),
        });
      }

      return {
        tableName: safeName,
        columns,
        foreignKeys,
        indexes,
      };
    } catch {
      return null;
    }
  }
}
