import { randomUUID } from "node:crypto";
import pg from "pg";
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

const { Pool } = pg;

export interface PostgresAdapterOptions {
  connectionString?: string;
  host?: string;
  port?: number;
  user?: string;
  password?: string;
  database?: string;
  ssl?: pg.PoolConfig["ssl"];
  maxConnections?: number;
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
  defaultMaxRows?: number;
  defaultMaxMutationRows?: number;
  statementTimeoutMs?: number;
}

export class PostgresAdapter implements DatabaseAdapter {
  public readonly dialect: DatabaseDialect = "postgres";
  private pool: pg.Pool | null = null;
  private readonly config: pg.PoolConfig;
  private readonly defaultMaxRows: number;
  private readonly defaultMaxMutationRows: number;
  private readonly statementTimeoutMs: number;

  constructor(
    connection: string | PostgresAdapterOptions = "postgres://localhost:5432/postgres",
    defaultMaxRows = 500,
    defaultMaxMutationRows = 50,
    statementTimeoutMs = 5000,
  ) {
    this.defaultMaxRows = defaultMaxRows;
    this.defaultMaxMutationRows = defaultMaxMutationRows;
    this.statementTimeoutMs = statementTimeoutMs;

    if (typeof connection === "string") {
      const isCloud =
        connection.includes("sslmode=require") ||
        connection.includes("neon.tech") ||
        connection.includes("supabase.co") ||
        connection.includes("render.com") ||
        connection.includes("amazonaws.com");

      this.config = {
        connectionString: connection,
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
        ...(isCloud ? { ssl: { rejectUnauthorized: false } } : {}),
      };
    } else {
      const {
        defaultMaxRows: optMaxRows,
        defaultMaxMutationRows: optMaxMutation,
        statementTimeoutMs: optTimeout,
        ...poolConfig
      } = connection;

      if (optMaxRows !== undefined) this.defaultMaxRows = optMaxRows;
      if (optMaxMutation !== undefined) this.defaultMaxMutationRows = optMaxMutation;
      if (optTimeout !== undefined) this.statementTimeoutMs = optTimeout;

      this.config = {
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
        ...poolConfig,
      };
    }
  }

  /**
   * Inject an existing Pool instance (primarily for mocking / unit tests)
   */
  public setPool(customPool: pg.Pool): void {
    this.pool = customPool;
  }

  public getPool(): pg.Pool {
    if (!this.pool) {
      this.pool = new Pool(this.config);
    }
    return this.pool;
  }

  async connect(): Promise<void> {
    const pool = this.getPool();
    // Verify connectivity by borrowing and releasing a client
    const client = await pool.connect();
    try {
      await client.query("SELECT 1 AS healthcheck;");
    } finally {
      client.release();
    }
  }

  async disconnect(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }
  }

  async query(
    sql: string,
    params: unknown[] = [],
    options?: { maxRows?: number; maxMutationRows?: number; timeoutMs?: number },
  ): Promise<QueryResult> {
    const pool = this.getPool();
    const startTime = performance.now();
    const auditId = randomUUID();
    const timeoutMs = options?.timeoutMs ?? this.statementTimeoutMs ?? 5000;

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

    const upper = stripped.trim().toUpperCase();
    const isRowReturningCandidate =
      upper.startsWith("SELECT") ||
      upper.startsWith("WITH") ||
      upper.startsWith("SHOW") ||
      upper.startsWith("EXPLAIN") ||
      upper.includes("RETURNING");

    if (isRowReturningCandidate) {
      const maxRows = options?.maxRows ?? this.defaultMaxRows ?? 500;
      let timer: NodeJS.Timeout | undefined;
      let result: pg.QueryResult;

      try {
        const queryPromise = pool.query(sql, params);
        const timeoutPromise = new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            reject(
              new Error(
                `[QUERY_TIMEOUT_EXCEEDED] Query execution exceeded the hard limit of ${timeoutMs}ms and was terminated to protect database stability.`,
              ),
            );
          }, timeoutMs);
        });

        result = await Promise.race([queryPromise, timeoutPromise]);
      } catch (err) {
        if (
          (err as { code?: string }).code === "57014" ||
          (err as Error).message?.includes("canceling statement due to statement timeout") ||
          (err as Error).message?.includes("[QUERY_TIMEOUT_EXCEEDED]")
        ) {
          throw new Error(
            `[QUERY_TIMEOUT_EXCEEDED] Query execution exceeded the hard limit of ${timeoutMs}ms and was terminated to protect database stability.`,
          );
        }
        throw err;
      } finally {
        if (timer) clearTimeout(timer);
      }

      const columns = result.fields ? result.fields.map((f) => f.name) : [];
      let rows = result.rows as Record<string, unknown>[];
      let isTruncated = false;

      if (rows.length > maxRows) {
        rows = rows.slice(0, maxRows);
        isTruncated = true;
      }

      const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

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

    // Mutation or DDL: Enforce transactional execution and row ceiling
    const maxMutationRows = options?.maxMutationRows ?? this.defaultMaxMutationRows ?? 50;
    const client = await pool.connect();
    let mutationTimer: NodeJS.Timeout | undefined;

    await client.query("BEGIN;");
    try {
      const queryPromise = client.query(sql, params);
      const timeoutPromise = new Promise<never>((_, reject) => {
        mutationTimer = setTimeout(() => {
          reject(
            new Error(
              `[QUERY_TIMEOUT_EXCEEDED] Query execution exceeded the hard limit of ${timeoutMs}ms and was terminated to protect database stability.`,
            ),
          );
        }, timeoutMs);
      });

      const result = await Promise.race([queryPromise, timeoutPromise]);
      const changes = Number(result.rowCount || 0);

      if (changes > maxMutationRows) {
        await client.query("ROLLBACK;");
        throw new Error(
          `[MUTATION_LIMIT_EXCEEDED] Mutation affected ${changes} rows, exceeding the hard safety limit of ${maxMutationRows} rows. Transaction rolled back.`,
        );
      }

      await client.query("COMMIT;");
      const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

      return {
        rows: [],
        rowCount: changes,
        columns: [],
        executionTimeMs,
        redactedColumns: [],
        auditId,
      };
    } catch (err) {
      try {
        await client.query("ROLLBACK;");
      } catch {
        // Rollback on failure
      }
      if (
        (err as { code?: string }).code === "57014" ||
        (err as Error).message?.includes("canceling statement due to statement timeout") ||
        (err as Error).message?.includes("[QUERY_TIMEOUT_EXCEEDED]")
      ) {
        throw new Error(
          `[QUERY_TIMEOUT_EXCEEDED] Query execution exceeded the hard limit of ${timeoutMs}ms and was terminated to protect database stability.`,
        );
      }
      throw err;
    } finally {
      if (mutationTimer) clearTimeout(mutationTimer);
      client.release();
    }
  }

  async executeDryRun(sql: string, params: unknown[] = []): Promise<DryRunResult> {
    const pool = this.getPool();
    const startTime = performance.now();
    const warnings: string[] = [];

    let affectedRows = 0;
    let rollbackVerified = false;

    const client = await pool.connect();

    await client.query("BEGIN;");
    try {
      const res = await client.query(sql, params);
      affectedRows = Number(res.rowCount || 0);

      // Verify transaction rollback
      await client.query("ROLLBACK;");
      rollbackVerified = true;
    } catch (error) {
      try {
        await client.query("ROLLBACK;");
      } catch {
        // Rollback failed or already rolled back
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
    } finally {
      client.release();
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

  async executeCommit(
    sql: string,
    params: unknown[] = [],
    options?: { maxRows?: number; expectedRows?: number },
  ): Promise<QueryResult> {
    const pool = this.getPool();
    const startTime = performance.now();
    const auditId = randomUUID();
    const maxRows = options?.maxRows ?? this.defaultMaxMutationRows ?? 50;

    const client = await pool.connect();

    await client.query("BEGIN;");
    try {
      const res = await client.query(sql, params);
      const changes = Number(res.rowCount || 0);

      if (changes > maxRows) {
        await client.query("ROLLBACK;");
        throw new Error(
          `[MUTATION_LIMIT_EXCEEDED] Mutation affected ${changes} rows, exceeding the authorized limit of ${maxRows} rows. Transaction rolled back.`,
        );
      }

      if (options?.expectedRows !== undefined && changes !== options.expectedRows) {
        await client.query("ROLLBACK;");
        throw new Error(
          `[SIMULATION_DELTA_DRIFT] Data changed between simulation and commit. Simulated affected rows was ${options.expectedRows}, but actual commit would affect ${changes} rows. Transaction rolled back for safety.`,
        );
      }

      await client.query("COMMIT;");

      const executionTimeMs = Number((performance.now() - startTime).toFixed(2));
      return {
        rows: [],
        rowCount: changes,
        columns: [],
        executionTimeMs,
        redactedColumns: [],
        auditId,
      };
    } catch (err) {
      try {
        await client.query("ROLLBACK;");
      } catch {
        // Rollback failed or already rolled back
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async getSchema(): Promise<TableSchema[]> {
    const pool = this.getPool();
    const tablesQuery = `
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
        AND table_type = 'BASE TABLE'
      ORDER BY table_name;
    `;

    const res = await pool.query(tablesQuery);
    const schemas: TableSchema[] = [];

    for (const row of res.rows) {
      const tableName = String(row.table_name);
      const schema = await this.getTableSchema(tableName);
      if (schema) {
        schemas.push(schema);
      }
    }

    return schemas;
  }

  async getTableSchema(tableName: string): Promise<TableSchema | null> {
    const pool = this.getPool();
    const safeName = tableName.replace(/[^a-zA-Z0-9_]/g, "");

    try {
      // 1. Fetch column definitions
      const colQuery = `
        SELECT 
          c.column_name, 
          c.data_type, 
          c.is_nullable, 
          c.column_default,
          CASE WHEN pk.column_name IS NOT NULL THEN true ELSE false END AS is_primary_key
        FROM information_schema.columns c
        LEFT JOIN (
          SELECT kcu.column_name
          FROM information_schema.table_constraints tc
          JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
          WHERE tc.constraint_type = 'PRIMARY KEY'
            AND tc.table_schema = 'public'
            AND tc.table_name = $1
        ) pk ON c.column_name = pk.column_name
        WHERE c.table_schema = 'public' 
          AND c.table_name = $1
        ORDER BY c.ordinal_position;
      `;

      const colRes = await pool.query(colQuery, [safeName]);
      if (!colRes.rows || colRes.rows.length === 0) {
        return null;
      }

      const columns: ColumnDefinition[] = colRes.rows.map((c) => ({
        name: String(c.column_name),
        type: String(c.data_type),
        nullable: c.is_nullable === "YES",
        primaryKey: Boolean(c.is_primary_key),
        defaultValue: c.column_default !== null ? String(c.column_default) : undefined,
      }));

      // 2. Fetch foreign keys
      const fkQuery = `
        SELECT
          kcu.column_name,
          ccu.table_name AS foreign_table_name,
          ccu.column_name AS foreign_column_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
          AND tc.table_schema = kcu.table_schema
        JOIN information_schema.constraint_column_usage AS ccu
          ON ccu.constraint_name = tc.constraint_name
          AND ccu.table_schema = tc.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY'
          AND tc.table_schema = 'public'
          AND tc.table_name = $1;
      `;

      const fkRes = await pool.query(fkQuery, [safeName]);
      const foreignKeys: ForeignKeyDefinition[] = fkRes.rows.map((f) => ({
        column: String(f.column_name),
        referencedTable: String(f.foreign_table_name),
        referencedColumn: String(f.foreign_column_name),
      }));

      // 3. Fetch indexes
      const idxQuery = `
        SELECT
          indexname,
          indexdef
        FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = $1;
      `;

      const idxRes = await pool.query(idxQuery, [safeName]);
      const indexes: IndexDefinition[] = idxRes.rows.map((i) => {
        const indexName = String(i.indexname);
        const indexDef = String(i.indexdef);
        const isUnique = indexDef.toUpperCase().includes("UNIQUE INDEX");

        // Parse column names from index definition (e.g., "CREATE INDEX ... ON table USING btree (col1, col2)")
        const match = indexDef.match(/\(([^)]+)\)$/);
        const indexCols = match ? match[1].split(",").map((c) => c.trim().replace(/"/g, "")) : [];

        return {
          name: indexName,
          unique: isUnique,
          columns: indexCols,
        };
      });

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
