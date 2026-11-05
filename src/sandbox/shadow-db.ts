/**
 * Protocol-Level Copy-on-Write Virtual Shadow Database.
 * Unauthorized or destructive mutations execute transparently against isolated
 * shadow layers, returning simulated execution success to the autonomous agent
 * without mutating live database state.
 */

export interface ShadowResult {
  simulated: boolean;
  commandTag: string;
  affectedRows: number;
  executionTimeMs: number;
  syntheticResponsePayload?: Record<string, unknown>[];
  warnings: string[];
}

export class VirtualShadowDatabase {
  private readonly shadowTables = new Map<string, { columns: string[]; rows: Record<string, unknown>[] }>();
  private readonly droppedTables = new Set<string>();

  constructor() {
    // Seed default shadow tables for common enterprise test fixtures
    this.registerTable("users", ["id", "email", "name", "role", "created_at"]);
    this.registerTable("customers", ["id", "company", "balance", "tier"]);
    this.registerTable("orders", ["id", "customer_id", "total", "status"]);
  }

  public registerTable(tableName: string, columns: string[]): void {
    const key = tableName.toLowerCase();
    this.shadowTables.set(key, {
      columns,
      rows: [
        { id: 1, name: "Sample 1", status: "active" },
        { id: 2, name: "Sample 2", status: "active" },
      ],
    });
    this.droppedTables.delete(key);
  }

  /**
   * Determines if a query should be diverted to the virtual shadow layer
   */
  public shouldInterceptToShadow(sql: string): boolean {
    const clean = sql.trim().toUpperCase();
    return (
      clean.startsWith("DROP TABLE") ||
      clean.startsWith("TRUNCATE") ||
      clean.startsWith("ALTER TABLE") ||
      (clean.startsWith("DELETE") && !clean.includes("WHERE")) ||
      (clean.startsWith("UPDATE") && !clean.includes("WHERE"))
    );
  }

  /**
   * Executes unauthorized/destructive query against virtual shadow copy-on-write database
   */
  public executeInShadow(sql: string): ShadowResult {
    const start = performance.now();
    const clean = sql.trim();
    const upper = clean.toUpperCase();
    const warnings: string[] = ["[SHADOW_INTERCEPTED] Destructive query executed inside ephemeral copy-on-write virtual shadow database."];

    if (upper.startsWith("DROP TABLE")) {
      const parts = clean.split(/\s+/);
      const tableName = (parts[2] || "unknown").replace(/;/g, "").toLowerCase();
      this.droppedTables.add(tableName);
      this.shadowTables.delete(tableName);

      return {
        simulated: true,
        commandTag: "DROP TABLE",
        affectedRows: 0,
        executionTimeMs: Math.max(0.1, performance.now() - start),
        warnings,
      };
    }

    if (upper.startsWith("TRUNCATE")) {
      const parts = clean.split(/\s+/);
      const tableName = (parts[1] === "TABLE" ? parts[2] : parts[1] || "unknown").replace(/;/g, "").toLowerCase();
      const tbl = this.shadowTables.get(tableName);
      const rowsCount = tbl ? tbl.rows.length : 10;
      if (tbl) tbl.rows = [];

      return {
        simulated: true,
        commandTag: "TRUNCATE TABLE",
        affectedRows: rowsCount,
        executionTimeMs: Math.max(0.1, performance.now() - start),
        warnings,
      };
    }

    if (upper.startsWith("DELETE")) {
      return {
        simulated: true,
        commandTag: "DELETE 42",
        affectedRows: 42,
        executionTimeMs: Math.max(0.1, performance.now() - start),
        warnings: [...warnings, "[SIMULATED_SUCCESS] Unconstrained DELETE simulated safely without host data loss."],
      };
    }

    if (upper.startsWith("UPDATE")) {
      return {
        simulated: true,
        commandTag: "UPDATE 42",
        affectedRows: 42,
        executionTimeMs: Math.max(0.1, performance.now() - start),
        warnings: [...warnings, "[SIMULATED_SUCCESS] Unconstrained UPDATE simulated safely without host data loss."],
      };
    }

    return {
      simulated: true,
      commandTag: "SELECT 1",
      affectedRows: 1,
      executionTimeMs: Math.max(0.1, performance.now() - start),
      warnings,
    };
  }

  public isTableDropped(tableName: string): boolean {
    return this.droppedTables.has(tableName.toLowerCase());
  }

  public reset(): void {
    this.shadowTables.clear();
    this.droppedTables.clear();
  }
}
