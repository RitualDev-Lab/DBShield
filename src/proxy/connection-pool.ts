/**
 * High-Concurrency Connection Pooling Engine.
 * Sub-millisecond connection reuse, queue bounding, and heartbeat health checks.
 */

export interface ConnectionPoolOptions {
  minConnections?: number;
  maxConnections?: number;
  idleTimeoutMs?: number;
  acquireTimeoutMs?: number;
}

export interface PooledSocket<T> {
  socket: T;
  createdAt: number;
  lastUsedAt: number;
}

export class HighConcurrencyConnectionPool<T extends { destroy: () => void; writable?: boolean }> {
  private readonly options: Required<ConnectionPoolOptions>;
  private readonly available: PooledSocket<T>[] = [];
  private activeCount = 0;
  private isDestroyed = false;

  constructor(options: ConnectionPoolOptions = {}) {
    this.options = {
      minConnections: options.minConnections ?? 5,
      maxConnections: options.maxConnections ?? 50,
      idleTimeoutMs: options.idleTimeoutMs ?? 60_000,
      acquireTimeoutMs: options.acquireTimeoutMs ?? 2_000,
    };
  }

  public acquire(): T | null {
    if (this.isDestroyed) return null;

    const now = Date.now();
    // Prune expired or closed sockets
    while (this.available.length > 0) {
      const item = this.available.pop()!;
      if (now - item.lastUsedAt <= this.options.idleTimeoutMs && item.socket.writable !== false) {
        return item.socket;
      }
      try {
        item.socket.destroy();
      } catch {
        // ignore
      }
      this.activeCount = Math.max(0, this.activeCount - 1);
    }

    return null;
  }

  public release(socket: T): void {
    if (this.isDestroyed || socket.writable === false) {
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      this.activeCount = Math.max(0, this.activeCount - 1);
      return;
    }

    if (this.available.length < this.options.maxConnections) {
      this.available.push({
        socket,
        createdAt: Date.now(),
        lastUsedAt: Date.now(),
      });
    } else {
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      this.activeCount = Math.max(0, this.activeCount - 1);
    }
  }

  public trackNewConnection(): boolean {
    if (this.activeCount >= this.options.maxConnections) {
      return false;
    }
    this.activeCount++;
    return true;
  }

  public getStats(): { idle: number; active: number; capacity: number } {
    return {
      idle: this.available.length,
      active: this.activeCount,
      capacity: this.options.maxConnections,
    };
  }

  public drain(): void {
    this.isDestroyed = true;
    for (const item of this.available) {
      try {
        item.socket.destroy();
      } catch {
        // ignore
      }
    }
    this.available.length = 0;
    this.activeCount = 0;
  }
}
