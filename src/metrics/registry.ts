export type MetricType = "counter" | "gauge" | "histogram";

export interface MetricLabels {
  [key: string]: string | number | undefined;
}

export class Counter {
  private values: Map<string, number> = new Map();

  constructor(
    public readonly name: string,
    public readonly help: string,
  ) {}

  private getLabelKey(labels?: MetricLabels): string {
    if (!labels || Object.keys(labels).length === 0) return "";
    return Object.entries(labels)
      .filter(([_, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${v}"`)
      .join(",");
  }

  public inc(labels?: MetricLabels, value = 1): void {
    const key = this.getLabelKey(labels);
    const current = this.values.get(key) ?? 0;
    this.values.set(key, current + value);
  }

  public get(labels?: MetricLabels): number {
    const key = this.getLabelKey(labels);
    return this.values.get(key) ?? 0;
  }

  public serialize(): string {
    const lines: string[] = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} counter`];

    if (this.values.size === 0) {
      lines.push(`${this.name} 0`);
    } else {
      for (const [labels, val] of this.values.entries()) {
        const labelPart = labels ? `{${labels}}` : "";
        lines.push(`${this.name}${labelPart} ${val}`);
      }
    }

    return lines.join("\n");
  }
}

export class Gauge {
  private values: Map<string, number> = new Map();

  constructor(
    public readonly name: string,
    public readonly help: string,
  ) {}

  private getLabelKey(labels?: MetricLabels): string {
    if (!labels || Object.keys(labels).length === 0) return "";
    return Object.entries(labels)
      .filter(([_, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${v}"`)
      .join(",");
  }

  public set(value: number, labels?: MetricLabels): void {
    const key = this.getLabelKey(labels);
    this.values.set(key, value);
  }

  public inc(labels?: MetricLabels, value = 1): void {
    const key = this.getLabelKey(labels);
    const current = this.values.get(key) ?? 0;
    this.values.set(key, current + value);
  }

  public dec(labels?: MetricLabels, value = 1): void {
    const key = this.getLabelKey(labels);
    const current = this.values.get(key) ?? 0;
    this.values.set(key, Math.max(0, current - value));
  }

  public get(labels?: MetricLabels): number {
    const key = this.getLabelKey(labels);
    return this.values.get(key) ?? 0;
  }

  public serialize(): string {
    const lines: string[] = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} gauge`];

    if (this.values.size === 0) {
      lines.push(`${this.name} 0`);
    } else {
      for (const [labels, val] of this.values.entries()) {
        const labelPart = labels ? `{${labels}}` : "";
        lines.push(`${this.name}${labelPart} ${val}`);
      }
    }

    return lines.join("\n");
  }
}

export class Histogram {
  private buckets: number[];
  private counts: Map<string, { bucketCounts: number[]; sum: number; count: number }> = new Map();

  constructor(
    public readonly name: string,
    public readonly help: string,
    buckets = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  ) {
    this.buckets = [...buckets].sort((a, b) => a - b);
  }

  private getLabelKey(labels?: MetricLabels): string {
    if (!labels || Object.keys(labels).length === 0) return "";
    return Object.entries(labels)
      .filter(([_, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${v}"`)
      .join(",");
  }

  public observe(value: number, labels?: MetricLabels): void {
    const key = this.getLabelKey(labels);
    let entry = this.counts.get(key);

    if (!entry) {
      entry = {
        bucketCounts: new Array(this.buckets.length).fill(0),
        sum: 0,
        count: 0,
      };
      this.counts.set(key, entry);
    }

    entry.count++;
    entry.sum += value;

    for (let i = 0; i < this.buckets.length; i++) {
      if (value <= this.buckets[i]) {
        entry.bucketCounts[i]++;
      }
    }
  }

  public serialize(): string {
    const lines: string[] = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} histogram`];

    if (this.counts.size === 0) {
      for (const le of this.buckets) {
        lines.push(`${this.name}_bucket{le="${le}"} 0`);
      }
      lines.push(`${this.name}_bucket{le="+Inf"} 0`);
      lines.push(`${this.name}_sum 0`);
      lines.push(`${this.name}_count 0`);
    } else {
      for (const [labels, data] of this.counts.entries()) {
        const baseLabels = labels ? `${labels},` : "";

        for (let i = 0; i < this.buckets.length; i++) {
          lines.push(
            `${this.name}_bucket{${baseLabels}le="${this.buckets[i]}"} ${data.bucketCounts[i]}`,
          );
        }
        lines.push(`${this.name}_bucket{${baseLabels}le="+Inf"} ${data.count}`);
        lines.push(`${this.name}_sum${labels ? `{${labels}}` : ""} ${data.sum.toFixed(6)}`);
        lines.push(`${this.name}_count${labels ? `{${labels}}` : ""} ${data.count}`);
      }
    }

    return lines.join("\n");
  }
}

export class MetricsRegistry {
  public readonly up: Gauge;
  public readonly connectionsActive: Gauge;
  public readonly connectionsTotal: Counter;
  public readonly queriesTotal: Counter;
  public readonly queriesBlockedTotal: Counter;
  public readonly queryDurationSeconds: Histogram;
  public readonly costSavingsDollarsTotal: Counter;
  public readonly piiRedactedFieldsTotal: Counter;

  constructor() {
    this.up = new Gauge(
      "dbshield_up",
      "Indicates whether DBShield proxy is healthy and operational (1 = up)",
    );
    this.up.set(1);

    this.connectionsActive = new Gauge(
      "dbshield_connections_active",
      "Current number of active client TCP connections to DBShield",
    );

    this.connectionsTotal = new Counter(
      "dbshield_connections_total",
      "Cumulative total of client connections established",
    );

    this.queriesTotal = new Counter(
      "dbshield_queries_total",
      "Total number of database queries processed by DBShield",
    );

    this.queriesBlockedTotal = new Counter(
      "dbshield_queries_blocked_total",
      "Total number of dangerous queries intercepted and prevented by DBShield",
    );

    this.queryDurationSeconds = new Histogram(
      "dbshield_query_duration_seconds",
      "Query processing and inspection duration in seconds",
      [0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
    );

    this.costSavingsDollarsTotal = new Counter(
      "dbshield_cost_savings_dollars_total",
      "Estimated cloud database dollars saved by terminating runaway and unindexed queries",
    );

    this.piiRedactedFieldsTotal = new Counter(
      "dbshield_pii_redacted_fields_total",
      "Total number of sensitive PII columns/literals redacted on the wire",
    );
  }

  /**
   * Serializes all registered metrics into standard Prometheus exposition format.
   */
  public toPrometheus(): string {
    return [
      this.up.serialize(),
      this.connectionsActive.serialize(),
      this.connectionsTotal.serialize(),
      this.queriesTotal.serialize(),
      this.queriesBlockedTotal.serialize(),
      this.queryDurationSeconds.serialize(),
      this.costSavingsDollarsTotal.serialize(),
      this.piiRedactedFieldsTotal.serialize(),
    ].join("\n\n");
  }
}

// Global default singleton registry
let defaultRegistry: MetricsRegistry | null = null;

export function getGlobalMetrics(): MetricsRegistry {
  if (!defaultRegistry) {
    defaultRegistry = new MetricsRegistry();
  }
  return defaultRegistry;
}
