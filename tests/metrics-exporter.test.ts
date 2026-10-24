import assert from "node:assert/strict";
import test from "node:test";
import {
  Counter,
  Gauge,
  Histogram,
  MetricsRegistry,
  MetricsServer,
  getGlobalMetrics,
} from "../src/metrics/index.js";

test("Metrics - Counter tracks counts and generates Prometheus format", () => {
  const counter = new Counter("test_requests_total", "Total requests received");
  assert.equal(counter.get(), 0);

  counter.inc();
  assert.equal(counter.get(), 1);

  counter.inc({ status: "success", method: "GET" }, 5);
  assert.equal(counter.get({ status: "success", method: "GET" }), 5);

  const serialized = counter.serialize();
  assert.ok(serialized.includes("# HELP test_requests_total Total requests received"));
  assert.ok(serialized.includes("# TYPE test_requests_total counter"));
  assert.ok(serialized.includes('test_requests_total{method="GET",status="success"} 5'));
});

test("Metrics - Gauge tracks dynamic gauges with inc, dec, and set", () => {
  const gauge = new Gauge("test_active_workers", "Active worker threads");
  assert.equal(gauge.get(), 0);

  gauge.set(10);
  assert.equal(gauge.get(), 10);

  gauge.inc(undefined, 2);
  assert.equal(gauge.get(), 12);

  gauge.dec(undefined, 5);
  assert.equal(gauge.get(), 7);

  const serialized = gauge.serialize();
  assert.ok(serialized.includes("# TYPE test_active_workers gauge"));
  assert.ok(serialized.includes("test_active_workers 7"));
});

test("Metrics - Histogram observes distributions and computes cumulative buckets", () => {
  const hist = new Histogram(
    "test_latency_seconds",
    "Latency histogram",
    [0.01, 0.05, 0.1, 0.5, 1.0],
  );

  hist.observe(0.005, { handler: "query" });
  hist.observe(0.04, { handler: "query" });
  hist.observe(0.2, { handler: "query" });

  const serialized = hist.serialize();
  assert.ok(serialized.includes("# TYPE test_latency_seconds histogram"));
  assert.ok(serialized.includes('test_latency_seconds_bucket{handler="query",le="0.01"} 1'));
  assert.ok(serialized.includes('test_latency_seconds_bucket{handler="query",le="0.05"} 2'));
  assert.ok(serialized.includes('test_latency_seconds_bucket{handler="query",le="0.5"} 3'));
  assert.ok(serialized.includes('test_latency_seconds_bucket{handler="query",le="+Inf"} 3'));
  assert.ok(serialized.includes('test_latency_seconds_count{handler="query"} 3'));
});

test("Metrics - MetricsRegistry integrates core DBShield metrics", () => {
  const reg = new MetricsRegistry();

  reg.connectionsActive.inc();
  reg.queriesTotal.inc({ status: "allowed", safety_tier: "BALANCED" }, 10);
  reg.queriesBlockedTotal.inc({ rule: "DDL_DROP", severity: "CRITICAL" }, 2);
  reg.costSavingsDollarsTotal.inc(undefined, 250);

  const promOutput = reg.toPrometheus();
  assert.ok(promOutput.includes("dbshield_up 1"));
  assert.ok(promOutput.includes("dbshield_connections_active 1"));
  assert.ok(
    promOutput.includes('dbshield_queries_total{safety_tier="BALANCED",status="allowed"} 10'),
  );
  assert.ok(
    promOutput.includes('dbshield_queries_blocked_total{rule="DDL_DROP",severity="CRITICAL"} 2'),
  );
  assert.ok(promOutput.includes("dbshield_cost_savings_dollars_total 250"));
});

test("MetricsServer - Exposes Prometheus /metrics and Kubernetes /healthz /ready endpoints", async () => {
  const reg = new MetricsRegistry();
  reg.queriesTotal.inc({ status: "allowed" }, 42);

  const server = new MetricsServer({
    port: 0,
    host: "127.0.0.1",
    registry: reg,
    version: "0.2.0",
    proxyInfo: {
      listenPort: 5433,
      upstreamHost: "127.0.0.1",
      upstreamPort: 5432,
      safetyTier: "BALANCED",
    },
  });

  const port = await server.start();

  try {
    // 1. Test /healthz
    const resHealth = await fetch(`http://127.0.0.1:${port}/healthz`);
    assert.equal(resHealth.status, 200);
    const healthJson = (await resHealth.json()) as {
      status: string;
      service: string;
      proxy: { safetyTier: string };
    };
    assert.equal(healthJson.status, "healthy");
    assert.equal(healthJson.service, "dbshield-proxy");
    assert.equal(healthJson.proxy.safetyTier, "BALANCED");

    // 2. Test /ready
    const resReady = await fetch(`http://127.0.0.1:${port}/ready`);
    assert.equal(resReady.status, 200);
    const readyJson = (await resReady.json()) as { status: string };
    assert.equal(readyJson.status, "ready");

    // 3. Test /metrics
    const resMetrics = await fetch(`http://127.0.0.1:${port}/metrics`);
    assert.equal(resMetrics.status, 200);
    assert.ok(resMetrics.headers.get("content-type")?.includes("text/plain"));
    const metricsText = await resMetrics.text();
    assert.ok(metricsText.includes("dbshield_up 1"));
    assert.ok(metricsText.includes('dbshield_queries_total{status="allowed"} 42'));

    // 4. Test root /
    const resRoot = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(resRoot.status, 200);
    const rootJson = (await resRoot.json()) as {
      endpoints: { metrics: string };
    };
    assert.equal(rootJson.endpoints.metrics, "/metrics");
  } finally {
    await server.stop();
  }
});
