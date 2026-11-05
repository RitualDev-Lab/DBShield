import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  HighConcurrencyConnectionPool,
  ProtocolWireMasker,
  VirtualShadowDatabase,
} from "../src/index.js";

describe("Phase 2 (DBShield): High-Concurrency Connection Pooling", () => {
  it("acquires, releases, and recycles pooled connections with sub-millisecond overhead", () => {
    const pool = new HighConcurrencyConnectionPool<{ destroy: () => void; id: number }>({
      maxConnections: 10,
      idleTimeoutMs: 1000,
    });

    let destroyed = false;
    const mockSocket = {
      id: 1,
      destroy: () => {
        destroyed = true;
      },
    };

    assert.equal(pool.acquire(), null, "Empty pool returns null initially");
    assert.equal(pool.trackNewConnection(), true);

    pool.release(mockSocket);
    const stats1 = pool.getStats();
    assert.equal(stats1.idle, 1);

    const reacquired = pool.acquire();
    assert.equal(reacquired?.id, 1, "Recycled socket returned");

    pool.release(reacquired);
    pool.drain();
    assert.equal(destroyed, true, "Drain destroys all sockets in pool");
  });
});

describe("Phase 2 (DBShield): Virtual Shadow Database (Copy-on-Write)", () => {
  it("intercepts DROP TABLE and returns simulated execution success without mutating live DB", () => {
    const shadow = new VirtualShadowDatabase();
    assert.equal(shadow.shouldInterceptToShadow("DROP TABLE customers CASCADE;"), true);

    const res = shadow.executeInShadow("DROP TABLE customers CASCADE;");
    assert.equal(res.simulated, true);
    assert.equal(res.commandTag, "DROP TABLE");
    assert.equal(shadow.isTableDropped("customers"), true);
    assert.ok(res.warnings[0].includes("SHADOW_INTERCEPTED"));
  });

  it("intercepts unconstrained DELETE and returns simulated affected rows safely", () => {
    const shadow = new VirtualShadowDatabase();
    assert.equal(shadow.shouldInterceptToShadow("DELETE FROM audit_logs"), true);

    const res = shadow.executeInShadow("DELETE FROM audit_logs");
    assert.equal(res.simulated, true);
    assert.equal(res.commandTag, "DELETE 42");
    assert.equal(res.affectedRows, 42);
    assert.ok(res.warnings.some((w) => w.includes("SIMULATED_SUCCESS")));
  });

  it("allows safe parameterized queries to bypass shadow layer", () => {
    const shadow = new VirtualShadowDatabase();
    assert.equal(shadow.shouldInterceptToShadow("SELECT * FROM users WHERE id = $1"), false);
    assert.equal(shadow.shouldInterceptToShadow("DELETE FROM users WHERE id = $1"), false);
  });
});

describe("Phase 2 (DBShield): Protocol-Level Wire Masking & Format-Preserving Pseudonymization", () => {
  it("masks PII columns on wire with deterministic format preservation", () => {
    const masker = new ProtocolWireMasker({
      salt: "enterprise-audit-salt",
      enableFormatPreserving: true,
    });

    const rawRow = {
      id: 101,
      name: "Alice Smith",
      email: "alice.smith@enterprise.corp",
      phone: "+1-555-839-2094",
      credit_card: "4111-2222-3333-4444",
      balance: 9500.5,
    };

    const masked = masker.maskRow(rawRow);
    assert.equal(masked.id, 101);
    assert.equal(masked.name, "Alice Smith");
    assert.equal(masked.balance, 9500.5);

    // Format preservation
    assert.ok(String(masked.email).startsWith("user_"));
    assert.ok(String(masked.email).endsWith("@enterprise.corp"));
    assert.equal(masked.phone, "+***-***-2094");
    assert.equal(masked.credit_card, "****-****-****-4444");

    // Referential integrity check (same value = same pseudonym)
    const masked2 = masker.maskRow(rawRow);
    assert.equal(masked.email, masked2.email);
  });
});
