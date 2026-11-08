import test from "node:test";
import assert from "node:assert/strict";
import { DistributedLockManager } from "../src/sandbox/distributed-lock.js";

test("DistributedLockManager acquires lock with monotonic fencing token", async () => {
  const manager = new DistributedLockManager();

  const handle1 = await manager.acquireLock("table:accounts", { ownerId: "replica_A" });
  assert.ok(handle1, "Must acquire lock successfully");
  assert.equal(handle1.resourceKey, "table:accounts");
  assert.equal(handle1.ownerId, "replica_A");
  assert.ok(handle1.fenceToken > 0, "Fence token must be positive monotonic number");

  const isLocked = manager.isLocked("table:accounts");
  assert.equal(isLocked, true);

  await manager.releaseLock(handle1);
  assert.equal(manager.isLocked("table:accounts"), false);
});

test("DistributedLockManager enforces mutual exclusion across concurrent replicas", async () => {
  const manager = new DistributedLockManager();

  const lock1 = await manager.acquireLock("table:orders", {
    ownerId: "replica_1",
    leaseTtlMs: 2000,
  });
  assert.ok(lock1);

  // Replica 2 attempts to acquire the same resource concurrently
  const lock2 = await manager.acquireLock("table:orders", {
    ownerId: "replica_2",
    retryCount: 1,
    retryDelayMs: 10,
  });
  assert.equal(lock2, null, "Concurrent replica must be blocked while lock is held");

  // Release lock 1
  const released = await manager.releaseLock(lock1);
  assert.equal(released, true);

  // Now Replica 2 can acquire
  const lock2After = await manager.acquireLock("table:orders", {
    ownerId: "replica_2",
  });
  assert.ok(lock2After, "Replica 2 must acquire after lock 1 is released");
  assert.ok(lock2After.fenceToken > lock1.fenceToken, "Fencing token must strictly increase");

  await manager.releaseLock(lock2After);
});

test("DistributedLockManager prevents stale worker from releasing hijacked lock", async () => {
  const manager = new DistributedLockManager();

  const lockA = await manager.acquireLock("table:ledger", { ownerId: "worker_slow" });
  assert.ok(lockA);

  // Fake stolen handle with different owner
  const fakeHandle = { ...lockA, ownerId: "worker_imposter" };
  const released = await manager.releaseLock(fakeHandle);
  assert.equal(released, false, "Imposter or stale owner must not be allowed to release lock");

  // Clean release by real owner
  assert.equal(await manager.releaseLock(lockA), true);
});

test("DistributedLockManager automatically purges expired leases", async () => {
  const manager = new DistributedLockManager();

  // Acquire with tiny TTL (50ms)
  const lock = await manager.acquireLock("table:ephemeral", {
    ownerId: "worker_quick",
    leaseTtlMs: 50,
  });
  assert.ok(lock);

  // Wait 70ms for expiration
  await new Promise((r) => setTimeout(r, 70));

  assert.equal(manager.isLocked("table:ephemeral"), false);

  // New worker can immediately acquire without deadlocking
  const newLock = await manager.acquireLock("table:ephemeral", {
    ownerId: "worker_new",
  });
  assert.ok(newLock, "New worker must acquire expired lock seamlessly");

  await manager.releaseLock(newLock);
});

test("withDistributedLock executes protected block and releases automatically on error", async () => {
  const manager = new DistributedLockManager();

  let executedToken = 0;
  await manager.withDistributedLock("table:customers", async (fenceToken) => {
    executedToken = fenceToken;
    assert.ok(manager.isLocked("table:customers"));
  });

  assert.ok(executedToken > 0);
  assert.equal(manager.isLocked("table:customers"), false, "Lock must be released after block");

  // Verify release even on exception
  let caught = false;
  try {
    await manager.withDistributedLock("table:customers", async () => {
      throw new Error("Simulated mutation failure");
    });
  } catch (err: any) {
    caught = true;
    assert.equal(err.message, "Simulated mutation failure");
  }

  assert.equal(caught, true);
  assert.equal(manager.isLocked("table:customers"), false, "Lock must be released even after thrown error");
});
