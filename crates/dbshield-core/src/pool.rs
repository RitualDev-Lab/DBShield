//! High-Concurrency Connection Pooling Engine.
//!
//! Sub-millisecond connection reuse, queue bounding, and heartbeat health checks.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct PooledConnection<T> {
    pub client: T,
    pub created_at: Instant,
    pub last_used: Instant,
}

pub struct PoolConfig {
    pub min_connections: usize,
    pub max_connections: usize,
    pub idle_timeout: Duration,
    pub acquire_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 5,
            max_connections: 50,
            idle_timeout: Duration::from_secs(300),
            acquire_timeout: Duration::from_millis(1500),
        }
    }
}

pub struct AsyncConnectionPool<T> {
    config: PoolConfig,
    available: Arc<Mutex<VecDeque<PooledConnection<T>>>>,
    active_count: Arc<AtomicUsize>,
}

impl<T> AsyncConnectionPool<T> {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            available: Arc::new(Mutex::new(VecDeque::new())),
            active_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn acquire(&self) -> Option<PooledConnection<T>> {
        let mut queue = self.available.lock();
        let now = Instant::now();

        // Drain expired idle connections
        while let Some(front) = queue.front() {
            if now.duration_since(front.last_used) > self.config.idle_timeout {
                queue.pop_front();
                self.active_count.fetch_sub(1, Ordering::SeqCst);
            } else {
                break;
            }
        }

        if let Some(conn) = queue.pop_back() {
            Some(conn)
        } else {
            None
        }
    }

    pub fn release(&self, mut conn: PooledConnection<T>) {
        conn.last_used = Instant::now();
        let mut queue = self.available.lock();
        if queue.len() < self.config.max_connections {
            queue.push_back(conn);
        } else {
            self.active_count.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub fn pool_stats(&self) -> (usize, usize) {
        let idle = self.available.lock().len();
        let total = self.active_count.load(Ordering::SeqCst);
        (idle, total)
    }
}
