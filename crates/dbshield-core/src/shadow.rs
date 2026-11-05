//! Protocol-Level Copy-on-Write Virtual Shadow Database.
//!
//! Unauthorized or destructive queries execute transparently against isolated
//! in-memory shadow layers, returning simulated execution success to the autonomous
//! agent while keeping live production databases 100% immutable.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ShadowExecutionResult {
    pub success: bool,
    pub command_tag: String,
    pub simulated_affected_rows: u64,
    pub execution_time_us: u64,
    pub was_shadow_isolated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct VirtualTable {
    pub columns: Vec<String>,
    pub rows: Vec<HashMap<String, String>>,
}

pub struct VirtualShadowDatabase {
    tables: Arc<RwLock<HashMap<String, VirtualTable>>>,
}

impl Default for VirtualShadowDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualShadowDatabase {
    pub fn new() -> Self {
        Self {
            tables: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Seeds shadow layer with a schema definition
    pub fn register_table(&self, table_name: &str, columns: Vec<String>) {
        let mut map = self.tables.write();
        map.insert(
            table_name.to_lowercase(),
            VirtualTable {
                columns,
                rows: Vec::new(),
            },
        );
    }

    /// Evaluates whether a query should be routed to the shadow layer
    pub fn should_shadow(&self, query: &str) -> bool {
        let upper = query.trim().to_uppercase();
        upper.starts_with("DROP TABLE")
            || upper.starts_with("TRUNCATE")
            || upper.starts_with("ALTER TABLE")
            || (upper.starts_with("DELETE") && !upper.contains("WHERE"))
            || (upper.starts_with("UPDATE") && !upper.contains("WHERE"))
    }

    /// Executes destructive/unauthorized SQL inside the isolated shadow sandbox
    pub fn execute_shadow(&self, query: &str) -> ShadowExecutionResult {
        let start = std::time::Instant::now();
        let upper = query.trim().to_uppercase();

        let (tag, affected) = if upper.starts_with("DROP TABLE") {
            let table = query
                .split_whitespace()
                .nth(2)
                .unwrap_or("unknown_table")
                .trim_matches(';')
                .to_lowercase();
            self.tables.write().remove(&table);
            ("DROP TABLE".to_string(), 0)
        } else if upper.starts_with("TRUNCATE") {
            let table = query
                .split_whitespace()
                .nth(1)
                .unwrap_or("unknown_table")
                .trim_matches(';')
                .to_lowercase();
            if let Some(tbl) = self.tables.write().get_mut(&table) {
                let count = tbl.rows.len() as u64;
                tbl.rows.clear();
                ("TRUNCATE TABLE".to_string(), count)
            } else {
                ("TRUNCATE TABLE".to_string(), 0)
            }
        } else if upper.starts_with("DELETE") {
            ("DELETE 42".to_string(), 42)
        } else if upper.starts_with("UPDATE") {
            ("UPDATE 42".to_string(), 42)
        } else {
            ("OK".to_string(), 1)
        };

        let elapsed_us = start.elapsed().as_micros() as u64;
        ShadowExecutionResult {
            success: true,
            command_tag: tag,
            simulated_affected_rows: affected,
            execution_time_us: elapsed_us,
            was_shadow_isolated: true,
        }
    }
}
