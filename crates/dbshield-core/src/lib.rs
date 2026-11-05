//! DBShield Core: High-Performance Rust Wire Protocol Engine
//!
//! Sub-millisecond database wire proxy, connection pooling, and virtual shadow
//! execution layer for autonomous AI coding agents.

pub mod pg_protocol;
pub mod mysql_protocol;
pub mod pool;
pub mod shadow;
pub mod masking;

pub use pg_protocol::*;
pub use mysql_protocol::*;
pub use pool::*;
pub use shadow::*;
pub use masking::*;

/// Current DBShield Core engine version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
