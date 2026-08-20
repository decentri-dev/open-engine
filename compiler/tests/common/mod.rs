// A shared fixtures module: each test binary includes the whole file but uses
// only the parts it needs, so unused items here are expected rather than dead.
#![allow(dead_code)]

/// Shared in-memory gateway double, defined in core (`test-utils` feature) so
/// the compiler and broadcaster test suites exercise the same behavior.
pub use open_engine_core::gateway::MockGateway;

pub const SPONSOR_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub const DUMMY_SENDER: &str = "0x1111111111111111111111111111111111111111";
