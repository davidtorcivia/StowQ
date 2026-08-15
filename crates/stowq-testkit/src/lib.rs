//! Test kit: logical oracle, differential driver, fault-injecting
//! harness, and (later) the deterministic interleaving executor.

pub mod driver;
pub mod interleaving;
pub mod oracle;

pub use oracle::{JobState, Oracle, Phase, Terminal};
