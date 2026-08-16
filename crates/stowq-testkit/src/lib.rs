//! Test kit: logical oracle, differential driver, fault-injecting
//! harness, and the interleaving lab.

pub mod driver;
pub mod interleaving;
pub mod oracle;

pub use oracle::{JobState, Oracle, Phase, Terminal};
