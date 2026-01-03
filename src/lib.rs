pub mod core;
pub mod modules;
pub mod ui;
pub mod utils;

// Re-export main types for convenience
pub use core::manager::{
    SecurityConfig, SecurityEvent, SecurityManager, SecuritySeverity, ThreatResponseAction,
};
