use sare_security::{SecurityConfig, SecurityManager};
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("==================================================");
    println!("🛡️  SecRS: Ruthless Security System - LIVE DEMO 🛡️");
    println!("==================================================");

    // Initialize Configuration
    let config_data = SecurityConfig::load("config.toml").unwrap_or_else(|e| {
        eprintln!("Failed to load config: {}. Using default.", e);
        SecurityConfig::default()
    });
    let config = Arc::new(RwLock::new(config_data));
    let manager = Arc::new(RwLock::new(SecurityManager::new(config.clone()).await?));

    // Run TUI
    if let Err(e) = sare_security::ui::run(config, manager).await {
        eprintln!("Application error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
