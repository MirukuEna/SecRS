use sare_security::{SecurityConfig, SecurityEvent, SecurityManager};
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("==================================================");
    println!("🛡️  SecRS: Ruthless Security System - LIVE DEMO 🛡️");
    println!("==================================================");

    // Initialize Configuration
    let config = Arc::new(RwLock::new(SecurityConfig::default()));
    println!("\n[INFO] Initializing Security Manager...");
    let mut manager = SecurityManager::new(config).await?;
    println!("[INFO] System Active and Monitoring.");

    // Simulate Safe Event
    println!("\n--------------------------------------------------");
    println!("Scenario 1: Routine Administrative Task");
    println!("--------------------------------------------------");
    let safe_event = SecurityEvent::CommandExecution {
        command: "ls -la /var/log".to_string(),
        user: "sysadmin".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        success: true,
    };
    println!("[EVENT] Command Execution: 'ls -la /var/log' by user 'sysadmin'");
    let actions = manager.process_security_event(safe_event).await?;
    println!("[RESULT] System Response: {:?}", actions);

    // Simulate Malicious Event
    println!("\n--------------------------------------------------");
    println!("Scenario 2: Critical Threat Detection");
    println!("--------------------------------------------------");
    let malicious_event = SecurityEvent::CommandExecution {
        command: "rm -rf / --no-preserve-root".to_string(),
        user: "intruder".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        success: false,
    };
    println!("[EVENT] Command Execution: 'rm -rf /' by user 'intruder'");
    println!("[ANALYSIS] Analyzing threat patterns and behavior...");
    let actions = manager.process_security_event(malicious_event).await?;

    println!("[RESULT] System Response:");
    for action in actions {
        println!("  - 🛑 {:?}", action);
    }

    println!("\n==================================================");
    println!("✅ Demo Complete. System Integrity Maintained.");
    println!("==================================================");

    Ok(())
}
