/**
 * Audit logging module
 * 
 * This module provides comprehensive audit logging for security events,
 * including file persistence, log rotation, and alerting capabilities.
 * 
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 * File: audit.rs
 * Description: Audit logging with file persistence and rotation
 */

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};

use super::{SecurityConfig, SecurityEvent, SecuritySeverity};

/**
 * Audit log entry
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
	/// Entry ID
	pub id: String,
	/// Security event
	pub event: SecurityEvent,
	/// Timestamp
	pub timestamp: DateTime<Utc>,
	/// Source IP (if applicable)
	pub source_ip: Option<String>,
	/// User agent (if applicable)
	pub user_agent: Option<String>,
	/// Session ID (if applicable)
	pub session_id: Option<String>,
	/// Additional metadata
	pub metadata: serde_json::Value,
}

/**
 * Audit configuration
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
	/// Enable audit logging
	pub enabled: bool,
	/// Log file path
	pub log_file_path: String,
	/// Maximum log file size (bytes)
	pub max_file_size: u64,
	/// Maximum number of log files to keep
	pub max_log_files: u32,
	/// Log rotation interval (hours)
	pub rotation_interval: u32,
	/// Maximum in-memory entries
	pub max_memory_entries: usize,
	/// Enable JSON formatting
	pub json_format: bool,
	/// Enable compression
	pub compression_enabled: bool,
	/// Alert thresholds
	pub alert_thresholds: AlertThresholds,
}

/**
 * Alert thresholds
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
	/// Critical events per minute
	pub critical_per_minute: u32,
	/// High severity events per minute
	pub high_per_minute: u32,
	/// Medium severity events per minute
	pub medium_per_minute: u32,
	/// Low severity events per minute
	pub low_per_minute: u32,
}

impl Default for AuditConfig {
	fn default() -> Self {
		Self {
			enabled: true,
			log_file_path: "/tmp/sare_security_audit.log".to_string(),
			max_file_size: 100 * 1024 * 1024, // 100MB
			max_log_files: 10,
			rotation_interval: 24, // 24 hours
			max_memory_entries: 10000,
			json_format: true,
			compression_enabled: false,
			alert_thresholds: AlertThresholds {
				critical_per_minute: 1,
				high_per_minute: 5,
				medium_per_minute: 10,
				low_per_minute: 20,
			},
		}
	}
}

/**
 * Audit logger
 */
pub struct AuditLogger {
	/// Security configuration
	config: Arc<RwLock<SecurityConfig>>,
	/// Audit configuration
	audit_config: AuditConfig,
	/// In-memory log entries
	log_entries: Arc<RwLock<VecDeque<AuditLogEntry>>>,
	/// Log file writer
	log_writer: Arc<RwLock<Option<BufWriter<File>>>>,
	/// Active state
	active: bool,
	/// Alert callbacks
	alert_callbacks: Arc<RwLock<Vec<Box<dyn Fn(AuditLogEntry) + Send + Sync>>>>,
	/// Event counters
	event_counters: Arc<RwLock<EventCounters>>,
}

/**
 * Event counters for alerting
 */
#[derive(Debug, Clone)]
pub struct EventCounters {
	/// Critical events in current minute
	pub critical_count: u32,
	/// High severity events in current minute
	pub high_count: u32,
	/// Medium severity events in current minute
	pub medium_count: u32,
	/// Low severity events in current minute
	pub low_count: u32,
	/// Last reset time
	pub last_reset: u64,
}

impl Default for EventCounters {
	fn default() -> Self {
		Self {
			critical_count: 0,
			high_count: 0,
			medium_count: 0,
			low_count: 0,
			last_reset: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
		}
	}
}

impl AuditLogger {
	/**
	 * Creates a new audit logger
	 */
	pub async fn new(config: Arc<RwLock<SecurityConfig>>) -> Result<Self> {
		let audit_config = AuditConfig::default();
		
		// Initialize log file
		let log_writer = if audit_config.enabled {
			let file = OpenOptions::new()
				.create(true)
				.append(true)
				.open(&audit_config.log_file_path)?;
			Some(BufWriter::new(file))
		} else {
			None
		};
		
		let logger = Self {
			config,
			audit_config,
			log_entries: Arc::new(RwLock::new(VecDeque::new())),
			log_writer: Arc::new(RwLock::new(log_writer)),
			active: true,
			alert_callbacks: Arc::new(RwLock::new(Vec::new())),
			event_counters: Arc::new(RwLock::new(EventCounters::default())),
		};
		
		// Start background tasks
		logger.start_background_tasks().await?;
		
		Ok(logger)
	}
	
	/**
	 * Logs a security event
	 */
	pub async fn log_event(&self, event: SecurityEvent) -> Result<()> {
		if !self.active || !self.audit_config.enabled {
			return Ok(());
		}
		
		// Create log entry
		let entry = self.create_log_entry(event).await?;
		
		// Add to in-memory storage
		{
			let mut entries = self.log_entries.write().await;
			entries.push_back(entry.clone());
			
			// Remove old entries if exceeding limit
			while entries.len() > self.audit_config.max_memory_entries {
				entries.pop_front();
			}
		}
		
		// Write to file
		self.write_log_entry(&entry).await?;
		
		// Update event counters
		self.update_event_counters(&entry).await?;
		
		// Check for alerts
		self.check_alerts(&entry).await?;
		
		Ok(())
	}
	
	/**
	 * Creates a log entry from a security event
	 */
	async fn create_log_entry(&self, event: SecurityEvent) -> Result<AuditLogEntry> {
		let now = SystemTime::now();
		let timestamp = DateTime::from(now);
		
		// Generate unique ID
		let id = format!("audit_{}", now.duration_since(UNIX_EPOCH)?.as_nanos());
		
		// Extract source information from event
		let (source_ip, user_agent, session_id) = self.extract_source_info(&event);
		
		// Create metadata
		let metadata = serde_json::json!({
			"version": "1.0",
			"source": "sare_security",
			"timestamp_unix": now.duration_since(UNIX_EPOCH)?.as_secs(),
		});
		
		Ok(AuditLogEntry {
			id,
			event,
			timestamp,
			source_ip,
			user_agent,
			session_id,
			metadata,
		})
	}
	
	/**
	 * Extracts source information from security event
	 */
	fn extract_source_info(&self, event: &SecurityEvent) -> (Option<String>, Option<String>, Option<String>) {
		match event {
			SecurityEvent::CommandExecution { user, .. } => {
				(Some("127.0.0.1".to_string()), None, Some(format!("session_{}", user)))
			}
			SecurityEvent::FileAccess { user, .. } => {
				(Some("127.0.0.1".to_string()), None, Some(format!("session_{}", user)))
			}
			SecurityEvent::NetworkAccess { user, .. } => {
				(Some("127.0.0.1".to_string()), None, Some(format!("session_{}", user)))
			}
			SecurityEvent::PermissionViolation { user, .. } => {
				(Some("127.0.0.1".to_string()), None, Some(format!("session_{}", user)))
			}
			SecurityEvent::SecurityAlert { .. } => {
				(Some("127.0.0.1".to_string()), None, None)
			}
			SecurityEvent::ThreatDetected { source, .. } => {
				(Some(source.clone()), None, None)
			}
			SecurityEvent::BehavioralAnomaly { user, .. } => {
				(Some("127.0.0.1".to_string()), None, Some(format!("session_{}", user)))
			}
		}
	}
	
	/**
	 * Writes a log entry to file
	 */
	async fn write_log_entry(&self, entry: &AuditLogEntry) -> Result<()> {
		if let Some(writer) = &mut *self.log_writer.write().await {
			let json = serde_json::to_string(entry)?;
			writeln!(writer, "{}", json)?;
			writer.flush()?;
		}
		Ok(())
	}
	
	/**
	 * Starts background tasks
	 */
	async fn start_background_tasks(&self) -> Result<()> {
		let log_entries = self.log_entries.clone();
		let audit_config = self.audit_config.clone();
		let log_writer = self.log_writer.clone();
		
		// Log rotation task
		tokio::spawn(async move {
			let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // Check every hour
			
			loop {
				interval.tick().await;
				
				// Check if rotation is needed
				if let Ok(file) = std::fs::metadata(&audit_config.log_file_path) {
					if file.len() > audit_config.max_file_size {
						// Rotate log file
						if let Err(e) = Self::rotate_log_file(&audit_config.log_file_path, audit_config.max_log_files).await {
							eprintln!("Failed to rotate log file: {}", e);
						}
					}
				}
			}
		});
		
		// Event counter reset task
		let event_counters = self.event_counters.clone();
		tokio::spawn(async move {
			let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60)); // Reset every minute
			
			loop {
				interval.tick().await;
				
				if let Ok(mut counters) = event_counters.try_write() {
					counters.critical_count = 0;
					counters.high_count = 0;
					counters.medium_count = 0;
					counters.low_count = 0;
					counters.last_reset = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
				}
			}
		});
		
		Ok(())
	}
	
	/**
	 * Rotates log file
	 */
	async fn rotate_log_file(log_path: &str, max_files: u32) -> Result<()> {
		let path = Path::new(log_path);
		let parent = path.parent().unwrap_or(Path::new("."));
		let stem = path.file_stem().unwrap_or_default().to_string_lossy();
		let extension = path.extension().unwrap_or_default().to_string_lossy();
		
		// Create backup filename
		let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
		let backup_name = format!("{}.{}.{}", stem, timestamp, extension);
		let backup_path = parent.join(backup_name);
		
		// Move current log file
		if path.exists() {
			std::fs::rename(path, &backup_path)?;
		}
		
		// Remove old backup files
		let mut backup_files = Vec::new();
		if let Ok(entries) = std::fs::read_dir(parent) {
			for entry in entries {
				if let Ok(entry) = entry {
					if let Ok(file_name) = entry.file_name().into_string() {
						if file_name.starts_with(&format!("{}.", stem)) && file_name.ends_with(&format!(".{}", extension)) {
							backup_files.push((entry.path(), entry.metadata()?.modified()?));
						}
					}
				}
			}
		}
		
		// Sort by modification time and remove oldest
		backup_files.sort_by(|a, b| a.1.cmp(&b.1));
		for (path, _) in backup_files.iter().skip(max_files as usize) {
			let _ = std::fs::remove_file(path);
		}
		
		Ok(())
	}
	
	/**
	 * Updates event counters
	 */
	async fn update_event_counters(&self, entry: &AuditLogEntry) -> Result<()> {
		let mut counters = self.event_counters.write().await;
		
		match &entry.event {
			SecurityEvent::SecurityAlert { severity, .. } => {
				match severity {
					SecuritySeverity::Critical => counters.critical_count += 1,
					SecuritySeverity::High => counters.high_count += 1,
					SecuritySeverity::Medium => counters.medium_count += 1,
					SecuritySeverity::Low => counters.low_count += 1,
				}
			}
			SecurityEvent::ThreatDetected { severity, .. } => {
				match severity {
					SecuritySeverity::Critical => counters.critical_count += 1,
					SecuritySeverity::High => counters.high_count += 1,
					SecuritySeverity::Medium => counters.medium_count += 1,
					SecuritySeverity::Low => counters.low_count += 1,
				}
			}
			_ => {
				// Default to medium severity for other events
				counters.medium_count += 1;
			}
		}
		
		Ok(())
	}
	
	/**
	 * Checks for alerts based on thresholds
	 */
	async fn check_alerts(&self, entry: &AuditLogEntry) -> Result<()> {
		let counters = self.event_counters.read().await;
		let thresholds = &self.audit_config.alert_thresholds;
		
		let mut should_alert = false;
		let mut alert_message = String::new();
		
		if counters.critical_count >= thresholds.critical_per_minute {
			should_alert = true;
			alert_message = format!("Critical security events threshold exceeded: {} events per minute", counters.critical_count);
		} else if counters.high_count >= thresholds.high_per_minute {
			should_alert = true;
			alert_message = format!("High severity security events threshold exceeded: {} events per minute", counters.high_count);
		} else if counters.medium_count >= thresholds.medium_per_minute {
			should_alert = true;
			alert_message = format!("Medium severity security events threshold exceeded: {} events per minute", counters.medium_count);
		} else if counters.low_count >= thresholds.low_per_minute {
			should_alert = true;
			alert_message = format!("Low severity security events threshold exceeded: {} events per minute", counters.low_count);
		}
		
		if should_alert {
			self.trigger_alert(entry.clone()).await?;
			
			// Log alert
			let alert_event = SecurityEvent::SecurityAlert {
				alert_type: "threshold_exceeded".to_string(),
				description: alert_message,
				severity: SecuritySeverity::High,
				timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
				attack_vector: "audit_threshold".to_string(),
				response_action: None,
			};
			
			self.log_event(alert_event).await?;
		}
		
		Ok(())
	}
	
	/**
	 * Triggers an alert
	 */
	async fn trigger_alert(&self, entry: AuditLogEntry) -> Result<()> {
		let callbacks = self.alert_callbacks.read().await;
		for callback in callbacks.iter() {
			callback(entry.clone());
		}
		Ok(())
	}
	
	/**
	 * Gets recent log entries
	 */
	pub async fn get_recent_entries(&self, count: usize) -> Vec<AuditLogEntry> {
		let entries = self.log_entries.read().await;
		entries.iter().rev().take(count).cloned().collect()
	}
	
	/**
	 * Gets entries by severity
	 */
	pub async fn get_entries_by_severity(&self, severity: SecuritySeverity) -> Vec<AuditLogEntry> {
		let entries = self.log_entries.read().await;
		entries.iter()
			.filter(|entry| {
				match &entry.event {
					SecurityEvent::SecurityAlert { severity: event_severity, .. } => {
						std::mem::discriminant(event_severity) == std::mem::discriminant(&severity)
					}
					SecurityEvent::ThreatDetected { severity: event_severity, .. } => {
						std::mem::discriminant(event_severity) == std::mem::discriminant(&severity)
					}
					_ => false,
				}
			})
			.cloned()
			.collect()
	}
	
	/**
	 * Gets entries by user
	 */
	pub async fn get_entries_by_user(&self, user: &str) -> Vec<AuditLogEntry> {
		let entries = self.log_entries.read().await;
		entries.iter()
			.filter(|entry| {
				match &entry.event {
					SecurityEvent::CommandExecution { user: event_user, .. } => event_user == user,
					SecurityEvent::FileAccess { user: event_user, .. } => event_user == user,
					SecurityEvent::NetworkAccess { user: event_user, .. } => event_user == user,
					SecurityEvent::PermissionViolation { user: event_user, .. } => event_user == user,
					SecurityEvent::BehavioralAnomaly { user: event_user, .. } => event_user == user,
					_ => false,
				}
			})
			.cloned()
			.collect()
	}
	
	/**
	 * Adds an alert callback
	 */
	pub async fn add_alert_callback(&self, callback: Box<dyn Fn(AuditLogEntry) + Send + Sync>) {
		self.alert_callbacks.write().await.push(callback);
	}
	
	/**
	 * Checks if audit logger is active
	 */
	pub async fn is_active(&self) -> bool {
		self.active
	}
	
	/**
	 * Updates audit configuration
	 */
	pub fn update_config(&mut self, config: AuditConfig) {
		self.audit_config = config;
	}
	
	/**
	 * Gets current configuration
	 */
	pub fn get_config(&self) -> AuditConfig {
		self.audit_config.clone()
	}
} 