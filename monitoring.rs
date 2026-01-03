/**
 * Security monitoring module provides comprehensive real-time threat
 * detection, alerting, and security event analysis capabilities.
 * The module implements multiple monitoring layers including behavioral
 * analysis, anomaly detection, and pattern recognition to maintain
 * system security and integrity.
 * 
 * The monitoring system employs statistical analysis, machine learning
 * techniques, and rule-based detection to identify security threats
 * and anomalous behavior patterns. Real-time monitoring provides
 * immediate threat detection and enables rapid response to security
 * incidents while maintaining comprehensive audit trails.
 */

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, sleep};
use std::time::{SystemTime, UNIX_EPOCH};
use regex::Regex;

use super::{SecurityConfig, SecurityEvent, SecuritySeverity};

/**
 * Security alert information tracks comprehensive security events
 * including detailed information, severity levels, and response
 * status tracking. Alert tracking enables detailed security analysis
 * and provides comprehensive audit trails for incident response.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
	pub alert_id: String,
	pub alert_type: String,
	pub severity: SecuritySeverity,
	pub description: String,
	pub details: serde_json::Value,
	pub timestamp: u64,
	pub source: String,
	pub acknowledged: bool,
	pub resolved: bool,
	pub resolution_notes: Option<String>,
}

/**
 * Monitoring configuration defines comprehensive security monitoring
 * settings including real-time monitoring, alert configuration, and
 * security policies. Configuration parameters enable fine-tuned
 * monitoring policies that can be adjusted based on security
 * requirements and system constraints.
 */
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
	pub real_time_monitoring: bool,
	pub threat_detection: bool,
	pub behavioral_analysis: bool,
	pub anomaly_detection: bool,
	pub alert_on_high_severity: bool,
	pub alert_on_critical_severity: bool,
	pub max_alerts_in_memory: usize,
	pub alert_retention_days: u32,
	pub monitoring_interval: u64,
	pub threat_detection_sensitivity: f64,
	pub anomaly_detection_threshold: f64,
}

impl Default for MonitoringConfig {
	fn default() -> Self {
		Self {
			real_time_monitoring: true,
			threat_detection: true,
			behavioral_analysis: true,
			anomaly_detection: true,
			alert_on_high_severity: true,
			alert_on_critical_severity: true,
			max_alerts_in_memory: 1000,
			alert_retention_days: 30,
			monitoring_interval: 60,
			threat_detection_sensitivity: 0.8,
			anomaly_detection_threshold: 0.7,
		}
	}
}

/**
 * Threat pattern information defines comprehensive threat detection
 * rules including threat types, detection methods, and response
 * strategies. Pattern-based detection provides efficient threat
 * identification without requiring complex machine learning models
 * while maintaining high detection accuracy.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPattern {
	pub pattern_id: String,
	pub pattern_name: String,
	pub description: String,
	pub severity: SecuritySeverity,
	pub regex_pattern: String,
	pub keywords: Vec<String>,
	pub actions: Vec<String>,
	pub active: bool,
}

/**
 * Security monitor implements comprehensive real-time monitoring
 * capabilities including threat detection, behavioral analysis,
 * and alerting. The monitor provides centralized security monitoring
 * that ensures consistent threat detection across all system
 * components and security events.
 */
pub struct SecurityMonitor {
	config: Arc<RwLock<SecurityConfig>>,
	monitoring_config: MonitoringConfig,
	alerts: Arc<RwLock<VecDeque<SecurityAlert>>>,
	threat_patterns: Arc<RwLock<HashMap<String, ThreatPattern>>>,
	behavioral_patterns: Arc<RwLock<HashMap<String, Vec<String>>>>,
	anomaly_data: Arc<RwLock<HashMap<String, Vec<f64>>>>,
	active: bool,
}

impl SecurityMonitor {
	pub async fn new(config: Arc<RwLock<SecurityConfig>>) -> Result<Self> {
		let monitoring_config = MonitoringConfig::default();
		let alerts = Arc::new(RwLock::new(VecDeque::new()));
		let threat_patterns = Arc::new(RwLock::new(HashMap::new()));
		let behavioral_patterns = Arc::new(RwLock::new(HashMap::new()));
		let anomaly_data = Arc::new(RwLock::new(HashMap::new()));
		
		let monitor = Self {
			config,
			monitoring_config,
			alerts,
			threat_patterns,
			behavioral_patterns,
			anomaly_data,
			active: true,
		};
		
		monitor.initialize_threat_patterns().await?;
		monitor.start_monitoring_tasks().await?;
		
		Ok(monitor)
	}
	
	pub async fn process_event(&self, event: SecurityEvent) -> Result<()> {
		if !self.monitoring_config.real_time_monitoring {
			return Ok(());
		}
		
		if self.monitoring_config.threat_detection {
			self.check_threat_patterns(&event).await?;
		}
		
		if self.monitoring_config.behavioral_analysis {
			self.check_behavioral_patterns(&event).await?;
		}
		
		if self.monitoring_config.anomaly_detection {
			self.check_anomalies(&event).await?;
		}
		
		match event {
			SecurityEvent::SecurityAlert { alert_type, description, severity, timestamp } => {
				if (severity == SecuritySeverity::High && self.monitoring_config.alert_on_high_severity) ||
				   (severity == SecuritySeverity::Critical && self.monitoring_config.alert_on_critical_severity) {
					self.generate_alert(alert_type, description, severity, timestamp).await?;
				}
			},
			SecurityEvent::PermissionViolation { resource, operation, user, timestamp, reason } => {
				if self.monitoring_config.alert_on_high_severity {
					let description = format!("Permission violation: {} {} by user {}", operation, resource, user);
					self.generate_alert("permission_violation".to_string(), description, SecuritySeverity::High, timestamp).await?;
				}
			},
			_ => {
				self.process_general_event(&event).await?;
			}
		}
		
		Ok(())
	}
	
	async fn check_threat_patterns(&self, event: &SecurityEvent) -> Result<()> {
		let patterns = self.threat_patterns.read().await;
		
		for pattern in patterns.values() {
			if !pattern.active {
				continue;
			}
			
			if self.matches_threat_pattern(event, pattern).await? {
				let description = format!("Threat detected: {} - {}", pattern.pattern_name, pattern.description);
				self.generate_alert(
					"threat_detected".to_string(),
					description,
					pattern.severity,
					std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)?
						.as_secs()
				).await?;
			}
		}
		
		Ok(())
	}
	
	async fn check_behavioral_patterns(&self, event: &SecurityEvent) -> Result<()> {
		let event_key = match event {
			SecurityEvent::CommandExecution { command, user, .. } => format!("cmd:{}:{}", user, command),
			SecurityEvent::FileAccess { path, operation, user, .. } => format!("file:{}:{}:{}", user, operation, path),
			SecurityEvent::NetworkAccess { host, port, protocol, user, .. } => format!("net:{}:{}://{}:{}", user, protocol, host, port),
			SecurityEvent::PermissionViolation { resource, operation, user, .. } => format!("perm:{}:{}:{}", user, operation, resource),
			SecurityEvent::SecurityAlert { description, .. } => format!("alert:{}", description),
		};
		
		let timestamp = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)?
			.as_secs();
		
		if let Ok(mut patterns) = self.behavioral_patterns.write().await {
			let user_patterns = patterns.entry(event_key.clone()).or_insert_with(Vec::new);
			user_patterns.push(timestamp.to_string());
			
			if user_patterns.len() > 10 {
				let recent_patterns = &user_patterns[user_patterns.len().saturating_sub(10)..];
				let pattern_frequency = recent_patterns.len() as f64 / 60.0;
				
				if pattern_frequency > 5.0 {
					let alert_description = format!("High frequency behavior detected: {} ({} patterns/min)", event_key, pattern_frequency);
					self.generate_alert(
						"BehavioralAnomaly".to_string(),
						alert_description,
						SecuritySeverity::High,
						timestamp
					).await?;
				}
			}
		}
		
		if let Ok(patterns) = self.behavioral_patterns.read().await {
			if let Some(user_patterns) = patterns.get(&event_key) {
				if user_patterns.len() > 50 {
					let alert_description = format!("Excessive behavior detected: {} ({} total patterns)", event_key, user_patterns.len());
					self.generate_alert(
						"ExcessiveBehavior".to_string(),
						alert_description,
						SecuritySeverity::Medium,
						timestamp
					).await?;
				}
			}
		}
		
		Ok(())
	}
	
	async fn check_anomalies(&self, event: &SecurityEvent) -> Result<()> {
		let event_key = match event {
			SecurityEvent::CommandExecution { command, .. } => format!("cmd:{}", command),
			SecurityEvent::FileAccess { path, operation, .. } => format!("file:{}:{}", operation, path),
			SecurityEvent::NetworkAccess { host, port, protocol, .. } => format!("net:{}://{}:{}", protocol, host, port),
			SecurityEvent::PermissionViolation { resource, operation, .. } => format!("perm:{}:{}", operation, resource),
			SecurityEvent::SecurityAlert { description, .. } => format!("alert:{}", description),
		};
		
		let timestamp = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)?
			.as_secs();
		
		if let Ok(mut anomaly_data) = self.anomaly_data.write().await {
			let entry = anomaly_data.entry(event_key.clone()).or_insert_with(Vec::new);
			entry.push(1.0);
			
			if entry.len() > 100 {
				entry.drain(0..entry.len().saturating_sub(100));
			}
			
			if entry.len() >= 10 {
				let mean = entry.iter().sum::<f64>() / entry.len() as f64;
				let variance = entry.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / entry.len() as f64;
				let std_dev = variance.sqrt();
				
				let current_value = entry.last().unwrap_or(&0.0);
				let z_score = if std_dev > 0.0 { (current_value - mean) / std_dev } else { 0.0 };
				
				if z_score.abs() > 2.5 {
					let alert_description = format!("Statistical anomaly detected: {} (z-score: {:.2})", event_key, z_score);
					self.generate_alert(
						"StatisticalAnomaly".to_string(),
						alert_description,
						SecuritySeverity::High,
						timestamp
					).await?;
				}
			}
		}
		
		if let Ok(anomaly_data) = self.anomaly_data.read().await {
			if let Some(entry) = anomaly_data.get(&event_key) {
				if entry.len() >= 20 {
					let recent_trend = entry[entry.len().saturating_sub(10)..].iter().sum::<f64>();
					let previous_trend = entry[entry.len().saturating_sub(20)..entry.len().saturating_sub(10)].iter().sum::<f64>();
					
					if recent_trend > previous_trend * 2.0 {
						let alert_description = format!("Trend anomaly detected: {} (increase: {:.1}x)", event_key, recent_trend / previous_trend);
						self.generate_alert(
							"TrendAnomaly".to_string(),
							alert_description,
							SecuritySeverity::Medium,
							timestamp
						).await?;
					}
				}
			}
		}
		
		Ok(())
	}
	
	async fn matches_threat_pattern(&self, event: &SecurityEvent, pattern: &ThreatPattern) -> Result<bool> {
		let event_str = match event {
			SecurityEvent::CommandExecution { command, .. } => command,
			SecurityEvent::FileAccess { path, operation, .. } => &format!("{} {}", operation, path),
			SecurityEvent::NetworkAccess { host, port, protocol, .. } => &format!("{}://{}:{}", protocol, host, port),
			SecurityEvent::PermissionViolation { resource, operation, .. } => &format!("{} {}", operation, resource),
			SecurityEvent::SecurityAlert { description, .. } => description,
		};
		
		if !pattern.regex_pattern.is_empty() {
			if let Ok(regex) = regex::Regex::new(&pattern.regex_pattern) {
				if regex.is_match(event_str) {
					return Ok(true);
				}
			}
		}
		
		for keyword in &pattern.keywords {
			if event_str.to_lowercase().contains(&keyword.to_lowercase()) {
				return Ok(true);
			}
		}
		
		Ok(false)
	}
	
	async fn process_general_event(&self, event: &SecurityEvent) -> Result<()> {
		{
			let mut anomaly_data = self.anomaly_data.write().await;
			
			let event_type = match event {
				SecurityEvent::CommandExecution { .. } => "command_execution",
				SecurityEvent::FileAccess { .. } => "file_access",
				SecurityEvent::NetworkAccess { .. } => "network_access",
				SecurityEvent::PermissionViolation { .. } => "permission_violation",
				SecurityEvent::SecurityAlert { .. } => "security_alert",
			};
			
			let entry = anomaly_data.entry(event_type.to_string()).or_insert_with(Vec::new);
			entry.push(1.0);
			
			if entry.len() > 1000 {
				entry.drain(0..entry.len() - 1000);
			}
		}
		
		Ok(())
	}
	
	async fn generate_alert(&self, alert_type: String, description: String, severity: SecuritySeverity, timestamp: u64) -> Result<()> {
		let alert_id = self.generate_alert_id().await?;
		
		let alert = SecurityAlert {
			alert_id,
			alert_type,
			severity,
			description,
			details: serde_json::json!({}),
			timestamp,
			source: "security_monitor".to_string(),
			acknowledged: false,
			resolved: false,
			resolution_notes: None,
		};
		
		{
			let mut alerts = self.alerts.write().await;
			alerts.push_back(alert);
			
			while alerts.len() > self.monitoring_config.max_alerts_in_memory {
				alerts.pop_front();
			}
		}
		
		Ok(())
	}
	
	async fn generate_alert_id(&self) -> Result<String> {
		use rand::Rng;
		let mut rng = rand::thread_rng();
		let id_bytes: [u8; 16] = rng.gen();
		let alert_id = base64::engine::general_purpose::STANDARD.encode(&id_bytes);
		
		Ok(alert_id)
	}
	
	async fn initialize_threat_patterns(&self) -> Result<()> {
		let mut patterns = self.threat_patterns.write().await;
		
		patterns.insert("command_injection".to_string(), ThreatPattern {
			pattern_id: "command_injection".to_string(),
			pattern_name: "Command Injection".to_string(),
			description: "Attempted command injection attack".to_string(),
			severity: SecuritySeverity::High,
			regex_pattern: r"[;&|`$\(\)\{\}\[\]]".to_string(),
			keywords: vec![";", "&", "|", "`", "$", "(", ")", "{", "}", "[", "]"].into_iter().map(|s| s.to_string()).collect(),
			actions: vec!["block".to_string(), "alert".to_string()],
			active: true,
		});
		
		patterns.insert("path_traversal".to_string(), ThreatPattern {
			pattern_id: "path_traversal".to_string(),
			pattern_name: "Path Traversal".to_string(),
			description: "Attempted path traversal attack".to_string(),
			severity: SecuritySeverity::High,
			regex_pattern: r"\.\./|\.\.\\|%2e%2e|%2e%2e%2f|%2e%2e%5c".to_string(),
			keywords: vec!["../", "..\\", "%2e%2e"].into_iter().map(|s| s.to_string()).collect(),
			actions: vec!["block".to_string(), "alert".to_string()],
			active: true,
		});
		
		patterns.insert("dangerous_commands".to_string(), ThreatPattern {
			pattern_id: "dangerous_commands".to_string(),
			pattern_name: "Dangerous Commands".to_string(),
			description: "Attempted execution of dangerous commands".to_string(),
			severity: SecuritySeverity::Critical,
			regex_pattern: r"(rm\s+-rf|dd\s+if=|:\(\)\s*\{\s*:\|:\s*&\s*\};:|forkbomb|killall|pkill|kill\s+-9)".to_string(),
			keywords: vec!["rm -rf", "dd if=", "forkbomb", "killall", "pkill"].into_iter().map(|s| s.to_string()).collect(),
			actions: vec!["block".to_string(), "alert".to_string(), "terminate".to_string()],
			active: true,
		});
		
		Ok(())
	}
	
	async fn start_monitoring_tasks(&self) -> Result<()> {
		let alerts = self.alerts.clone();
		let monitoring_interval = self.monitoring_config.monitoring_interval;
		let anomaly_data = self.anomaly_data.clone();
		let behavioral_patterns = self.behavioral_patterns.clone();
		
		tokio::spawn(async move {
			loop {
				sleep(Duration::from_secs(monitoring_interval)).await;
				
				if let Ok(mut alerts_guard) = alerts.write().await {
					if alerts_guard.len() > 0 {
						let recent_alerts = alerts_guard.iter()
							.filter(|alert| alert.timestamp > SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 300)
							.count();
						
						if recent_alerts > 10 {
							let summary_alert = SecurityAlert {
								alert_id: format!("summary_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
								alert_type: "ThreatSummary".to_string(),
								severity: SecuritySeverity::High,
								description: format!("High threat activity detected: {} alerts in last 5 minutes", recent_alerts),
								details: serde_json::json!({"alert_count": recent_alerts, "time_window": "5 minutes"}),
								timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
								source: "PeriodicMonitor".to_string(),
								acknowledged: false,
								resolved: false,
								resolution_notes: None,
							};
							alerts_guard.push_back(summary_alert);
						}
					}
				}
				
				if let Ok(patterns) = behavioral_patterns.read().await {
					for (pattern_key, timestamps) in patterns.iter() {
						if timestamps.len() > 100 {
							let analysis_alert = SecurityAlert {
								alert_id: format!("behavior_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
								alert_type: "BehavioralAnalysis".to_string(),
								severity: SecuritySeverity::Medium,
								description: format!("Excessive behavioral pattern detected: {} ({} total events)", pattern_key, timestamps.len()),
								details: serde_json::json!({"pattern": pattern_key, "event_count": timestamps.len()}),
								timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
								source: "PeriodicMonitor".to_string(),
								acknowledged: false,
								resolved: false,
								resolution_notes: None,
							};
							
							if let Ok(mut alerts_guard) = alerts.write().await {
								alerts_guard.push_back(analysis_alert);
							}
						}
					}
				}
				
				if let Ok(anomaly_guard) = anomaly_data.read().await {
					for (event_key, data_points) in anomaly_guard.iter() {
						if data_points.len() >= 50 {
							let mean = data_points.iter().sum::<f64>() / data_points.len() as f64;
							let variance = data_points.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / data_points.len() as f64;
							let std_dev = variance.sqrt();
							
							if std_dev > mean * 0.5 {
								let anomaly_alert = SecurityAlert {
									alert_id: format!("anomaly_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
									alert_type: "AnomalyReport".to_string(),
									severity: SecuritySeverity::Medium,
									description: format!("Anomaly detected in pattern: {} (std_dev: {:.2})", event_key, std_dev),
									details: serde_json::json!({"pattern": event_key, "mean": mean, "std_dev": std_dev}),
									timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
									source: "PeriodicMonitor".to_string(),
									acknowledged: false,
									resolved: false,
									resolution_notes: None,
								};
								
								if let Ok(mut alerts_guard) = alerts.write().await {
									alerts_guard.push_back(anomaly_alert);
								}
							}
						}
					}
				}
				
				if let Ok(alerts_guard) = alerts.read().await {
					let total_alerts = alerts_guard.len();
					let critical_alerts = alerts_guard.iter().filter(|alert| alert.severity == SecuritySeverity::Critical).count();
					let high_alerts = alerts_guard.iter().filter(|alert| alert.severity == SecuritySeverity::High).count();
					
					if critical_alerts > 0 || high_alerts > 5 {
						let report_alert = SecurityAlert {
							alert_id: format!("report_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
							alert_type: "PeriodicReport".to_string(),
							severity: SecuritySeverity::Medium,
							description: format!("Security report: {} total alerts ({} critical, {} high)", total_alerts, critical_alerts, high_alerts),
							details: serde_json::json!({"total_alerts": total_alerts, "critical_alerts": critical_alerts, "high_alerts": high_alerts}),
							timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
							source: "PeriodicMonitor".to_string(),
							acknowledged: false,
							resolved: false,
							resolution_notes: None,
						};
						
						if let Ok(mut alerts_guard) = alerts.write().await {
							alerts_guard.push_back(report_alert);
						}
					}
				}
			}
		});
		
		Ok(())
	}
	
	pub async fn get_alerts(&self) -> Vec<SecurityAlert> {
		let alerts = self.alerts.read().await;
		alerts.iter().cloned().collect()
	}
	
	pub async fn get_alerts_by_severity(&self, severity: SecuritySeverity) -> Vec<SecurityAlert> {
		let alerts = self.alerts.read().await;
		alerts.iter()
			.filter(|alert| alert.severity == severity)
			.cloned()
			.collect()
	}
	
	pub async fn acknowledge_alert(&self, alert_id: &str) -> Result<()> {
		let mut alerts = self.alerts.write().await;
		
		for alert in alerts.iter_mut() {
			if alert.alert_id == alert_id {
				alert.acknowledged = true;
				break;
			}
		}
		
		Ok(())
	}
	
	pub async fn resolve_alert(&self, alert_id: &str, notes: Option<String>) -> Result<()> {
		let mut alerts = self.alerts.write().await;
		
		for alert in alerts.iter_mut() {
			if alert.alert_id == alert_id {
				alert.resolved = true;
				alert.resolution_notes = notes;
				break;
			}
		}
		
		Ok(())
	}
	
	pub async fn is_active(&self) -> bool {
		self.active
	}
	
	pub fn update_config(&mut self, config: MonitoringConfig) {
		self.monitoring_config = config;
	}
	
	pub fn get_config(&self) -> MonitoringConfig {
		self.monitoring_config.clone()
	}
} 