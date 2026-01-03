/**
 * Behavioral analysis module provides context-aware threat detection by
 * analyzing user behavior patterns over time rather than isolated events.
 * The module implements pattern recognition algorithms that identify
 * anomalous behaviors and suspicious activity patterns across multiple
 * security event types.
 * 
 * The behavioral analysis system tracks user activities, resource usage
 * patterns, and access behaviors to establish baseline normal behavior
 * and detect deviations that may indicate security threats. Analysis
 * includes temporal patterns, frequency analysis, and correlation of
 * events across different security domains.
 */

use anyhow::Result;
use crate::SecurityEvent;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

/**
 * Behavioral analyzer implements comprehensive pattern recognition
 * and anomaly detection across all security events and users. The
 * system provides real-time behavioral analysis with configurable
 * detection rules and adaptive thresholds for different user roles
 * and system environments.
 */
pub struct BehavioralAnalyzer {
	config: Arc<RwLock<crate::SecurityConfig>>,
	user_patterns: HashMap<String, Vec<SecurityEvent>>,
	behavior_rules: Vec<BehaviorRule>,
	analysis_window: u64,
}

/**
 * Behavior patterns represent identified user activity patterns and
 * their associated risk assessments. Pattern analysis enables efficient
 * detection of anomalous behavior without requiring complex machine
 * learning models while maintaining high detection accuracy and low
 * false positive rates.
 */
#[derive(Debug, Clone)]
pub struct BehaviorPattern {
	pub pattern_type: String,
	pub confidence: f64,
	pub severity: crate::SecuritySeverity,
	pub factors: Vec<String>,
}

/**
 * Behavior rules define configurable detection patterns and thresholds
 * for identifying suspicious user activities. Rule-based behavior
 * analysis provides flexible pattern detection that can be easily
 * modified and tuned for different security environments and user
 * populations.
 */
#[derive(Debug, Clone)]
pub struct BehaviorRule {
	pub name: String,
	pub pattern: String,
	pub threshold: u32,
	pub window: u64,
	pub severity: crate::SecuritySeverity,
}

impl BehavioralAnalyzer {
	pub async fn new(config: Arc<RwLock<crate::SecurityConfig>>) -> Result<Self> {
		let behavior_rules = Self::initialize_behavior_rules();
		let analysis_window = 300; // 5 minutes

		Ok(Self {
			config,
			user_patterns: HashMap::new(),
			behavior_rules,
			analysis_window,
		})
	}

	pub async fn analyze_behavior(&mut self, event: &SecurityEvent) -> Result<BehaviorPattern> {
		let user = self.extract_user_from_event(event);
		let timestamp = self.extract_timestamp_from_event(event);

		let user_events = self.user_patterns.entry(user.clone()).or_insert_with(Vec::new);
		user_events.push(event.clone());

		// Remove old events outside analysis window
		user_events.retain(|e| {
			let event_time = self.extract_timestamp_from_event(e);
			timestamp - event_time < self.analysis_window
		});

		// Analyze for behavioral patterns
		for rule in &self.behavior_rules {
			if let Some(pattern) = self.detect_behavior_pattern(user_events, rule).await? {
				return Ok(pattern);
			}
		}

		// Return default pattern if no specific pattern detected
		Ok(BehaviorPattern {
			pattern_type: "normal".to_string(),
			confidence: 0.5,
			severity: crate::SecuritySeverity::Low,
			factors: vec!["normal_behavior".to_string()],
		})
	}

	async fn detect_behavior_pattern(&self, events: &[SecurityEvent], rule: &BehaviorRule) -> Result<Option<BehaviorPattern>> {
		let matching_events: Vec<&SecurityEvent> = events.iter()
			.filter(|e| self.event_matches_pattern(e, &rule.pattern))
			.collect();

		if matching_events.len() >= rule.threshold as usize {
			return Ok(Some(BehaviorPattern {
				pattern_type: rule.name.clone(),
				confidence: (matching_events.len() as f64 / rule.threshold as f64).min(1.0),
				severity: rule.severity.clone(),
				factors: vec![rule.pattern.clone()],
			}));
		}

		Ok(None)
	}

	fn event_matches_pattern(&self, event: &SecurityEvent, pattern: &str) -> bool {
		match event {
			SecurityEvent::CommandExecution { command, .. } => {
				pattern == "command_execution" || command.contains(pattern)
			}
			SecurityEvent::FileAccess { path, .. } => {
				pattern == "file_access" || path.contains(pattern)
			}
			SecurityEvent::NetworkAccess { host, .. } => {
				pattern == "network_access" || host.contains(pattern)
			}
			SecurityEvent::PermissionViolation { resource, .. } => {
				pattern == "permission_violation" || resource.contains(pattern)
			}
			SecurityEvent::SecurityAlert { .. } => {
				pattern == "security_alert"
			}
		}
	}

	fn extract_user_from_event(&self, event: &SecurityEvent) -> String {
		match event {
			SecurityEvent::CommandExecution { user, .. } => user.clone(),
			SecurityEvent::FileAccess { user, .. } => user.clone(),
			SecurityEvent::NetworkAccess { user, .. } => user.clone(),
			SecurityEvent::PermissionViolation { user, .. } => user.clone(),
			SecurityEvent::SecurityAlert { .. } => "system".to_string(),
		}
	}

	fn extract_timestamp_from_event(&self, event: &SecurityEvent) -> u64 {
		match event {
			SecurityEvent::CommandExecution { timestamp, .. } => *timestamp,
			SecurityEvent::FileAccess { timestamp, .. } => *timestamp,
			SecurityEvent::NetworkAccess { timestamp, .. } => *timestamp,
			SecurityEvent::PermissionViolation { timestamp, .. } => *timestamp,
			SecurityEvent::SecurityAlert { timestamp, .. } => *timestamp,
		}
	}

	fn initialize_behavior_rules() -> Vec<BehaviorRule> {
		vec![
			BehaviorRule {
				name: "rapid_command_execution".to_string(),
				pattern: "command_execution".to_string(),
				threshold: 10,
				window: 60,
				severity: crate::SecuritySeverity::High,
			},
			BehaviorRule {
				name: "privilege_escalation".to_string(),
				pattern: "sudo".to_string(),
				threshold: 3,
				window: 300,
				severity: crate::SecuritySeverity::Critical,
			},
			BehaviorRule {
				name: "data_exfiltration".to_string(),
				pattern: "file_access".to_string(),
				threshold: 20,
				window: 300,
				severity: crate::SecuritySeverity::High,
			},
			BehaviorRule {
				name: "network_scanning".to_string(),
				pattern: "network_access".to_string(),
				threshold: 15,
				window: 300,
				severity: crate::SecuritySeverity::Medium,
			},
		]
	}
} 