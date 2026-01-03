/**
 * Response automation module implements intelligent threat response selection
 * and execution based on threat analysis results and system policies. The
 * module provides rule-based and automated response capabilities that ensure
 * consistent and appropriate security measures are applied across all threat
 * scenarios.
 * 
 * The response automation system evaluates security events against predefined
 * rules and triggers to determine appropriate response actions. Response
 * selection considers threat severity, attack vectors, and system context
 * to provide targeted security measures while minimizing false positives.
 */

use anyhow::Result;
use crate::{SecurityEvent, SecuritySeverity, ThreatResponseAction};
use crate::threat_detection::{ThreatType, ThreatScore};
use crate::behavioral_analysis::BehaviorPattern;
use std::sync::Arc;
use tokio::sync::RwLock;

/**
 * Response automation system coordinates threat response across all security
 * components by evaluating events against response rules and automated
 * triggers. The system ensures consistent response application and provides
 * policy-based action selection for different threat scenarios.
 */
pub struct ResponseAutomation {
	config: Arc<RwLock<crate::SecurityConfig>>,
	response_rules: Vec<ResponseRule>,
	automated_responses: Vec<AutomatedResponse>,
}

/**
 * Response rules define policy-based response actions for specific threat
 * conditions and scenarios. Rule-based responses provide flexible and
 * configurable threat response policies that can be easily modified to
 * adapt to changing security requirements and threat landscapes.
 */
#[derive(Debug, Clone)]
pub struct ResponseRule {
	pub name: String,
	pub conditions: Vec<String>,
	pub actions: Vec<ThreatResponseAction>,
	pub priority: u32,
	pub enabled: bool,
}

/**
 * Automated responses provide immediate action capabilities for common
 * threat scenarios without requiring manual intervention. Pre-configured
 * responses enable rapid threat containment while maintaining system
 * availability and reducing response time for critical security events.
 */
#[derive(Debug, Clone)]
pub struct AutomatedResponse {
	pub name: String,
	pub triggers: Vec<String>,
	pub actions: Vec<ThreatResponseAction>,
	pub delay: u64,
	pub enabled: bool,
}

impl ResponseAutomation {
	pub async fn new(config: Arc<RwLock<crate::SecurityConfig>>) -> Result<Self> {
		let response_rules = Self::initialize_response_rules();
		let automated_responses = Self::initialize_automated_responses();

		Ok(Self {
			config,
			response_rules,
			automated_responses,
		})
	}

	pub async fn determine_response(
		&self,
		event: &SecurityEvent,
		threat_score: ThreatScore,
		threat_type: ThreatType,
		behavior_pattern: &BehaviorPattern,
	) -> Result<Vec<ThreatResponseAction>> {
		let mut actions = Vec::new();

		match threat_type {
			ThreatType::CriticalIntrusion => {
				actions.push(ThreatResponseAction::SilentShutdown);
				actions.push(ThreatResponseAction::ForensicCapture);
				actions.push(ThreatResponseAction::CounterAttack);
				actions.push(ThreatResponseAction::Deception);
				actions.push(ThreatResponseAction::Honeypot);
			}
			ThreatType::DataExfiltration => {
				actions.push(ThreatResponseAction::Block);
				actions.push(ThreatResponseAction::Terminate);
				actions.push(ThreatResponseAction::Isolate);
				actions.push(ThreatResponseAction::ForensicCapture);
			}
			ThreatType::PrivilegeEscalation => {
				actions.push(ThreatResponseAction::Terminate);
				actions.push(ThreatResponseAction::Isolate);
				actions.push(ThreatResponseAction::Alert);
				if threat_score.value > 0.8 {
					actions.push(ThreatResponseAction::CounterAttack);
				}
			}
			ThreatType::MalwareExecution => {
				actions.push(ThreatResponseAction::Terminate);
				actions.push(ThreatResponseAction::Block);
				actions.push(ThreatResponseAction::Isolate);
				actions.push(ThreatResponseAction::ForensicCapture);
				actions.push(ThreatResponseAction::Deception);
			}
			ThreatType::NetworkAttack => {
				actions.push(ThreatResponseAction::Block);
				actions.push(ThreatResponseAction::CounterAttack);
				actions.push(ThreatResponseAction::Alert);
				if threat_score.value > 0.7 {
					actions.push(ThreatResponseAction::Honeypot);
				}
			}
			ThreatType::SuspiciousActivity => {
				actions.push(ThreatResponseAction::Log);
				actions.push(ThreatResponseAction::Alert);
				if threat_score.value > 0.6 {
					actions.push(ThreatResponseAction::Deception);
				}
			}
		}

		actions.extend(self.check_automated_responses(event).await?);
		actions.extend(self.check_response_rules(event, &threat_score).await?);

		Ok(actions)
	}

	async fn check_automated_responses(&self, event: &SecurityEvent) -> Result<Vec<ThreatResponseAction>> {
		let mut actions = Vec::new();

		for response in &self.automated_responses {
			if response.enabled && self.matches_triggers(event, &response.triggers).await? {
				actions.extend(response.actions.clone());
			}
		}

		Ok(actions)
	}

	async fn check_response_rules(&self, event: &SecurityEvent, threat_score: &ThreatScore) -> Result<Vec<ThreatResponseAction>> {
		let mut actions = Vec::new();

		for rule in &self.response_rules {
			if rule.enabled && self.matches_conditions(event, &rule.conditions, threat_score).await? {
				actions.extend(rule.actions.clone());
			}
		}

		Ok(actions)
	}

	async fn matches_triggers(&self, event: &SecurityEvent, triggers: &[String]) -> Result<bool> {
		for trigger in triggers {
			match event {
				SecurityEvent::CommandExecution { command, .. } => {
					if command.contains(trigger) {
						return Ok(true);
					}
				}
				SecurityEvent::FileAccess { path, .. } => {
					if path.contains(trigger) {
						return Ok(true);
					}
				}
				SecurityEvent::NetworkAccess { host, .. } => {
					if host.contains(trigger) {
						return Ok(true);
					}
				}
				_ => {}
			}
		}
		Ok(false)
	}

	async fn matches_conditions(&self, event: &SecurityEvent, conditions: &[String], threat_score: &ThreatScore) -> Result<bool> {
		for condition in conditions {
			match event {
				SecurityEvent::CommandExecution { command, .. } => {
					if command.contains(condition) {
						return Ok(true);
					}
				}
				SecurityEvent::FileAccess { path, .. } => {
					if path.contains(condition) {
						return Ok(true);
					}
				}
				SecurityEvent::NetworkAccess { host, .. } => {
					if host.contains(condition) {
						return Ok(true);
					}
				}
				_ => {}
			}

			if condition == "high_threat_score" && threat_score.value > 0.8 {
				return Ok(true);
			}
		}
		Ok(false)
	}

	fn initialize_response_rules() -> Vec<ResponseRule> {
		vec![
			ResponseRule {
				name: "critical_threat_response".to_string(),
				conditions: vec!["high_threat_score".to_string()],
				actions: vec![
					ThreatResponseAction::SilentShutdown,
					ThreatResponseAction::ForensicCapture,
				],
				priority: 1,
				enabled: true,
			},
			ResponseRule {
				name: "privilege_escalation_response".to_string(),
				conditions: vec!["sudo".to_string(), "su".to_string()],
				actions: vec![
					ThreatResponseAction::Terminate,
					ThreatResponseAction::Alert,
				],
				priority: 2,
				enabled: true,
			},
			ResponseRule {
				name: "network_attack_response".to_string(),
				conditions: vec!["nmap".to_string(), "netcat".to_string()],
				actions: vec![
					ThreatResponseAction::Block,
					ThreatResponseAction::CounterAttack,
				],
				priority: 3,
				enabled: true,
			},
		]
	}

	fn initialize_automated_responses() -> Vec<AutomatedResponse> {
		vec![
			AutomatedResponse {
				name: "destructive_command_response".to_string(),
				triggers: vec!["rm -rf".to_string(), "dd if=".to_string()],
				actions: vec![
					ThreatResponseAction::Terminate,
					ThreatResponseAction::SilentShutdown,
				],
				delay: 0,
				enabled: true,
			},
			AutomatedResponse {
				name: "sensitive_file_access_response".to_string(),
				triggers: vec!["/etc/passwd".to_string(), "/etc/shadow".to_string()],
				actions: vec![
					ThreatResponseAction::Alert,
					ThreatResponseAction::ForensicCapture,
				],
				delay: 5,
				enabled: true,
			},
		]
	}
} 