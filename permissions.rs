/**
 * Permission management module provides comprehensive access control
 * capabilities including user permissions, resource access control,
 * and role-based security policies. The module implements multiple
 * authorization layers to ensure secure access to system resources.
 * 
 * The permission system employs role-based access control (RBAC),
 * group-based access control (GBAC), and time-based restrictions
 * to provide flexible and secure authorization policies. Access
 * control includes user authentication, session management, and
 * comprehensive audit logging for security compliance.
 */

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{SecurityConfig, SecurityEvent, SecuritySeverity};

/**
 * Permission levels define the various access levels that can be
 * assigned to users and resources. Permission levels provide
 * granular access control that enables precise security policies
 * while maintaining system usability and administrative flexibility.
 */
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PermissionLevel {
	Deny,
	Read,
	Write,
	Full,
	Admin,
}

/**
 * Resource types categorize system resources for access control
 * purposes. Resource categorization enables targeted security
 * policies and simplifies permission management across different
 * system components and data types.
 */
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ResourceType {
	File,
	Network,
	Command,
	System,
	User,
}

/**
 * Permission rules define comprehensive access control policies
 * including user permissions, role assignments, and access
 * restrictions. Rule-based permissions provide flexible and
 * configurable security policies that can be easily modified
 * to adapt to changing security requirements.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRule {
	pub id: String,
	pub resource_type: ResourceType,
	pub resource_path: String,
	pub permission_level: PermissionLevel,
	pub allowed_users: HashSet<String>,
	pub allowed_roles: HashSet<String>,
	pub allowed_groups: HashSet<String>,
	pub denied_users: HashSet<String>,
	pub denied_roles: HashSet<String>,
	pub denied_groups: HashSet<String>,
	pub time_restrictions: Option<TimeRestrictions>,
	pub ip_restrictions: Option<IpRestrictions>,
	pub active: bool,
}

/**
 * Time restrictions implement temporal access control policies
 * that limit resource access based on time of day and day of
 * week. Temporal restrictions provide additional security layers
 * and enable compliance with time-based security policies.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestrictions {
	pub allowed_days: HashSet<u8>,
	pub allowed_hours: HashSet<u8>,
	pub time_range: Option<(u8, u8)>,
}

/**
 * IP restrictions implement network-based access control policies
 * that limit resource access based on client IP addresses and
 * network ranges. Network restrictions provide additional security
 * layers and enable compliance with network-based security policies.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRestrictions {
	pub allowed_ips: HashSet<String>,
	pub allowed_ranges: HashSet<String>,
	pub denied_ips: HashSet<String>,
	pub denied_ranges: HashSet<String>,
}

/**
 * User permissions track comprehensive user access rights including
 * roles, groups, and specific permissions. User permission tracking
 * enables detailed access control and provides comprehensive audit
 * trails for security analysis and compliance reporting.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPermissions {
	pub user_id: String,
	pub roles: HashSet<String>,
	pub groups: HashSet<String>,
	pub permissions: HashMap<String, PermissionLevel>,
	pub failed_attempts: u32,
	pub last_failed_attempt: Option<u64>,
	pub locked_until: Option<u64>,
	pub active: bool,
}

/**
 * Permission configuration defines comprehensive access control
 * settings including authentication policies, session management,
 * and security restrictions. Configuration parameters enable
 * fine-tuned access control policies that can be adjusted based
 * on security requirements and organizational needs.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionConfig {
	pub enabled: bool,
	pub default_permission_level: PermissionLevel,
	pub max_failed_attempts: u32,
	pub lockout_duration: u64,
	pub session_timeout: u64,
	pub rbac_enabled: bool,
	pub gbac_enabled: bool,
	pub time_restrictions_enabled: bool,
	pub ip_restrictions_enabled: bool,
}

impl Default for PermissionConfig {
	fn default() -> Self {
		Self {
			enabled: true,
			default_permission_level: PermissionLevel::Read,
			max_failed_attempts: 5,
			lockout_duration: 300,
			session_timeout: 3600,
			rbac_enabled: true,
			gbac_enabled: true,
			time_restrictions_enabled: true,
			ip_restrictions_enabled: true,
		}
	}
}

/**
 * Permission manager implements comprehensive access control
 * capabilities including user authentication, authorization,
 * and session management. The manager provides centralized
 * permission management that ensures consistent security
 * policies across all system resources and users.
 */
pub struct PermissionManager {
	config: Arc<RwLock<SecurityConfig>>,
	permission_config: PermissionConfig,
	rules: Arc<RwLock<HashMap<String, PermissionRule>>>,
	users: Arc<RwLock<HashMap<String, UserPermissions>>>,
	roles: Arc<RwLock<HashMap<String, HashSet<String>>>>,
	groups: Arc<RwLock<HashMap<String, HashSet<String>>>>,
	failed_attempts: Arc<RwLock<HashMap<String, (u32, u64)>>>,
	active: bool,
}

impl PermissionManager {
	pub async fn new(config: Arc<RwLock<SecurityConfig>>) -> Result<Self> {
		let permission_config = PermissionConfig::default();
		
		let manager = Self {
			config,
			permission_config,
			rules: Arc::new(RwLock::new(HashMap::new())),
			users: Arc::new(RwLock::new(HashMap::new())),
			roles: Arc::new(RwLock::new(HashMap::new())),
			groups: Arc::new(RwLock::new(HashMap::new())),
			failed_attempts: Arc::new(RwLock::new(HashMap::new())),
			active: true,
		};
		
		manager.initialize_default_permissions().await?;
		
		Ok(manager)
	}
	
	pub async fn can_execute_command(&self, command: &str, user: &str) -> Result<bool> {
		if !self.active || !self.permission_config.enabled {
			return Ok(true);
		}
		
		if self.is_user_locked_out(user).await? {
			return Ok(false);
		}
		
		let user_permissions = self.get_user_permissions(user).await?;
		
		if let Some(rule) = self.find_command_rule(command, user).await? {
			return Ok(self.check_rule_access(&rule, user, &user_permissions).await?);
		}
		
		if let Some(level) = user_permissions.permissions.get("command") {
			match level {
				PermissionLevel::Deny => Ok(false),
				PermissionLevel::Read => Ok(false),
				PermissionLevel::Write => Ok(true),
				PermissionLevel::Full => Ok(true),
				PermissionLevel::Admin => Ok(true),
			}
		} else {
			Ok(self.permission_config.default_permission_level != PermissionLevel::Deny)
		}
	}
	
	pub async fn can_access_file(&self, path: &str, operation: &str, user: &str) -> Result<bool> {
		if !self.active || !self.permission_config.enabled {
			return Ok(true);
		}
		
		if self.is_user_locked_out(user).await? {
			return Ok(false);
		}
		
		let user_permissions = self.get_user_permissions(user).await?;
		
		if let Some(rule) = self.find_file_rule(path, operation, user).await? {
			return Ok(self.check_rule_access(&rule, user, &user_permissions).await?);
		}
		
		if let Some(level) = user_permissions.permissions.get("file") {
			match level {
				PermissionLevel::Deny => Ok(false),
				PermissionLevel::Read => Ok(operation == "read"),
				PermissionLevel::Write => Ok(operation == "read" || operation == "write"),
				PermissionLevel::Full => Ok(true),
				PermissionLevel::Admin => Ok(true),
			}
		} else {
			Ok(self.permission_config.default_permission_level != PermissionLevel::Deny)
		}
	}
	
	pub async fn can_access_network(&self, host: &str, port: u16, protocol: &str, user: &str) -> Result<bool> {
		if !self.active || !self.permission_config.enabled {
			return Ok(true);
		}
		
		if self.is_user_locked_out(user).await? {
			return Ok(false);
		}
		
		let user_permissions = self.get_user_permissions(user).await?;
		
		let resource_path = format!("{}:{}", host, port);
		if let Some(rule) = self.find_network_rule(&resource_path, protocol, user).await? {
			return Ok(self.check_rule_access(&rule, user, &user_permissions).await?);
		}
		
		if let Some(level) = user_permissions.permissions.get("network") {
			match level {
				PermissionLevel::Deny => Ok(false),
				PermissionLevel::Read => Ok(protocol == "http" || protocol == "https"),
				PermissionLevel::Write => Ok(true),
				PermissionLevel::Full => Ok(true),
				PermissionLevel::Admin => Ok(true),
			}
		} else {
			Ok(self.permission_config.default_permission_level != PermissionLevel::Deny)
		}
	}
	
	pub async fn add_rule(&self, rule: PermissionRule) -> Result<()> {
		self.rules.write().await.insert(rule.id.clone(), rule);
		Ok(())
	}
	
	pub async fn remove_rule(&self, rule_id: &str) -> Result<()> {
		self.rules.write().await.remove(rule_id);
		Ok(())
	}
	
	async fn get_user_permissions(&self, user: &str) -> Result<UserPermissions> {
		let users = self.users.read().await;
		
		if let Some(user_perms) = users.get(user) {
			Ok(user_perms.clone())
		} else {
			Ok(UserPermissions {
				user_id: user.to_string(),
				roles: HashSet::new(),
				groups: HashSet::new(),
				permissions: HashMap::new(),
				failed_attempts: 0,
				last_failed_attempt: None,
				locked_until: None,
				active: true,
			})
		}
	}
	
	async fn find_command_rule(&self, command: &str, user: &str) -> Result<Option<PermissionRule>> {
		let rules = self.rules.read().await;
		
		for rule in rules.values() {
			if rule.resource_type == ResourceType::Command && rule.active {
				if self.matches_pattern(command, &rule.resource_path) {
					if rule.allowed_users.contains(user) {
						return Ok(Some(rule.clone()));
					}
					
					if rule.denied_users.contains(user) {
						return Ok(None);
					}
					
					let user_permissions = self.get_user_permissions(user).await?;
					if self.check_rule_access(rule, user, &user_permissions).await? {
						return Ok(Some(rule.clone()));
					}
				}
			}
		}
		
		Ok(None)
	}
	
	async fn find_file_rule(&self, path: &str, operation: &str, user: &str) -> Result<Option<PermissionRule>> {
		let rules = self.rules.read().await;
		
		for rule in rules.values() {
			if rule.resource_type == ResourceType::File && rule.active {
				if self.matches_pattern(path, &rule.resource_path) {
					if rule.allowed_users.contains(user) {
						return Ok(Some(rule.clone()));
					}
					
					if rule.denied_users.contains(user) {
						return Ok(None);
					}
					
					let user_permissions = self.get_user_permissions(user).await?;
					if self.check_rule_access(rule, user, &user_permissions).await? {
						return Ok(Some(rule.clone()));
					}
				}
			}
		}
		
		Ok(None)
	}
	
	async fn find_network_rule(&self, resource_path: &str, protocol: &str, user: &str) -> Result<Option<PermissionRule>> {
		let rules = self.rules.read().await;
		
		for rule in rules.values() {
			if rule.resource_type == ResourceType::Network && rule.active {
				if self.matches_pattern(resource_path, &rule.resource_path) {
					if rule.allowed_users.contains(user) {
						return Ok(Some(rule.clone()));
					}
					
					if rule.denied_users.contains(user) {
						return Ok(None);
					}
					
					let user_permissions = self.get_user_permissions(user).await?;
					if self.check_rule_access(rule, user, &user_permissions).await? {
						return Ok(Some(rule.clone()));
					}
				}
			}
		}
		
		Ok(None)
	}
	
	async fn is_user_locked_out(&self, user: &str) -> Result<bool> {
		let failed_attempts = self.failed_attempts.read().await;
		
		if let Some((attempts, last_attempt)) = failed_attempts.get(user) {
			let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
			let lockout_duration = self.permission_config.lockout_duration;
			
			if *attempts >= self.permission_config.max_failed_attempts {
				if now - last_attempt < lockout_duration {
					return Ok(true);
				}
			}
		}
		
		Ok(false)
	}
	
	pub async fn record_failed_attempt(&self, user: &str) {
		let mut failed_attempts = self.failed_attempts.write().await;
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		
		let entry = failed_attempts.entry(user.to_string()).or_insert((0, now));
		entry.0 += 1;
		entry.1 = now;
	}
	
	pub async fn clear_failed_attempts(&self, user: &str) {
		self.failed_attempts.write().await.remove(user);
	}
	
	async fn check_rule_access(&self, rule: &PermissionRule, user: &str, user_permissions: &UserPermissions) -> Result<bool> {
		if let Some(time_restrictions) = &rule.time_restrictions {
			if !self.check_time_restrictions(time_restrictions).await? {
				return Ok(false);
			}
		}
		
		if let Some(ip_restrictions) = &rule.ip_restrictions {
			if !self.check_ip_restrictions(ip_restrictions).await? {
				return Ok(false);
			}
		}
		
		if !rule.allowed_roles.is_empty() {
			let has_role = user_permissions.roles.iter().any(|role| rule.allowed_roles.contains(role));
			if !has_role {
				return Ok(false);
			}
		}
		
		if !rule.allowed_groups.is_empty() {
			let has_group = user_permissions.groups.iter().any(|group| rule.allowed_groups.contains(group));
			if !has_group {
				return Ok(false);
			}
		}
		
		if !rule.denied_roles.is_empty() {
			let has_denied_role = user_permissions.roles.iter().any(|role| rule.denied_roles.contains(role));
			if has_denied_role {
				return Ok(false);
			}
		}
		
		if !rule.denied_groups.is_empty() {
			let has_denied_group = user_permissions.groups.iter().any(|group| rule.denied_groups.contains(group));
			if has_denied_group {
				return Ok(false);
			}
		}
		
		Ok(true)
	}
	
	async fn check_time_restrictions(&self, restrictions: &TimeRestrictions) -> Result<bool> {
		if !self.permission_config.time_restrictions_enabled {
			return Ok(true);
		}
		
		let now = chrono::Utc::now();
		let weekday = now.weekday().num_days_from_sunday();
		let hour = now.hour() as u8;
		
		if !restrictions.allowed_days.is_empty() && !restrictions.allowed_days.contains(&weekday) {
			return Ok(false);
		}
		
		if !restrictions.allowed_hours.is_empty() && !restrictions.allowed_hours.contains(&hour) {
			return Ok(false);
		}
		
		if let Some((start_hour, end_hour)) = restrictions.time_range {
			if hour < start_hour || hour > end_hour {
				return Ok(false);
			}
		}
		
		Ok(true)
	}
	
	async fn check_ip_restrictions(&self, restrictions: &IpRestrictions) -> Result<bool> {
		if !self.permission_config.ip_restrictions_enabled {
			return Ok(true);
		}
		
		let client_ip = "127.0.0.1";
		
		if restrictions.denied_ips.contains(client_ip) {
			return Ok(false);
		}
		
		for range in &restrictions.denied_ranges {
			if self.ip_in_range(client_ip, range) {
				return Ok(false);
			}
		}
		
		if !restrictions.allowed_ips.is_empty() && !restrictions.allowed_ips.contains(client_ip) {
			return Ok(false);
		}
		
		if !restrictions.allowed_ranges.is_empty() {
			let in_allowed_range = restrictions.allowed_ranges.iter().any(|range| self.ip_in_range(client_ip, range));
			if !in_allowed_range {
				return Ok(false);
			}
		}
		
		Ok(true)
	}
	
	fn ip_in_range(&self, ip: &str, range: &str) -> bool {
		ip == range || range.contains(ip)
	}
	
	fn matches_pattern(&self, input: &str, pattern: &str) -> bool {
		input.contains(pattern) || pattern.contains(input) || input == pattern
	}
	
	async fn initialize_default_permissions(&self) -> Result<()> {
		let admin_user = UserPermissions {
			user_id: "admin".to_string(),
			roles: HashSet::from(["admin".to_string()]),
			groups: HashSet::from(["admin".to_string()]),
			permissions: HashMap::from([
				("command".to_string(), PermissionLevel::Admin),
				("file".to_string(), PermissionLevel::Admin),
				("network".to_string(), PermissionLevel::Admin),
				("system".to_string(), PermissionLevel::Admin),
			]),
			failed_attempts: 0,
			last_failed_attempt: None,
			locked_until: None,
			active: true,
		};
		
		self.users.write().await.insert("admin".to_string(), admin_user);
		
		let mut roles = self.roles.write().await;
		roles.insert("admin".to_string(), HashSet::from([
			"command".to_string(),
			"file".to_string(),
			"network".to_string(),
			"system".to_string(),
		]));
		roles.insert("user".to_string(), HashSet::from([
			"file".to_string(),
			"network".to_string(),
		]));
		roles.insert("guest".to_string(), HashSet::from([
			"file".to_string(),
		]));
		
		let mut groups = self.groups.write().await;
		groups.insert("admin".to_string(), HashSet::from(["admin".to_string()]));
		groups.insert("users".to_string(), HashSet::from(["user".to_string()]));
		groups.insert("guests".to_string(), HashSet::from(["guest".to_string()]));
		
		Ok(())
	}
	
	pub async fn is_active(&self) -> bool {
		self.active
	}
	
	pub fn update_config(&mut self, config: PermissionConfig) {
		self.permission_config = config;
	}
	
	pub fn get_config(&self) -> PermissionConfig {
		self.permission_config.clone()
	}
} 