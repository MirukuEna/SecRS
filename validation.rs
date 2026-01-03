/**
 * Input validation and sanitization module provides comprehensive security
 * validation for commands, file paths, network hosts, and URLs to prevent
 * injection attacks and malicious input processing. The module implements
 * multiple validation layers including pattern matching, size limits, and
 * content sanitization to ensure secure input handling across all system
 * components.
 * 
 * The validation system employs regex-based pattern matching, length
 * restrictions, and dangerous character filtering to prevent command
 * injection, path traversal, and other input-based security vulnerabilities.
 * Validation rules are configurable and can be adapted to different security
 * requirements and threat landscapes.
 */

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use regex::Regex;
use url::Url;

use super::{SecurityConfig, SecurityEvent, SecuritySeverity};

/**
 * Validation configuration defines comprehensive input validation settings
 * including size limits, allowed patterns, and blocked content rules.
 * Configuration parameters enable fine-tuned validation policies that
 * can be adjusted based on security requirements and system constraints.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
	pub command_validation: bool,
	pub path_validation: bool,
	pub host_validation: bool,
	pub url_validation: bool,
	pub size_validation: bool,
	pub max_command_length: usize,
	pub max_path_length: usize,
	pub max_host_length: usize,
	pub max_url_length: usize,
	pub max_file_size: u64,
	pub allowed_extensions: Vec<String>,
	pub blocked_patterns: Vec<String>,
}

impl Default for ValidationConfig {
	fn default() -> Self {
		Self {
			command_validation: true,
			path_validation: true,
			host_validation: true,
			url_validation: true,
			size_validation: true,
			max_command_length: 1024,
			max_path_length: 4096,
			max_host_length: 253,
			max_url_length: 2048,
			max_file_size: 100 * 1024 * 1024,
			allowed_extensions: vec![
				"txt".to_string(), "md".to_string(), "rs".to_string(),
				"toml".to_string(), "json".to_string(), "yaml".to_string(),
				"yml".to_string(), "sh".to_string(), "py".to_string(),
				"js".to_string(), "ts".to_string(), "html".to_string(),
				"css".to_string(), "xml".to_string(), "log".to_string(),
			],
			blocked_patterns: vec![
				r"rm\s+-rf\s+/".to_string(),
				r"dd\s+if=/dev/zero".to_string(),
				r":\(\)\s*\{\s*:\|\s*:\s*&\s*\};\s*:".to_string(),
				r"forkbomb".to_string(),
				r"mkfs".to_string(),
				r"fdisk".to_string(),
				r"dd\s+if=".to_string(),
			],
		}
	}
}

/**
 * Validation patterns implement regex-based pattern matching for input
 * validation across different data types. Pattern matching provides
 * efficient validation without requiring complex parsing while maintaining
 * high accuracy for detecting malicious input patterns.
 */
#[derive(Debug, Clone)]
pub struct ValidationPatterns {
	pub command_regex: Regex,
	pub path_regex: Regex,
	pub host_regex: Regex,
	pub url_regex: Regex,
	pub blocked_patterns: Vec<Regex>,
	pub dangerous_chars: Regex,
}

impl ValidationPatterns {
	pub fn new() -> Result<Self> {
		Ok(Self {
			command_regex: Regex::new(r"^[a-zA-Z0-9_\-\./\\\s]+$")?,
			path_regex: Regex::new(r"^[a-zA-Z0-9_\-\./\\\s]+$")?,
			host_regex: Regex::new(r"^[a-zA-Z0-9\-\.]+$")?,
			url_regex: Regex::new(r"^https?://[a-zA-Z0-9\-\.]+(:\d+)?(/[a-zA-Z0-9\-\./]*)?$")?,
			blocked_patterns: vec![
				Regex::new(r"rm\s+-rf\s+/")?,
				Regex::new(r"dd\s+if=/dev/zero")?,
				Regex::new(r":\(\)\s*\{\s*:\|\s*:\s*&\s*\};\s*:")?,
				Regex::new(r"forkbomb")?,
				Regex::new(r"mkfs")?,
				Regex::new(r"fdisk")?,
				Regex::new(r"dd\s+if=")?,
			],
			dangerous_chars: Regex::new(r"[;&|`$(){}[\]<>]")?,
		})
	}
}

/**
 * Input validator implements comprehensive input validation and sanitization
 * across all system inputs including commands, file paths, network addresses,
 * and URLs. The validator provides multiple validation layers and configurable
 * security policies to prevent injection attacks and malicious input processing.
 */
pub struct InputValidator {
	config: Arc<RwLock<SecurityConfig>>,
	validation_config: ValidationConfig,
	patterns: ValidationPatterns,
	active: bool,
}

impl InputValidator {
	pub async fn new(config: Arc<RwLock<SecurityConfig>>) -> Result<Self> {
		let validation_config = ValidationConfig::default();
		let patterns = ValidationPatterns::new()?;
		
		Ok(Self {
			config,
			validation_config,
			patterns,
			active: true,
		})
	}
	
	pub async fn validate_command(&self, command: &str) -> Result<bool> {
		if !self.active || !self.validation_config.command_validation {
			return Ok(true);
		}
		
		if command.len() > self.validation_config.max_command_length {
			return Ok(false);
		}
		
		for pattern in &self.patterns.blocked_patterns {
			if pattern.is_match(command) {
				return Ok(false);
			}
		}
		
		if self.patterns.dangerous_chars.is_match(command) {
			return Ok(false);
		}
		
		if !self.patterns.command_regex.is_match(command) {
			return Ok(false);
		}
		
		if command.contains(";") || command.contains("|") || command.contains("&") {
			return Ok(false);
		}
		
		if command.contains("../") || command.contains("..\\") {
			return Ok(false);
		}
		
		Ok(true)
	}
	
	pub async fn validate_path(&self, path: &str) -> Result<bool> {
		if !self.active || !self.validation_config.path_validation {
			return Ok(true);
		}
		
		if path.len() > self.validation_config.max_path_length {
			return Ok(false);
		}
		
		if path.contains("../") || path.contains("..\\") {
			return Ok(false);
		}
		
		let sensitive_dirs = vec!["/etc", "/var", "/sys", "/proc", "/dev"];
		for dir in sensitive_dirs {
			if path.starts_with(dir) {
				return Ok(false);
			}
		}
		
		if !self.patterns.path_regex.is_match(path) {
			return Ok(false);
		}
		
		if let Some(extension) = self.get_file_extension(path) {
			if !self.validation_config.allowed_extensions.contains(&extension) {
				return Ok(false);
			}
		}
		
		Ok(true)
	}
	
	pub async fn validate_host(&self, host: &str) -> Result<bool> {
		if !self.active || !self.validation_config.host_validation {
			return Ok(true);
		}
		
		if host.len() > self.validation_config.max_host_length {
			return Ok(false);
		}
		
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return Ok(false);
		}
		
		if host.starts_with("192.168.") || host.starts_with("10.") || host.starts_with("172.") {
			return Ok(false);
		}
		
		if !self.patterns.host_regex.is_match(host) {
			return Ok(false);
		}
		
		if self.is_ip_address(host) {
			return self.validate_ip_address(host);
		}
		
		if self.is_domain_name(host) {
			return self.validate_domain_name(host);
		}
		
		Ok(false)
	}
	
	pub async fn validate_url(&self, url: &str) -> Result<bool> {
		if !self.active || !self.validation_config.url_validation {
			return Ok(true);
		}
		
		if url.len() > self.validation_config.max_url_length {
			return Ok(false);
		}
		
		let parsed_url = match Url::parse(url) {
			Ok(url) => url,
			Err(_) => return Ok(false),
		};
		
		let scheme = parsed_url.scheme();
		if scheme != "http" && scheme != "https" {
			return Ok(false);
		}
		
		if let Some(host) = parsed_url.host_str() {
			if !self.validate_host(host).await? {
				return Ok(false);
			}
		}
		
		if !self.patterns.url_regex.is_match(url) {
			return Ok(false);
		}
		
		Ok(true)
	}
	
	pub fn sanitize_input(&self, input: &str) -> String {
		let sanitized = self.patterns.dangerous_chars.replace_all(input, "");
		let sanitized = sanitized.replace("../", "").replace("..\\", "");
		let sanitized = sanitized.replace(";", "").replace("|", "").replace("&", "");
		let sanitized = sanitized.replace("`", "");
		let sanitized = sanitized.replace("$", "");
		let sanitized = sanitized.replace("(", "").replace(")", "");
		let sanitized = sanitized.replace("[", "").replace("]", "");
		let sanitized = sanitized.replace("{", "").replace("}", "");
		let sanitized = sanitized.replace("<", "").replace(">", "");
		
		sanitized.to_string()
	}
	
	fn get_file_extension(&self, path: &str) -> Option<String> {
		path.split('.')
			.last()
			.map(|ext| ext.to_lowercase())
	}
	
	pub async fn validate_size(&self, size: u64) -> Result<bool> {
		if !self.active || !self.validation_config.size_validation {
			return Ok(true);
		}
		
		Ok(size <= self.validation_config.max_file_size)
	}
	
	pub async fn is_active(&self) -> bool {
		self.active
	}
	
	pub fn update_config(&mut self, config: ValidationConfig) {
		self.validation_config = config;
	}
	
	pub fn get_config(&self) -> ValidationConfig {
		self.validation_config.clone()
	}
	
	fn is_ip_address(&self, host: &str) -> bool {
		host.split('.').count() == 4 && host.chars().all(|c| c.is_ascii_digit() || c == '.')
	}
	
	fn validate_ip_address(&self, ip: &str) -> Result<bool> {
		if ip.starts_with("192.168.") || ip.starts_with("10.") || ip.starts_with("172.") {
			return Ok(false);
		}
		
		if ip == "127.0.0.1" || ip == "::1" {
			return Ok(false);
		}
		
		let parts: Vec<&str> = ip.split('.').collect();
		if parts.len() != 4 {
			return Ok(false);
		}
		
		for part in parts {
			if let Ok(num) = part.parse::<u8>() {
				if num > 255 {
					return Ok(false);
				}
			} else {
				return Ok(false);
			}
		}
		
		Ok(true)
	}
	
	fn is_domain_name(&self, host: &str) -> bool {
		host.contains('.') && !host.starts_with('.') && !host.ends_with('.')
	}
	
	fn validate_domain_name(&self, domain: &str) -> Result<bool> {
		if domain == "localhost" {
			return Ok(false);
		}
		
		if !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
			return Ok(false);
		}
		
		if domain.contains("..") {
			return Ok(false);
		}
		
		let parts: Vec<&str> = domain.split('.').collect();
		if parts.len() < 2 {
			return Ok(false);
		}
		
		for part in parts {
			if part.is_empty() || part.len() > 63 {
				return Ok(false);
			}
			
			if part.starts_with('-') || part.ends_with('-') {
				return Ok(false);
			}
		}
		
		Ok(true)
	}
} 