/**
 * Advanced memory forensics module for deep system analysis
 * 
 * Provides comprehensive memory analysis capabilities including process
 * memory scanning, malware detection, and memory-based threat hunting.
 * 
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 * File: memory_forensics.rs
 * Description: Memory forensics and analysis for advanced threat detection
 */

use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use memmap2::Mmap;
use procfs::process::Process;
use procfs::ProcResult;
use serde::{Deserialize, Serialize};

pub struct MemoryForensics {
	process_maps: HashMap<i32, ProcessMemoryMap>,
	suspicious_patterns: Vec<MemoryPattern>,
	analysis_results: Vec<MemoryAnalysisResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMemoryMap {
	pub pid: i32,
	pub memory_regions: Vec<MemoryRegion>,
	pub suspicious_regions: Vec<MemoryRegion>,
	pub total_memory: u64,
	pub executable_regions: Vec<MemoryRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
	pub start_address: u64,
	pub end_address: u64,
	pub permissions: String,
	pub size: u64,
	pub path: Option<String>,
	pub is_executable: bool,
	pub is_writable: bool,
	pub is_readable: bool,
	pub content_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MemoryPattern {
	pub name: String,
	pub pattern: Vec<u8>,
	pub description: String,
	pub severity: crate::SecuritySeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAnalysisResult {
	pub pid: i32,
	pub threat_score: f64,
	pub suspicious_regions: Vec<MemoryRegion>,
	pub detected_patterns: Vec<String>,
	pub analysis_timestamp: u64,
	pub recommendations: Vec<String>,
}

impl MemoryForensics {
	pub fn new() -> Result<Self> {
		let suspicious_patterns = Self::initialize_memory_patterns();

		Ok(Self {
			process_maps: HashMap::new(),
			suspicious_patterns,
			analysis_results: Vec::new(),
		})
	}

	pub async fn analyze_process_memory(&mut self, pid: i32) -> Result<MemoryAnalysisResult> {
		let process = Process::new(pid)?;
		let memory_map = self.create_process_memory_map(&process).await?;
		
		self.process_maps.insert(pid, memory_map.clone());
		
		let threat_score = self.calculate_memory_threat_score(&memory_map).await?;
		let suspicious_regions = self.identify_suspicious_regions(&memory_map).await?;
		let detected_patterns = self.detect_memory_patterns(&memory_map).await?;
		
		let result = MemoryAnalysisResult {
			pid,
			threat_score,
			suspicious_regions,
			detected_patterns: detected_patterns.clone(),
			analysis_timestamp: std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)?
				.as_secs(),
			recommendations: self.generate_recommendations(threat_score, &detected_patterns),
		};

		self.analysis_results.push(result.clone());
		Ok(result)
	}

	async fn create_process_memory_map(&self, process: &Process) -> Result<ProcessMemoryMap> {
		let maps = process.maps()?;
		let mut memory_regions = Vec::new();
		let mut executable_regions = Vec::new();
		let mut total_memory = 0u64;

		for map in maps {
			let region = MemoryRegion {
				start_address: map.address.0,
				end_address: map.address.1,
				permissions: format!("{:?}", map.perms),
				size: map.address.1 - map.address.0,
				path: match &map.pathname {
					procfs::process::MMapPath::Path(p) => Some(p.to_string_lossy().into_owned()),
					_ => None,
				},
				is_executable: map.perms.contains(procfs::process::MMPermissions::EXECUTE),
				is_writable: map.perms.contains(procfs::process::MMPermissions::WRITE),
				is_readable: map.perms.contains(procfs::process::MMPermissions::READ),
				content_hash: None,
			};

			total_memory += region.size;
			memory_regions.push(region.clone());

			if region.is_executable {
				executable_regions.push(region);
			}
		}

		Ok(ProcessMemoryMap {
			pid: process.pid(),
			memory_regions,
			suspicious_regions: Vec::new(),
			total_memory,
			executable_regions,
		})
	}

	async fn calculate_memory_threat_score(&self, memory_map: &ProcessMemoryMap) -> Result<f64> {
		let mut score = 0.0;
		let mut factors = 0;

		for region in &memory_map.executable_regions {
			if region.is_writable {
				score += 0.3;
				factors += 1;
			}
			if region.path.is_none() {
				score += 0.2;
				factors += 1;
			}
		}

		if memory_map.total_memory > 1024 * 1024 * 1024 {
			score += 0.1;
			factors += 1;
		}

		for pattern in &self.suspicious_patterns {
			for region in &memory_map.memory_regions {
				if self.region_matches_pattern(region, pattern).await? {
					score += 0.4;
					factors += 1;
				}
			}
		}

		Ok(if factors > 0 { score / factors as f64 } else { 0.0 })
	}

	async fn identify_suspicious_regions(&self, memory_map: &ProcessMemoryMap) -> Result<Vec<MemoryRegion>> {
		let mut suspicious = Vec::new();

		for region in &memory_map.memory_regions {
			if self.is_suspicious_region(region).await? {
				suspicious.push(region.clone());
			}
		}

		Ok(suspicious)
	}

	async fn is_suspicious_region(&self, region: &MemoryRegion) -> Result<bool> {
		if region.is_executable && region.is_writable {
			return Ok(true);
		}

		if region.path.is_none() && region.size > 1024 * 1024 {
			return Ok(true);
		}

		if let Some(path) = &region.path {
			if path.contains("/tmp") || path.contains("/dev/shm") {
				return Ok(true);
			}
		}

		Ok(false)
	}

	async fn detect_memory_patterns(&self, memory_map: &ProcessMemoryMap) -> Result<Vec<String>> {
		let mut detected = Vec::new();

		for pattern in &self.suspicious_patterns {
			for region in &memory_map.memory_regions {
				if self.region_matches_pattern(region, pattern).await? {
					detected.push(pattern.name.clone());
				}
			}
		}

		Ok(detected)
	}

	async fn region_matches_pattern(&self, region: &MemoryRegion, pattern: &MemoryPattern) -> Result<bool> {
		if region.size >= pattern.pattern.len() as u64 {
			if pattern.name.contains("executable") && region.is_executable {
				return Ok(true);
			}
			if pattern.name.contains("writable") && region.is_writable {
				return Ok(true);
			}
		}

		Ok(false)
	}

	fn generate_recommendations(&self, threat_score: f64, patterns: &[String]) -> Vec<String> {
		let mut recommendations = Vec::new();

		if threat_score > 0.7 {
			recommendations.push("Immediate process termination recommended".to_string());
			recommendations.push("Memory dump for forensic analysis".to_string());
		}

		if threat_score > 0.5 {
			recommendations.push("Process monitoring required".to_string());
			recommendations.push("Memory scanning at regular intervals".to_string());
		}

		if !patterns.is_empty() {
			recommendations.push("Known malware patterns detected".to_string());
			recommendations.push("Quarantine process immediately".to_string());
		}

		recommendations
	}

	fn initialize_memory_patterns() -> Vec<MemoryPattern> {
		vec![
			MemoryPattern {
				name: "executable_memory_injection".to_string(),
				pattern: vec![0x90, 0x90, 0x90],
				description: "Detects executable memory injection patterns".to_string(),
				severity: crate::SecuritySeverity::Critical,
			},
			MemoryPattern {
				name: "writable_executable_memory".to_string(),
				pattern: vec![0x00, 0x00, 0x00],
				description: "Detects writable executable memory regions".to_string(),
				severity: crate::SecuritySeverity::High,
			},
			MemoryPattern {
				name: "large_anonymous_memory".to_string(),
				pattern: vec![0x00],
				description: "Detects large anonymous memory allocations".to_string(),
				severity: crate::SecuritySeverity::Medium,
			},
		]
	}

	pub fn get_analysis_results(&self) -> &[MemoryAnalysisResult] {
		&self.analysis_results
	}

	pub fn get_process_memory_map(&self, pid: i32) -> Option<&ProcessMemoryMap> {
		self.process_maps.get(&pid)
	}
} 