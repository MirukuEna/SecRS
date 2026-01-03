/**
 * Encryption module
 * 
 * This module provides comprehensive encryption capabilities including
 * data encryption, key management, and secure storage for sensitive data.
 * 
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 * File: encryption.rs
 * Description: Encryption with AES-256-GCM and key management
 */

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use rand::{Rng, RngCore};
use base64::{Engine as _, engine::general_purpose};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;

use super::{SecurityConfig, SecurityEvent, SecuritySeverity};

/**
 * Encryption algorithms
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
	/// AES-256-GCM
	Aes256Gcm,
	/// ChaCha20-Poly1305
	ChaCha20Poly1305,
	/// XChaCha20-Poly1305
	XChaCha20Poly1305,
}

/**
 * Encryption key
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKey {
	/// Key ID
	pub key_id: String,
	/// Algorithm
	pub algorithm: EncryptionAlgorithm,
	/// Key data (base64 encoded)
	pub key_data: String,
	/// Creation time
	pub created_at: u64,
	/// Expiration time
	pub expires_at: Option<u64>,
	/// Active state
	pub active: bool,
}

/**
 * Encrypted data
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
	/// Algorithm used
	pub algorithm: EncryptionAlgorithm,
	/// Key ID used
	pub key_id: String,
	/// Initialization vector (base64 encoded)
	pub iv: String,
	/// Ciphertext (base64 encoded)
	pub ciphertext: String,
	/// Authentication tag (base64 encoded)
	pub tag: String,
	/// Encryption timestamp
	pub encrypted_at: u64,
}

/**
 * Encryption configuration
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
	/// Enable encryption
	pub enabled: bool,
	/// Default algorithm
	pub default_algorithm: EncryptionAlgorithm,
	/// Key rotation interval (seconds)
	pub key_rotation_interval: u64,
	/// Key expiration time (seconds)
	pub key_expiration_time: u64,
	/// Maximum key age (seconds)
	pub max_key_age: u64,
	/// Enable key rotation
	pub key_rotation_enabled: bool,
	/// Enable secure key storage
	pub secure_key_storage: bool,
	/// Key storage path
	pub key_storage_path: String,
}

impl Default for EncryptionConfig {
	fn default() -> Self {
		Self {
			enabled: true,
			default_algorithm: EncryptionAlgorithm::Aes256Gcm,
			key_rotation_interval: 86400, // 24 hours
			key_expiration_time: 2592000, // 30 days
			max_key_age: 7776000, // 90 days
			key_rotation_enabled: true,
			secure_key_storage: true,
			key_storage_path: "/tmp/sare_encryption_keys".to_string(),
		}
	}
}

/**
 * Encryption manager
 */
pub struct EncryptionManager {
	/// Security configuration
	config: Arc<RwLock<SecurityConfig>>,
	/// Encryption configuration
	encryption_config: EncryptionConfig,
	/// Encryption keys
	keys: Arc<RwLock<HashMap<String, EncryptionKey>>>,
	/// Current active key
	active_key: Arc<RwLock<Option<String>>>,
	/// Active state
	active: bool,
}

impl EncryptionManager {
	/**
	 * Creates a new encryption manager
	 */
	pub async fn new(config: Arc<RwLock<SecurityConfig>>) -> Result<Self> {
		let encryption_config = EncryptionConfig::default();
		
		let manager = Self {
			config,
			encryption_config,
			keys: Arc::new(RwLock::new(HashMap::new())),
			active_key: Arc::new(RwLock::new(None)),
			active: true,
		};
		
		// Initialize encryption keys
		manager.initialize_keys().await?;
		
		Ok(manager)
	}
	
	/**
	 * Encrypts data
	 */
	pub async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
		if !self.active || !self.encryption_config.enabled {
			return Ok(data.to_vec());
		}
		
		// Get active key
		let key = self.get_active_key().await?;
		
		// Generate nonce
		let mut nonce_bytes = [0u8; 12];
		rand::thread_rng().fill_bytes(&mut nonce_bytes);
		let nonce = Nonce::from_slice(&nonce_bytes);
		
		// Create cipher
		let cipher = Aes256Gcm::new_from_slice(&key.key_data.as_bytes())?;
		
		// Encrypt data
		let ciphertext = cipher.encrypt(nonce, data)?;
		
		// Create encrypted data structure
		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
		let encrypted_data = EncryptedData {
			algorithm: key.algorithm.clone(),
			key_id: key.key_id.clone(),
			iv: general_purpose::STANDARD.encode(nonce_bytes),
			ciphertext: general_purpose::STANDARD.encode(&ciphertext),
			tag: String::new(), // GCM includes tag in ciphertext
			encrypted_at: now,
		};
		
		// Serialize encrypted data
		let serialized = serde_json::to_vec(&encrypted_data)?;
		
		Ok(serialized)
	}
	
	/**
	 * Decrypts data
	 */
	pub async fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
		if !self.active || !self.encryption_config.enabled {
			return Ok(data.to_vec());
		}
		
		// Deserialize encrypted data
		let encrypted_data: EncryptedData = serde_json::from_slice(data)?;
		
		// Get key
		let keys = self.keys.read().await;
		let key = keys.get(&encrypted_data.key_id)
			.ok_or_else(|| anyhow::anyhow!("Key not found: {}", encrypted_data.key_id))?;
		
		// Decode nonce
		let nonce_bytes = general_purpose::STANDARD.decode(&encrypted_data.iv)?;
		let nonce = Nonce::from_slice(&nonce_bytes);
		
		// Decode ciphertext
		let ciphertext = general_purpose::STANDARD.decode(&encrypted_data.ciphertext)?;
		
		// Create cipher
		let cipher = Aes256Gcm::new_from_slice(&key.key_data.as_bytes())?;
		
		// Decrypt data
		let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
		
		Ok(plaintext)
	}
	
	/**
	 * Generates a new encryption key
	 */
	pub async fn generate_key(&self, algorithm: EncryptionAlgorithm) -> Result<EncryptionKey> {
		let key_id = self.generate_key_id().await?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
		
		// Generate key data
		let mut key_bytes = [0u8; 32]; // 256-bit key
		rand::thread_rng().fill_bytes(&mut key_bytes);
		let key_data = general_purpose::STANDARD.encode(key_bytes);
		
		// Calculate expiration time
		let expires_at = if self.encryption_config.key_expiration_time > 0 {
			Some(now + self.encryption_config.key_expiration_time)
		} else {
			None
		};
		
		let key = EncryptionKey {
			key_id,
			algorithm,
			key_data,
			created_at: now,
			expires_at,
			active: true,
		};
		
		// Store key
		self.keys.write().await.insert(key.key_id.clone(), key.clone());
		
		// Save key to storage
		self.save_key_to_storage(&key).await?;
		
		Ok(key)
	}
	
	/**
	 * Rotates encryption keys
	 */
	pub async fn rotate_keys(&self) -> Result<()> {
		if !self.encryption_config.key_rotation_enabled {
			return Ok(());
		}
		
		// Generate new key
		let new_key = self.generate_key(self.encryption_config.default_algorithm.clone()).await?;
		
		// Set as active key
		*self.active_key.write().await = Some(new_key.key_id.clone());
		
		// Clean up old keys
		self.cleanup_old_keys().await?;
		
		Ok(())
	}
	
	/**
	 * Gets active key
	 */
	async fn get_active_key(&self) -> Result<EncryptionKey> {
		let active_key_id = self.active_key.read().await.clone();
		
		if let Some(key_id) = active_key_id {
			let keys = self.keys.read().await;
			if let Some(key) = keys.get(&key_id) {
				return Ok(key.clone());
			}
		}
		
		// Generate new key if no active key
		let new_key = self.generate_key(self.encryption_config.default_algorithm.clone()).await?;
		*self.active_key.write().await = Some(new_key.key_id.clone());
		
		Ok(new_key)
	}
	
	/**
	 * Generates a unique key ID
	 */
	async fn generate_key_id(&self) -> Result<String> {
		let mut rng = rand::thread_rng();
		let id_bytes: [u8; 16] = rng.gen();
		let key_id = general_purpose::STANDARD.encode(id_bytes);
		
		Ok(format!("key_{}", key_id))
	}
	
	/**
	 * Saves key to storage
	 */
	async fn save_key_to_storage(&self, key: &EncryptionKey) -> Result<()> {
		if !self.encryption_config.secure_key_storage {
			return Ok(());
		}
		
		// Create storage directory
		std::fs::create_dir_all(&self.encryption_config.key_storage_path)?;
		
		// Save key to file
		let key_path = format!("{}/{}.key", self.encryption_config.key_storage_path, key.key_id);
		let key_data = serde_json::to_string(key)?;
		std::fs::write(key_path, key_data)?;
		
		Ok(())
	}
	
	/**
	 * Loads keys from storage
	 */
	async fn load_keys_from_storage(&self) -> Result<()> {
		if !self.encryption_config.secure_key_storage {
			return Ok(());
		}
		
		let storage_path = std::path::Path::new(&self.encryption_config.key_storage_path);
		if !storage_path.exists() {
			return Ok(());
		}
		
		if let Ok(entries) = std::fs::read_dir(storage_path) {
			for entry in entries {
				if let Ok(entry) = entry {
					if let Ok(file_name) = entry.file_name().into_string() {
						if file_name.ends_with(".key") {
							if let Ok(key_data) = std::fs::read_to_string(entry.path()) {
								if let Ok(key) = serde_json::from_str::<EncryptionKey>(&key_data) {
									self.keys.write().await.insert(key.key_id.clone(), key);
								}
							}
						}
					}
				}
			}
		}
		
		Ok(())
	}
	
	/**
	 * Cleans up old keys
	 */
	async fn cleanup_old_keys(&self) -> Result<()> {
		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
		let max_age = self.encryption_config.max_key_age;
		
		let mut keys = self.keys.write().await;
		let keys_to_remove: Vec<String> = keys.values()
			.filter(|key| {
				// Remove expired keys
				if let Some(expires_at) = key.expires_at {
					if now > expires_at {
						return true;
					}
				}
				
				// Remove old keys
				if now - key.created_at > max_age {
					return true;
				}
				
				false
			})
			.map(|key| key.key_id.clone())
			.collect();
		
		for key_id in keys_to_remove {
			keys.remove(&key_id);
			
			// Remove from storage
			let key_path = format!("{}/{}.key", self.encryption_config.key_storage_path, key_id);
			let _ = std::fs::remove_file(key_path);
		}
		
		Ok(())
	}
	
	/**
	 * Initializes encryption keys
	 */
	async fn initialize_keys(&self) -> Result<()> {
		// Load existing keys from storage
		self.load_keys_from_storage().await?;
		
		// Generate initial key if none exist
		let keys = self.keys.read().await;
		if keys.is_empty() {
			drop(keys);
			let initial_key = self.generate_key(self.encryption_config.default_algorithm.clone()).await?;
			*self.active_key.write().await = Some(initial_key.key_id);
		} else {
			// Set first key as active
			if let Some((key_id, _)) = keys.iter().next() {
				*self.active_key.write().await = Some(key_id.clone());
			}
		}
		
		// Start key rotation task
		if self.encryption_config.key_rotation_enabled {
			self.start_key_rotation_task().await?;
		}
		
		Ok(())
	}
	
	/**
	 * Starts key rotation task
	 */
	async fn start_key_rotation_task(&self) -> Result<()> {
		let rotation_interval = self.encryption_config.key_rotation_interval;
		let manager = self.clone();
		
		tokio::spawn(async move {
			let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(rotation_interval));
			
			loop {
				interval.tick().await;
				
				if let Err(e) = manager.rotate_keys().await {
					eprintln!("Failed to rotate encryption keys: {}", e);
				}
			}
		});
		
		Ok(())
	}
	
	/**
	 * Checks if encryption manager is active
	 */
	pub async fn is_active(&self) -> bool {
		self.active
	}
	
	/**
	 * Updates encryption configuration
	 */
	pub fn update_config(&mut self, config: EncryptionConfig) {
		self.encryption_config = config;
	}
	
	/**
	 * Gets current configuration
	 */
	pub fn get_config(&self) -> EncryptionConfig {
		self.encryption_config.clone()
	}
}

impl Clone for EncryptionManager {
	fn clone(&self) -> Self {
		Self {
			config: self.config.clone(),
			encryption_config: self.encryption_config.clone(),
			keys: self.keys.clone(),
			active_key: self.active_key.clone(),
			active: self.active,
		}
	}
} 