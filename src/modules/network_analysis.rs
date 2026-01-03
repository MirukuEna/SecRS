/**
 * Network Analysis Module.
 *
 * performs Deep Packet Inspection (DPI) to identify malicious traffic patterns.
 *
 * Analysis Strategy:
 * 1. Packet Parsing: Reconstructs TCP/UDP headers and payloads from raw bytes.
 * 2. Heuristic Scoring: Assigns threat scores based on:
 *    - Known port usage (e.g., SSH, Telnet)
 *    - Payload signature matching (e.g., "MALW" magic bytes)
 * 3. Connection Tracking: Aggregates stats per 4-tuple flow to detect volume anomalies.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */
use anyhow::Result;
use pcap::{Active, Capture, Device};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{ip::IpNextHeaderProtocols, Packet};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum NetworkMonitorEvent {
    Log(String),
    Alert {
        message: String,
        analysis: NetworkAnalysisResult,
    },
}

#[derive(Clone)]
pub struct NetworkAnalyzer {
    capture: Arc<Mutex<Option<Capture<Active>>>>,
    threat_patterns: Arc<Vec<NetworkThreatPattern>>,
    connection_tracker: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    analysis_results: Arc<Mutex<Vec<NetworkAnalysisResult>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkThreatPattern {
    pub name: String,
    pub protocol: String,
    pub payload_pattern: Vec<u8>,
    pub source_ips: Vec<String>,
    pub destination_ports: Vec<u16>,
    pub severity: crate::SecuritySeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub threat_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalysisResult {
    pub timestamp: u64,
    pub threat_score: f64,
    pub suspicious_connections: Vec<ConnectionInfo>,
    pub detected_patterns: Vec<String>,
    pub recommendations: Vec<String>,
}

impl NetworkAnalyzer {
    pub fn new() -> Result<Self> {
        let threat_patterns = Self::initialize_threat_patterns();

        Ok(Self {
            capture: Arc::new(Mutex::new(None)),
            threat_patterns: Arc::new(threat_patterns),
            connection_tracker: Arc::new(Mutex::new(HashMap::new())),
            analysis_results: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub async fn start_capture(&mut self, interface: &str) -> Result<()> {
        let device = Device::lookup()?
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| anyhow::anyhow!("Interface not found"))?;

        let capture = Capture::from_device(device)?
            .promisc(true)
            .snaplen(65535)
            .open()?;

        let mut capture_lock = self.capture.lock().unwrap();
        *capture_lock = Some(capture);
        Ok(())
    }

    pub fn monitor_traffic<F>(&self, callback: F)
    where
        F: Fn(NetworkMonitorEvent) + Send + Sync + 'static,
    {
        let analyzer = self.clone();

        std::thread::spawn(move || {
            // Find default device
            let device = match Device::lookup() {
                Ok(Some(d)) => d,
                Ok(None) => {
                    callback(NetworkMonitorEvent::Log(
                        "[NET] Error: No network interface found".to_string(),
                    ));
                    return;
                }
                Err(e) => {
                    callback(NetworkMonitorEvent::Log(format!("[NET] Error: {}", e)));
                    return;
                }
            };

            let name = device.name.clone();
            callback(NetworkMonitorEvent::Log(format!(
                "[NET] Starting capture on {}",
                name
            )));

            // Open capture
            let cap = match Capture::from_device(device) {
                Ok(c) => c,
                Err(e) => {
                    callback(NetworkMonitorEvent::Log(format!(
                        "[NET] Error initializing capture: {}",
                        e
                    )));
                    return;
                }
            };

            let mut cap = match cap.promisc(true).snaplen(65535).timeout(1000).open() {
                Ok(c) => c,
                Err(e) => {
                    callback(NetworkMonitorEvent::Log(format!(
                        "[NET] Error opening capture: {} (Try running as root?)",
                        e
                    )));
                    return;
                }
            };

            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        // Parse packet to get basic info
                        if let Some(ipv4) = Ipv4Packet::new(packet.data) {
                            let protocol = match ipv4.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => "TCP",
                                IpNextHeaderProtocols::Udp => "UDP",
                                _ => "OTHER",
                            };
                            let src = ipv4.get_source();
                            let dst = ipv4.get_destination();

                            // Perform DPI
                            match analyzer.analyze_packet(packet.data) {
                                Ok(analysis) => {
                                    if analysis.threat_score > 0.0 {
                                        // ALERT
                                        let msg = format!(
                                            "[NET] [ALERT] DANGER: {} (Score: {}) - Patterns: {:?}",
                                            analysis
                                                .suspicious_connections
                                                .first()
                                                .map(|c| c.protocol.clone())
                                                .unwrap_or("UNKNOWN".to_string()),
                                            analysis.threat_score,
                                            analysis.detected_patterns
                                        );
                                        callback(NetworkMonitorEvent::Alert {
                                            message: msg,
                                            analysis,
                                        });
                                    } else {
                                        // Normal Log
                                        let msg = format!(
                                            "[NET] {} {}:? -> {}:? ({} bytes)",
                                            protocol, src, dst, packet.header.len
                                        );
                                        callback(NetworkMonitorEvent::Log(msg));
                                    }
                                }
                                Err(e) => {
                                    callback(NetworkMonitorEvent::Log(format!(
                                        "[NET] Analysis Error: {}",
                                        e
                                    )));
                                }
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Continue
                    }
                    Err(e) => {
                        callback(NetworkMonitorEvent::Log(format!(
                            "[NET] Capture error: {}",
                            e
                        )));
                    }
                }
            }
        });
    }

    pub fn analyze_packet(&self, packet_data: &[u8]) -> Result<NetworkAnalysisResult> {
        let mut threat_score = 0.0;
        let mut suspicious_connections = Vec::new();
        let mut detected_patterns = Vec::new();

        if let Some(ipv4_packet) = Ipv4Packet::new(packet_data) {
            let source_ip = ipv4_packet.get_source().to_string();
            let dest_ip = ipv4_packet.get_destination().to_string();

            match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                        let connection_key = format!(
                            "{}:{}->{}:{}",
                            source_ip,
                            tcp_packet.get_source(),
                            dest_ip,
                            tcp_packet.get_destination()
                        );

                        let connection_info = self.update_connection_info(
                            &connection_key,
                            &source_ip,
                            &dest_ip,
                            tcp_packet.get_source(),
                            tcp_packet.get_destination(),
                            "TCP",
                            packet_data.len() as u64,
                        )?;

                        let (score, patterns) = self.analyze_tcp_packet(tcp_packet)?;
                        threat_score += score;
                        detected_patterns.extend(patterns);

                        if score > 0.5 {
                            suspicious_connections.push(connection_info);
                        }
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                        let connection_key = format!(
                            "{}:{}->{}:{}",
                            source_ip,
                            udp_packet.get_source(),
                            dest_ip,
                            udp_packet.get_destination()
                        );

                        let connection_info = self.update_connection_info(
                            &connection_key,
                            &source_ip,
                            &dest_ip,
                            udp_packet.get_source(),
                            udp_packet.get_destination(),
                            "UDP",
                            packet_data.len() as u64,
                        )?;

                        let (score, patterns) = self.analyze_udp_packet(udp_packet)?;
                        threat_score += score;
                        detected_patterns.extend(patterns);

                        if score > 0.5 {
                            suspicious_connections.push(connection_info);
                        }
                    }
                }
                _ => {}
            }
        }

        let result = NetworkAnalysisResult {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            threat_score,
            suspicious_connections,
            detected_patterns: detected_patterns.clone(),
            recommendations: self
                .generate_network_recommendations(threat_score, &detected_patterns),
        };

        self.analysis_results.lock().unwrap().push(result.clone());
        Ok(result)
    }

    /// Analyzes TCP traffic for high-risk ports and signature matches.
    /// Returns a tuple of (threat_score, detected_pattern_names).
    fn analyze_tcp_packet(&self, tcp_packet: TcpPacket<'_>) -> Result<(f64, Vec<String>)> {
        let mut score = 0.0;
        let mut patterns = Vec::new();

        let source_port = tcp_packet.get_source();
        let dest_port = tcp_packet.get_destination();
        let payload = tcp_packet.payload();

        if source_port == 22 || dest_port == 22 {
            score += 0.3;
            patterns.push("SSH traffic detected".to_string());
        }

        if source_port == 23 || dest_port == 23 {
            score += 0.4;
            patterns.push("Telnet traffic detected".to_string());
        }

        if source_port == 3389 || dest_port == 3389 {
            score += 0.3;
            patterns.push("RDP traffic detected".to_string());
        }

        for pattern in self.threat_patterns.iter() {
            if pattern.protocol == "TCP" {
                if payload
                    .windows(pattern.payload_pattern.len())
                    .any(|window| window == pattern.payload_pattern)
                {
                    score += 0.6;
                    patterns.push(pattern.name.clone());
                }
            }
        }

        Ok((score, patterns))
    }

    fn analyze_udp_packet(&self, udp_packet: UdpPacket<'_>) -> Result<(f64, Vec<String>)> {
        let mut score = 0.0;
        let mut patterns = Vec::new();

        let source_port = udp_packet.get_source();
        let dest_port = udp_packet.get_destination();
        let payload = udp_packet.payload();

        if source_port == 53 || dest_port == 53 {
            score += 0.2;
            patterns.push("DNS traffic detected".to_string());
        }

        if source_port == 123 || dest_port == 123 {
            score += 0.1;
            patterns.push("NTP traffic detected".to_string());
        }

        for pattern in self.threat_patterns.iter() {
            if pattern.protocol == "UDP" {
                if payload
                    .windows(pattern.payload_pattern.len())
                    .any(|window| window == pattern.payload_pattern)
                {
                    score += 0.6;
                    patterns.push(pattern.name.clone());
                }
            }
        }

        Ok((score, patterns))
    }

    fn update_connection_info(
        &self,
        key: &str,
        source_ip: &str,
        dest_ip: &str,
        source_port: u16,
        dest_port: u16,
        protocol: &str,
        bytes: u64,
    ) -> Result<ConnectionInfo> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let mut tracker = self.connection_tracker.lock().unwrap();
        let connection_info = tracker
            .entry(key.to_string())
            .or_insert_with(|| ConnectionInfo {
                source_ip: source_ip.to_string(),
                dest_ip: dest_ip.to_string(),
                source_port,
                dest_port,
                protocol: protocol.to_string(),
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                first_seen: timestamp,
                last_seen: timestamp,
                threat_score: 0.0,
            });

        connection_info.bytes_received += bytes;
        connection_info.packets_received += 1;
        connection_info.last_seen = timestamp;

        Ok(connection_info.clone())
    }

    fn generate_network_recommendations(
        &self,
        threat_score: f64,
        patterns: &[String],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if threat_score > 0.7 {
            recommendations.push("Block suspicious IP addresses".to_string());
            recommendations.push("Enable deep packet inspection".to_string());
        }

        if threat_score > 0.5 {
            recommendations.push("Monitor network traffic closely".to_string());
            recommendations.push("Review firewall rules".to_string());
        }

        if patterns.iter().any(|p| p.contains("malware")) {
            recommendations.push("Quarantine affected systems".to_string());
            recommendations.push("Update antivirus signatures".to_string());
        }

        recommendations
    }

    fn initialize_threat_patterns() -> Vec<NetworkThreatPattern> {
        vec![
            NetworkThreatPattern {
                name: "malware_communication".to_string(),
                protocol: "TCP".to_string(),
                payload_pattern: vec![0x4D, 0x41, 0x4C, 0x57], // "MALW"
                source_ips: vec!["192.168.1.100".to_string()],
                destination_ports: vec![4444, 8080],
                severity: crate::SecuritySeverity::Critical,
            },
            NetworkThreatPattern {
                name: "data_exfiltration".to_string(),
                protocol: "TCP".to_string(),
                payload_pattern: vec![0x44, 0x41, 0x54, 0x41], // "DATA"
                source_ips: vec![],
                destination_ports: vec![80, 443],
                severity: crate::SecuritySeverity::High,
            },
            NetworkThreatPattern {
                name: "port_scanning".to_string(),
                protocol: "TCP".to_string(),
                payload_pattern: vec![0x53, 0x59, 0x4E], // "SYN"
                source_ips: vec![],
                destination_ports: vec![],
                severity: crate::SecuritySeverity::Medium,
            },
        ]
    }

    pub fn get_analysis_results(&self) -> Vec<NetworkAnalysisResult> {
        self.analysis_results.lock().unwrap().clone()
    }

    pub fn get_connection_tracker(&self) -> HashMap<String, ConnectionInfo> {
        self.connection_tracker.lock().unwrap().clone()
    }
}
