use crate::{OutputFormat, detector::PqcDetector, types::{ScanResult, HandshakeResult, TlsFeatures, EarlyDataStatus}};
use anyhow::Result;

impl ScanResult {
    pub fn new(target: String) -> Self {
        Self {
            target,
            tls_version: "Unknown".to_string(),
            cipher_suite: "Unknown".to_string(),
            key_exchange: Vec::new(),
            pqc_extensions: crate::types::PqcExtensions::default(),
            certificate: None,
            certificate_visible: false,
            handshake_complete: false,
            pqc_detected: false,
            tls_features: TlsFeatures::default(),
            fallback: crate::types::FallbackInfo {
                attempted: false,
                succeeded: false,
                fallback_penalty_ms: None,
                attempts_count: 0,
                attempted_profiles: Vec::new(),
            },
            analysis: crate::types::PqcAnalysis::default(),
            handshake_duration_ms: None,
            client_profile_used: "Unknown".to_string(),
            total_scan_duration_ms: None,
            adaptive_fingerprinting: false,
            server_fingerprint: None,
        }
    }

    pub fn update_from_handshake(&mut self, handshake_result: HandshakeResult) {
        self.tls_version = handshake_result.tls_version.clone();
        self.cipher_suite = handshake_result.cipher_suite.clone();
        self.key_exchange = handshake_result.key_exchange.clone();
        self.pqc_extensions = handshake_result.pqc_extensions.clone();
        self.tls_features = handshake_result.tls_features.clone();
        
        self.certificate_visible = handshake_result.certificate_visible;
        self.handshake_complete = handshake_result.handshake_complete;
        self.handshake_duration_ms = handshake_result.handshake_duration_ms;
        self.client_profile_used = format!("{:?}", handshake_result.client_profile_used);
        
        if let Some(ref cert_info) = handshake_result.certificate_info {
            self.certificate = Some(cert_info.clone());
        }
        
        // Run PQC analysis
        let detector = PqcDetector::new();
        self.analysis = detector.analyze_handshake(&handshake_result);
        self.pqc_detected = self.analysis.pqc_detected;
        
        // Add PQC signature algorithms from handshake
        for sig_alg in &handshake_result.pqc_signature_algorithms {
            if !self.analysis.pqc_signature_algorithms.contains(sig_alg) {
                self.analysis.pqc_signature_algorithms.push(sig_alg.clone());
            }
        }
    }
}

pub fn output_results(result: &ScanResult, format: &OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(result)?;
            println!("{}", json);
        }
        OutputFormat::Stdout => {
            println!("=== TLS Scan Results ===");
            println!("Target: {}", result.target);
            println!("Client Profile: {}", result.client_profile_used);
            if let Some(duration) = result.handshake_duration_ms {
                println!("Handshake Duration: {}ms", duration);
            }
            if let Some(total_duration) = result.total_scan_duration_ms {
                println!("Total Scan Duration: {}ms", total_duration);
            }
            if result.adaptive_fingerprinting {
                println!("Adaptive Fingerprinting: Enabled");
            }
            if let Some(fingerprint) = &result.server_fingerprint {
                println!("Server Fingerprint: {}", fingerprint);
            }
            println!("TLS Version: {}", result.analysis.tls_version);
            println!("Cipher Suite: {}", result.analysis.cipher_suite);
            println!("Key Exchange: {}", result.analysis.key_exchange);
            println!("Security Level: {}", result.analysis.security_level);
            println!("PQC Detected: {}", result.pqc_detected);
            
            if !result.analysis.pqc_key_exchange.is_empty() {
                println!("PQC Key Exchange: {:?}", result.analysis.pqc_key_exchange);
            }
            
            if !result.analysis.pqc_extensions.is_empty() {
                println!("PQC Extensions: {:?}", result.analysis.pqc_extensions);
            }
            
            println!("\n--- Server Features ---");
            if let Some(alpn) = &result.tls_features.alpn {
                println!("ALPN Protocol: {}", alpn);
            } else {
                println!("ALPN Protocol: Not negotiated");
            }
            
            match &result.tls_features.session_ticket {
                Some(true) => println!("Session Ticket Support: true"),
                Some(false) => println!("Session Ticket Support: false"),
                None => println!("Session Ticket Support: Not present"),
            }
            
            println!("OCSP Stapling Support: {}", result.tls_features.ocsp_stapling);
            
            match &result.tls_features.early_data_status {
                EarlyDataStatus::NotOffered => println!("Early Data (0-RTT): Not offered"),
                EarlyDataStatus::Accepted => println!("Early Data (0-RTT): Accepted"),
                EarlyDataStatus::Rejected => println!("Early Data (0-RTT): Rejected"),
            }
            
            if !result.analysis.security_features.is_empty() {
                println!("\n--- Security Analysis ---");
                println!("Security Features: {:?}", result.analysis.security_features);
            }
            
            println!("Classical Fallback: {}", result.analysis.classical_fallback_available);
            println!("Hybrid Detected: {}", result.analysis.hybrid_detected);
            
            // Display fallback information if applicable
            if result.fallback.attempted {
                println!("\n--- Fallback Information ---");
                println!("Fallback Attempted: {}", result.fallback.attempted);
                println!("Fallback Succeeded: {}", result.fallback.succeeded);
                println!("Attempts Count: {}", result.fallback.attempts_count);
                if let Some(penalty) = result.fallback.fallback_penalty_ms {
                    println!("Fallback Time Penalty: {}ms", penalty);
                }
                if !result.fallback.attempted_profiles.is_empty() {
                    println!("Attempted Profiles: {:?}", result.fallback.attempted_profiles);
                }
            }
        }
    }
    
    Ok(())
}

/// Generate a comprehensive report in markdown format
pub fn generate_markdown_report(result: &ScanResult) -> String {
    let mut report = String::new();
    
    report.push_str(&format!("# PQC TLS Scan Report\n\n"));
    report.push_str(&format!("**Target:** {}\n", result.target));
    report.push_str(&format!("**Client Profile:** {}\n", result.client_profile_used));
    if let Some(duration) = result.handshake_duration_ms {
        report.push_str(&format!("**Handshake Duration:** {}ms\n", duration));
    }
    report.push_str(&format!("**Scan Date:** {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));

    report.push_str("## TLS Configuration\n\n");
    report.push_str(&format!("- **TLS Version:** {}\n", result.analysis.tls_version));
    report.push_str(&format!("- **Cipher Suite:** {}\n", result.analysis.cipher_suite));
    
    report.push_str("\n### Key Exchange\n\n");
    if result.key_exchange.is_empty() {
        report.push_str("No key exchange algorithms detected.\n");
    } else {
        for kex in &result.key_exchange {
            let pqc_status = if result.analysis.pqc_key_exchange.contains(kex) {
                "🚀 Post-Quantum"
            } else {
                "🔒 Classical"
            };
            report.push_str(&format!("- {} ({})\n", kex, pqc_status));
        }
    }

    report.push_str("\n## Certificate Information\n\n");
    if let Some(cert) = &result.certificate {
        report.push_str(&format!("- **Subject:** {}\n", cert.subject));
        report.push_str(&format!("- **Public Key Algorithm:** {}", cert.public_key_algorithm));
        if let Some(size) = cert.key_size {
            report.push_str(&format!(" ({} bits)", size));
        }
        report.push_str("\n");
        report.push_str(&format!("- **Signature Algorithm:** {}\n", cert.signature_algorithm));
    } else {
        report.push_str("- **Certificate not available**\n");
    }

    if result.fallback.attempted {
        report.push_str("\n## Fallback Testing\n\n");
        report.push_str(&format!("- **Attempted:** {}\n", if result.fallback.attempted { "Yes" } else { "No" }));
        report.push_str(&format!("- **Succeeded:** {}\n", if result.fallback.succeeded { "Yes" } else { "No" }));
    }

    report.push_str("\n## Recommendations\n\n");
    if result.pqc_detected {
        report.push_str("✅ This server is **quantum-ready** with Post-Quantum Cryptography support.\n\n");
        
        if result.analysis.hybrid_detected {
            report.push_str("🔗 **Hybrid mode** ensures compatibility with both quantum-safe and classical clients.\n");
        }
    } else {
        report.push_str("⚠️ This server **does not support** Post-Quantum Cryptography.\n\n");
        report.push_str("**Recommendations:**\n");
        report.push_str("- Consider upgrading to quantum-safe algorithms\n");
        report.push_str("- Implement hybrid mode for gradual transition\n");
        report.push_str("- Monitor NIST standardization updates\n");
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HandshakeResult, PqcExtensions, CertificateInfo, HandshakeProfile};

    #[test]
    fn test_scan_result_creation() {
        let mut result = ScanResult::new("example.com:443".to_string());
        
        let handshake_result = HandshakeResult {
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
            key_exchange: vec!["x25519".to_string(), "kyber1024".to_string()],
            pqc_extensions: PqcExtensions::default(),
            certificate_info: Some(CertificateInfo {
                subject: "CN=example.com".to_string(),
                public_key_algorithm: "rsa".to_string(),
                signature_algorithm: "sha256WithRSAEncryption".to_string(),
                key_size: Some(2048),
            }),
            raw_server_hello: Vec::new(),
            raw_certificate: Vec::new(),
            alert_info: None,
            certificate_visible: false,
            handshake_complete: true,
            pqc_signature_algorithms: Vec::new(),
            tls_features: TlsFeatures::default(),
            handshake_duration_ms: Some(150),
            client_profile_used: HandshakeProfile::CloudflarePqc,
        };

        result.update_from_handshake(handshake_result);
        
        assert_eq!(result.target, "example.com:443");
        assert_eq!(result.analysis.tls_version, "TLS 1.3");
        assert!(result.analysis.pqc_detected);
        assert_eq!(result.handshake_duration_ms, Some(150));
        assert_eq!(result.client_profile_used, "CloudflarePqc");
    }

    #[test]
    fn test_json_serialization() {
        let result = ScanResult::new("test.com:443".to_string());
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test.com:443"));
    }
} 