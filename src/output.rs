use crate::{OutputFormat, detector::PqcDetector, types::{ScanResult, HandshakeResult, TlsFeatures}};
use serde_json;

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
            extension_map: crate::types::ExtensionMap::default(),
            security_score: crate::types::SecurityScore::default(),
            security_warnings: Vec::new(),
            performance_warnings: Vec::new(),
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
        
        // Update extension_map from real handshake data
        self.extension_map = handshake_result.extension_map.clone();
        
        // Run PQC analysis
        let detector = PqcDetector::new();
        self.analysis = detector.analyze_handshake(&handshake_result);
        
        // Handle TLS 1.2 fallback scenario
        if handshake_result.tls_version == "1.2" {
            println!("TLS 1.2 detected - updating scan result for classical fallback");
            self.pqc_detected = false;
            self.fallback.attempted = true;
            self.fallback.succeeded = true;
            self.analysis.classical_fallback_available = true;
            self.fallback.attempted_profiles.push("TLS 1.2 Fallback".to_string());
        } else {
            self.pqc_detected = self.analysis.pqc_detected;
        }
        
        // Add PQC signature algorithms from handshake
        for sig_alg in &handshake_result.pqc_signature_algorithms {
            if !self.analysis.pqc_signature_algorithms.contains(sig_alg) {
                self.analysis.pqc_signature_algorithms.push(sig_alg.clone());
            }
        }
    }
}

pub struct OutputFormatter;

impl OutputFormatter {
    pub fn new() -> Self {
        Self
    }

    pub fn format_result(&self, result: &ScanResult, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => self.format_json(result),
            OutputFormat::Text => self.format_text(result),
        }
    }

    fn format_json(&self, result: &ScanResult) -> String {
        serde_json::to_string_pretty(result).unwrap_or_else(|_| "Error serializing result".to_string())
    }

    fn format_text(&self, result: &ScanResult) -> String {
        let mut output = String::new();
        
        // Basic information
        output.push_str(&format!("Target: {}\n", result.target));
        output.push_str(&format!("TLS Version: {}\n", result.tls_version));
        output.push_str(&format!("Cipher Suite: {}\n", result.cipher_suite));
        output.push_str(&format!("Key Exchange: {}\n", result.key_exchange.join(", ")));
        
        // PQC Information
        output.push_str(&format!("PQC Detected: {}\n", result.pqc_detected));
        if result.pqc_detected {
            output.push_str(&format!("PQC Extensions: {:?}\n", result.pqc_extensions));
        }
        
        // Certificate Information
        output.push_str(&format!("Certificate Visible: {}\n", result.certificate_visible));
        if let Some(ref cert) = result.certificate {
            output.push_str(&format!("Certificate Subject: {}\n", cert.subject));
            output.push_str(&format!("Certificate Issuer: {}\n", cert.issuer));
            output.push_str(&format!("Certificate Valid From: {}\n", cert.valid_from));
            output.push_str(&format!("Certificate Valid To: {}\n", cert.valid_to));
            output.push_str(&format!("Certificate Public Key Algorithm: {}\n", cert.public_key_algorithm));
            output.push_str(&format!("Certificate Signature Algorithm: {}\n", cert.signature_algorithm));
            if let Some(key_size) = cert.key_size {
                output.push_str(&format!("Certificate Key Size: {} bits\n", key_size));
            }
        }
        
        // TLS Features
        output.push_str(&format!("TLS Features: {:?}\n", result.tls_features));
        
        // Extension Mapping
        output.push_str("\nExtension Negotiation Mapping:\n");
        output.push_str(&format!("  Key Share: {}\n", self.format_extension_status(&result.extension_map.key_share)));
        output.push_str(&format!("  Supported Versions: {}\n", self.format_extension_status(&result.extension_map.supported_versions)));
        output.push_str(&format!("  Signature Algorithms: {}\n", self.format_extension_status(&result.extension_map.signature_algorithms)));
        output.push_str(&format!("  ALPN Protocols: {}\n", self.format_alpn_protocols(&result.extension_map.alpn_protocols)));
        output.push_str(&format!("  OCSP Stapling: {}\n", self.format_extension_status(&result.extension_map.ocsp_stapling)));
        output.push_str(&format!("  Session Ticket: {}\n", self.format_extension_status(&result.extension_map.session_ticket)));
        output.push_str(&format!("  PSK Key Exchange Modes: {}\n", self.format_extension_status(&result.extension_map.psk_key_exchange_modes)));
        output.push_str(&format!("  Early Data: {}\n", self.format_extension_status(&result.extension_map.early_data)));
        output.push_str(&format!("  Pre-Shared Key: {}\n", self.format_extension_status(&result.extension_map.pre_shared_key)));
        
        // Analysis
        output.push_str(&format!("\nAnalysis:\n"));
        output.push_str(&format!("  Security Level: {}\n", result.analysis.security_level));
        output.push_str(&format!("  Hybrid Detected: {}\n", result.analysis.hybrid_detected));
        output.push_str(&format!("  Classical Fallback Available: {}\n", result.analysis.classical_fallback_available));
        
        // Security Scoring
        output.push_str(&format!("\nSecurity Scoring:\n"));
        output.push_str(&format!("  Overall Score: {}/100\n", result.security_score.overall));
        output.push_str(&format!("  TLS Score: {}/100\n", result.security_score.tls));
        output.push_str(&format!("  Certificate Score: {}/100\n", result.security_score.certificate));
        output.push_str(&format!("  PQC Score: {}/100\n", result.security_score.pqc));
        
        // Detailed Security Breakdown
        output.push_str(&format!("\nDetailed Security Breakdown:\n"));
        output.push_str(&format!("  TLS Version: {}/100\n", result.security_score.details.tls_version));
        output.push_str(&format!("  Cipher Suite: {}/100\n", result.security_score.details.cipher_suite));
        output.push_str(&format!("  Key Exchange: {}/100\n", result.security_score.details.key_exchange));
        output.push_str(&format!("  Certificate Validation: {}/100\n", result.security_score.details.certificate_validation));
        output.push_str(&format!("  Certificate Key Strength: {}/100\n", result.security_score.details.certificate_key_strength));
        output.push_str(&format!("  PQC Algorithm: {}/100\n", result.security_score.details.pqc_algorithm));
        output.push_str(&format!("  PQC Implementation: {}/100\n", result.security_score.details.pqc_implementation));
        output.push_str(&format!("  Hybrid Security: {}/100\n", result.security_score.details.hybrid_security));
        
        // Timing
        if let Some(duration) = result.handshake_duration_ms {
            output.push_str(&format!("Handshake Duration: {} ms\n", duration));
        }
        
        // Security Warnings
        if !result.security_warnings.is_empty() {
            output.push_str(&format!("\nSecurity Warnings:\n"));
            for warning in &result.security_warnings {
                output.push_str(&format!("  [{}] {}: {}\n", 
                    warning.level.to_string().to_uppercase(), 
                    warning.category, 
                    warning.message));
                if let Some(ref recommendation) = warning.recommendation {
                    output.push_str(&format!("    Recommendation: {}\n", recommendation));
                }
            }
        }
        
        // Performance Warnings
        if !result.performance_warnings.is_empty() {
            output.push_str(&format!("\nPerformance Warnings:\n"));
            for warning in &result.performance_warnings {
                output.push_str(&format!("  [{}] {}: {}\n", 
                    warning.level.to_string().to_uppercase(), 
                    warning.category, 
                    warning.message));
                output.push_str(&format!("    Impact: {}\n", warning.impact));
                if let Some(ref recommendation) = warning.recommendation {
                    output.push_str(&format!("    Recommendation: {}\n", recommendation));
                }
            }
        }
        
        output
    }

    fn format_extension_status(&self, status: &bool) -> String {
        if *status {
            "present".to_string()
        } else {
            "not_present".to_string()
        }
    }

    fn format_alpn_protocols(&self, protocols: &[String]) -> String {
        if protocols.is_empty() {
            "none".to_string()
        } else {
            protocols.join(", ")
        }
    }
}

pub fn output_results(result: &ScanResult, format: OutputFormat) {
    let formatter = OutputFormatter::new();
    let output = formatter.format_result(result, format);
    println!("{}", output);
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
            target: "example.com:443".to_string(),
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
            key_exchange: vec!["x25519".to_string(), "kyber1024".to_string()],
            pqc_extensions: PqcExtensions::default(),
            certificate_info: Some(CertificateInfo {
                subject: "CN=example.com".to_string(),
                issuer: "CN=Example CA".to_string(),
                public_key_algorithm: "rsa".to_string(),
                signature_algorithm: "sha256WithRSAEncryption".to_string(),
                key_size: Some(2048),
                valid_from: "2023-01-01".to_string(),
                valid_to: "2024-01-01".to_string(),
                san: Some("example.com, *.example.com".to_string()),
                certificate_length_estimate: Some(1500),
                algorithm_consistency: true,
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
            extension_map: crate::types::ExtensionMap::default(),
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