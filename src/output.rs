use crate::{
    detector::PqcDetector,
    types::{
        HandshakeResult, PerformanceWarning, ScanResult, SecurityScore, TlsFeatures, WarningLevel,
    },
    OutputFormat,
};
use serde_json;
use serde_json::{json, Value};
use std::collections::HashMap;

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
                enabled: false,
                used: false,
                fallback_penalty_ms: None,
                attempts_count: 0,
                attempted_profiles: Vec::new(),
                tls12_fallback: None,
            },
            analysis: crate::types::PqcAnalysis::default(),
            handshake_duration_ms: None,
            client_profile_used: "Unknown".to_string(), // Will be set by update_from_handshake or explicitly in main.rs
            total_scan_duration_ms: None,
            adaptive_fingerprinting: false,
            server_fingerprint: None,
            extension_map: crate::types::ExtensionMap::default(),
            security_score: crate::types::SecurityScore::default(),
            security_warnings: Vec::new(),
            performance_warnings: Vec::new(),
            raw_server_hello: Vec::new(),
            http_redirect: None,
            connection_type: None,
            cipher_suite_reason: None,
        }
    }

    /// Set client profile used for failed scans
    pub fn set_profile(&mut self, profile: &str) {
        self.client_profile_used = profile.to_string();
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
        // FIXED: Convert HandshakeProfile to consistent display name matching CLI arguments
        // Map HandshakeProfile to ClientProfile display name for consistency
        self.client_profile_used = match handshake_result.client_profile_used {
            crate::types::HandshakeProfile::Standard => "Classic".to_string(),
            crate::types::HandshakeProfile::CloudflarePqc => "Fallback".to_string(),
            crate::types::HandshakeProfile::HybridPqc => "Hybrid".to_string(),
            crate::types::HandshakeProfile::PqcOnly => "MaxPQC".to_string(), // FIXED: PqcOnly -> MaxPQC for consistency
        };

        if let Some(ref cert_info) = handshake_result.certificate_info {
            self.certificate = Some(cert_info.clone());
        }

        // Update extension_map from real handshake data
        self.extension_map = handshake_result.extension_map.clone();

        // Copy raw_server_hello for PQC detection and analysis
        self.raw_server_hello = handshake_result.raw_server_hello.clone();

        // Tag connection type and cipher_suite reason for filtering (QUIC vs TLS, unknown cipher reason)
        self.connection_type = handshake_result.connection_type.clone();
        self.cipher_suite_reason = handshake_result.cipher_suite_reason.clone();

        // Run PQC analysis
        let detector = PqcDetector::new();
        self.analysis = detector.analyze_handshake(&handshake_result);

        // FIXED: Fallback structure is now managed in main.rs
        // This code is kept for backward compatibility but should not override main.rs values
        // The fallback structure is now set correctly in scan_target() function

        // Add PQC signature algorithms from handshake
        for sig_alg in &handshake_result.pqc_signature_algorithms {
            if !self.analysis.pqc_signature_algorithms.contains(sig_alg) {
                self.analysis.pqc_signature_algorithms.push(sig_alg.clone());
            }
        }
    }
}

pub struct OutputFormatter {
    format: OutputFormat,
    include_performance_analysis: bool,
    include_recommendations: bool,
}

impl OutputFormatter {
    pub fn new(format: OutputFormat) -> Self {
        Self {
            format,
            include_performance_analysis: true,
            include_recommendations: true,
        }
    }

    pub fn without_performance_analysis(mut self) -> Self {
        self.include_performance_analysis = false;
        self
    }

    pub fn without_recommendations(mut self) -> Self {
        self.include_recommendations = false;
        self
    }

    pub fn format_result(&self, result: &ScanResult) -> String {
        match self.format {
            OutputFormat::Json => self.format_json(result),
            OutputFormat::Text => self.format_text(result),
            OutputFormat::Csv => self.format_csv(result),
        }
    }

    /// Known experimental/QUIC-only domains for filtering in reports (suggestion 8.4).
    /// Summary scripts should exclude or tag these so site-level metrics are not mixed with production.
    fn is_experimental_quic_only_domain(target: &str) -> bool {
        let host = target.split(':').next().unwrap_or(target).to_lowercase();
        const EXPERIMENTAL_QUIC_DOMAINS: &[&str] = &[
            "s2n-quic.oqstest.net",
            "test.pqkd.aws",
            "oqs.duckdns.org",
            "oqstest.net", // subdomains
            "pqkd.aws",
            "quantumtls.com",
        ];
        EXPERIMENTAL_QUIC_DOMAINS
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{}", *d)))
    }

    fn format_json(&self, result: &ScanResult) -> String {
        // IMPROVED: Add protocol detection information
        let target_lower = result.target.to_lowercase();
        let is_experimental = target_lower.contains("test")
            || target_lower.contains("demo")
            || target_lower.contains("experimental")
            || target_lower.contains("quic");
        let experimental_quic_only_domain = Self::is_experimental_quic_only_domain(&result.target);

        let mut json_output = json!({
            "target": result.target,
            "tls_version": result.tls_version,
            "cipher_suite": result.cipher_suite,
            "key_exchange": result.key_exchange,
            "pqc_extensions": result.pqc_extensions,
            "certificate": self.format_certificate_json(&result.certificate),
            "tls_features": result.tls_features,
            "certificate_visible": result.certificate_visible,
            "handshake_complete": result.handshake_complete,
            "pqc_detected": !result.analysis.pqc_signature_algorithms.is_empty() ||
                           result.key_exchange.iter().any(|kex| kex.contains("ML-KEM") || kex.contains("Kyber")),
            "fallback": result.fallback,
            "analysis": self.format_analysis_json(result),
            "handshake_duration_ms": result.handshake_duration_ms,
            "client_profile_used": result.client_profile_used,
            "total_scan_duration_ms": result.total_scan_duration_ms,
            "adaptive_fingerprinting": result.adaptive_fingerprinting,
            "server_fingerprint": result.server_fingerprint,
            "extension_map": result.extension_map,
            "security_score": result.security_score,
            "is_experimental_server": is_experimental,
            "experimental_quic_only_domain": experimental_quic_only_domain,
            "protocol_support": {
                "tls": true,
                // FIXED: QUIC and HTTP/3 are always "unknown" since we only scan TLS/TCP, not UDP/QUIC
                "quic": "unknown",
                "http3": "unknown",
                "detection_method": "standard_tls"
            }
        });

        // Add performance analysis if enabled
        if self.include_performance_analysis {
            let performance_analysis = self.analyze_performance(result);
            if let Some(perf_json) = performance_analysis {
                json_output["performance_analysis"] = perf_json;
            }
        }

        // Add security warnings
        if !result.security_warnings.is_empty() {
            json_output["security_warnings"] = json!(result.security_warnings);
        }

        // Add performance warnings
        if !result.performance_warnings.is_empty() {
            json_output["performance_warnings"] = json!(result.performance_warnings);
        }

        // Add recommendations if enabled
        if self.include_recommendations {
            let recommendations = self.generate_recommendations(result, &result.security_score);
            if !recommendations.is_empty() {
                json_output["recommendations"] = json!(recommendations);
            }
        }

        // FIXED: Add raw_server_hello for PQC detection
        json_output["raw_server_hello"] = json!(result.raw_server_hello);

        // Tag connection type and cipher_suite reason for filtering (see SCAN_REPORT_ANALYSIS)
        if let Some(ref ct) = result.connection_type {
            json_output["connection_type"] = json!(ct);
        }
        if let Some(ref reason) = result.cipher_suite_reason {
            json_output["cipher_suite_reason"] = json!(reason);
        }

        // IMPROVED: Use compact JSON for better jq compatibility
        serde_json::to_string(&json_output).unwrap_or_else(|_| "{}".to_string())
    }

    fn format_certificate_json(&self, cert_info: &Option<crate::types::CertificateInfo>) -> Value {
        if let Some(ref cert) = cert_info {
            json!({
                "subject": cert.subject,
                "issuer": cert.issuer,
                "public_key_algorithm": cert.public_key_algorithm,
                "signature_algorithm": cert.signature_algorithm,
                "signature_algorithm_oid": cert.signature_algorithm_oid,
                "key_size": cert.key_size,
                "valid_from": cert.valid_from,
                "valid_to": cert.valid_to,
                "san": cert.san,
                "certificate_length_estimate": cert.certificate_length_estimate,
                "algorithm_consistency": cert.algorithm_consistency
            })
        } else {
            json!(null)
        }
    }

    fn format_analysis_json(&self, result: &ScanResult) -> Value {
        let mut analysis_json = json!({
            "tls_version": result.analysis.tls_version,
            "cipher_suite": result.analysis.cipher_suite,
            "key_exchange": result.analysis.key_exchange,
            "pqc_detected": result.analysis.pqc_detected,
            "pqc_key_exchange": result.analysis.pqc_key_exchange,
            "pqc_signature_algorithms": result.analysis.pqc_signature_algorithms,
            "pqc_signature_status": result.analysis.pqc_signature_status,
            "pqc_public_key_algorithms": result.analysis.pqc_public_key_algorithms,
            "pqc_extensions": result.analysis.pqc_extensions,
            "security_features": result.analysis.security_features,
            "security_level": result.analysis.security_level,
            "hybrid_detected": result.analysis.hybrid_detected,
            "classical_fallback_available": result.analysis.classical_fallback_available,
            "pqc_signature_used": result.analysis.pqc_signature_used,
            "pqc_signature_algorithm": result.analysis.pqc_signature_algorithm,
            "signature_negotiation_status": result.analysis.signature_negotiation_status,
            "server_endpoint_fingerprint": result.analysis.server_endpoint_fingerprint,
            // FIXED: Remove duplicate tls_version (already in analysis.tls_version above)
        });

        // Add TLS 1.3 limitations explanation
        // FIXED: Clarify protocol vs implementation limitations
        // Updated to reflect that we use rustls::ClientConnection and capture raw TLS records
        if result.tls_version == "1.3" {
            analysis_json["tls_1_3_limitations"] = json!({
                "certificate_visibility": "TLS 1.3 encrypts handshake messages on the wire. Passive sniffers cannot see certificates; active scanners like this tool decrypt them with session keys.",
                "signature_algorithm": "CertificateVerify signature extraction is implemented using rustls::ClientConnection API which captures raw TLS records. TLS 1.3 CertificateVerify signature scheme is captured via verifier callback for accurate PQC signature detection.",
                "recommendation": "For detailed certificate analysis, consider using TLS 1.2 fallback or active scanning tools",
                "scan_mode": "active"
            });
        }

        analysis_json
    }

    fn format_csv(&self, _result: &ScanResult) -> String {
        // Placeholder CSV implementation
        "target,tls_version,cipher_suite,key_exchange,pqc_detected\n".to_string()
    }

    fn format_text(&self, result: &ScanResult) -> String {
        let mut output = String::new();

        // Basic information
        output.push_str(&format!("Target: {}\n", result.target));
        output.push_str(&format!("TLS Version: {}\n", result.tls_version));
        output.push_str(&format!("Cipher Suite: {}\n", result.cipher_suite));
        output.push_str(&format!(
            "Key Exchange: {}\n",
            result.key_exchange.join(", ")
        ));

        // PQC Information
        output.push_str(&format!("PQC Detected: {}\n", result.pqc_detected));
        if result.pqc_detected {
            output.push_str(&format!("PQC Extensions: {:?}\n", result.pqc_extensions));
        }

        // Certificate Information
        output.push_str(&format!(
            "Certificate Visible: {}\n",
            result.certificate_visible
        ));
        if let Some(ref cert) = result.certificate {
            output.push_str(&format!("Certificate Subject: {}\n", cert.subject));
            output.push_str(&format!("Certificate Issuer: {}\n", cert.issuer));
            output.push_str(&format!("Certificate Valid From: {}\n", cert.valid_from));
            output.push_str(&format!("Certificate Valid To: {}\n", cert.valid_to));
            output.push_str(&format!(
                "Certificate Public Key Algorithm: {}\n",
                cert.public_key_algorithm
            ));
            output.push_str(&format!(
                "Certificate Signature Algorithm: {}\n",
                cert.signature_algorithm
            ));
            if let Some(key_size) = cert.key_size {
                output.push_str(&format!("Certificate Key Size: {} bits\n", key_size));
            }
        }

        // TLS Features
        output.push_str(&format!("TLS Features: {:?}\n", result.tls_features));

        // Extension Mapping
        output.push_str("\nExtension Negotiation Mapping:\n");
        output.push_str(&format!(
            "  Key Share: {}\n",
            self.format_extension_status(&result.extension_map.key_share)
        ));
        output.push_str(&format!(
            "  Supported Versions: {}\n",
            self.format_extension_status(&result.extension_map.supported_versions)
        ));
        output.push_str(&format!(
            "  Signature Algorithms: {}\n",
            self.format_extension_status(&result.extension_map.signature_algorithms)
        ));
        output.push_str(&format!(
            "  ALPN Protocols: {}\n",
            self.format_alpn_protocols(&result.extension_map.alpn_protocols)
        ));
        output.push_str(&format!(
            "  OCSP Stapling: {}\n",
            self.format_extension_status(&result.extension_map.ocsp_stapling)
        ));
        output.push_str(&format!(
            "  Session Ticket: {}\n",
            self.format_extension_status(&result.extension_map.session_ticket)
        ));
        output.push_str(&format!(
            "  PSK Key Exchange Modes: {}\n",
            self.format_extension_status(&result.extension_map.psk_key_exchange_modes)
        ));
        output.push_str(&format!(
            "  Early Data: {}\n",
            self.format_extension_status(&result.extension_map.early_data)
        ));
        output.push_str(&format!(
            "  Pre-Shared Key: {}\n",
            self.format_extension_status(&result.extension_map.pre_shared_key)
        ));

        // Analysis
        output.push_str(&"\nAnalysis:\n".to_string());
        output.push_str(&format!(
            "  Security Level: {}\n",
            result.analysis.security_level
        ));
        output.push_str(&format!(
            "  Hybrid Detected: {}\n",
            result.analysis.hybrid_detected
        ));
        output.push_str(&format!(
            "  Classical Fallback Available: {}\n",
            result.analysis.classical_fallback_available
        ));

        // Security Scoring
        output.push_str(&"\nSecurity Scoring:\n".to_string());
        output.push_str(&format!(
            "  Overall Score: {}/100\n",
            result.security_score.overall
        ));
        output.push_str(&format!("  TLS Score: {}/100\n", result.security_score.tls));
        output.push_str(&format!(
            "  Certificate Score: {}/100\n",
            result.security_score.certificate
        ));
        output.push_str(&format!("  PQC Score: {}/100\n", result.security_score.pqc));

        // Detailed Security Breakdown
        output.push_str(&"\nDetailed Security Breakdown:\n".to_string());
        output.push_str(&format!(
            "  TLS Version: {}/100\n",
            result.security_score.details.tls_version
        ));
        output.push_str(&format!(
            "  Cipher Suite: {}/100\n",
            result.security_score.details.cipher_suite
        ));
        output.push_str(&format!(
            "  Key Exchange: {}/100\n",
            result.security_score.details.key_exchange
        ));
        output.push_str(&format!(
            "  Certificate Validation: {}/100\n",
            result.security_score.details.certificate_validation
        ));
        output.push_str(&format!(
            "  Certificate Key Strength: {}/100\n",
            result.security_score.details.certificate_key_strength
        ));
        output.push_str(&format!(
            "  PQC Algorithm: {}/100\n",
            result.security_score.details.pqc_algorithm
        ));
        output.push_str(&format!(
            "  PQC Implementation: {}/100\n",
            result.security_score.details.pqc_implementation
        ));
        output.push_str(&format!(
            "  Hybrid Security: {}/100\n",
            result.security_score.details.hybrid_security
        ));

        // Timing
        if let Some(duration) = result.handshake_duration_ms {
            output.push_str(&format!("Handshake Duration: {} ms\n", duration));
        }

        // Security Warnings
        if !result.security_warnings.is_empty() {
            output.push_str(&"\nSecurity Warnings:\n".to_string());
            for warning in &result.security_warnings {
                output.push_str(&format!(
                    "  [{}] {}: {}\n",
                    warning.level.to_string().to_uppercase(),
                    warning.category,
                    warning.message
                ));
                if let Some(ref recommendation) = warning.recommendation {
                    output.push_str(&format!("    Recommendation: {}\n", recommendation));
                }
            }
        }

        // Performance Warnings
        if !result.performance_warnings.is_empty() {
            output.push_str(&"\nPerformance Warnings:\n".to_string());
            for warning in &result.performance_warnings {
                output.push_str(&format!(
                    "  [{}] {}: {}\n",
                    warning.level.to_string().to_uppercase(),
                    warning.category,
                    warning.message
                ));
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

    fn analyze_performance(&self, result: &ScanResult) -> Option<Value> {
        let handshake_duration = result.handshake_duration_ms.unwrap_or(0);

        // Slow-endpoint alert for tuning timeouts/concurrency (suggestion 8.4)
        const SLOW_ENDPOINT_THRESHOLD_MS: u64 = 2000;
        let slow_endpoint_alert = handshake_duration > SLOW_ENDPOINT_THRESHOLD_MS;

        // Performance benchmarks
        let performance_benchmarks = json!({
            "handshake_timing": {
                "duration_ms": handshake_duration,
                "category": self.categorize_handshake_performance(handshake_duration),
                "percentile": self.calculate_performance_percentile(handshake_duration),
                "slow_endpoint_alert": slow_endpoint_alert,
                "slow_endpoint_threshold_ms": SLOW_ENDPOINT_THRESHOLD_MS,
                "benchmark": {
                    "excellent": "< 200ms",
                    "good": "200-400ms",
                    "acceptable": "400-800ms",
                    "slow": "800-1500ms",
                    "very_slow": "> 1500ms"
                }
            },
            "overhead_analysis": {
                "baseline_ms": 150,
                "pqc_overhead_ms": self.calculate_pqc_overhead(result),
                "certificate_overhead_ms": self.calculate_certificate_overhead(result),
                "network_overhead_ms": self.calculate_network_overhead(result),
                "overhead_share_percent": self.calculate_overhead_share_percent(result),
                "overhead_vs_baseline_percent": self.calculate_overhead_vs_baseline_percent(result)
            },
            "optimization_opportunities": self.identify_optimization_opportunities(result)
        });

        Some(performance_benchmarks)
    }

    fn categorize_handshake_performance(&self, duration_ms: u64) -> &'static str {
        // FIXED: Consistent performance benchmarks for all connection types
        // These benchmarks are now consistent across TLS and QUIC connections
        match duration_ms {
            0..=200 => "excellent",    // Very fast connections
            201..=400 => "good",       // Good performance
            401..=800 => "acceptable", // Acceptable performance
            801..=1500 => "slow",      // Slow connections
            _ => "very_slow",          // Very slow connections
        }
    }

    fn calculate_performance_percentile(&self, duration_ms: u64) -> u8 {
        // Simplified percentile calculation based on typical TLS handshake times
        match duration_ms {
            0..=100 => 95,
            101..=200 => 85,
            201..=300 => 70,
            301..=400 => 50,
            401..=600 => 30,
            601..=800 => 15,
            801..=1000 => 10,
            _ => 5,
        }
    }

    fn calculate_pqc_overhead(&self, result: &ScanResult) -> u64 {
        // Estimate PQC overhead based on algorithms used
        let mut overhead = 0;

        for kex in &result.key_exchange {
            match kex.as_str() {
                "ML-KEM-512" => overhead += 50,
                "ML-KEM-768" => overhead += 100,
                "ML-KEM-1024" => overhead += 150,
                "Kyber512" => overhead += 60,
                "Kyber768" => overhead += 120,
                "Kyber1024" => overhead += 180,
                _ => {}
            }
        }

        overhead
    }

    fn calculate_certificate_overhead(&self, result: &ScanResult) -> u64 {
        if let Some(ref cert_info) = result.certificate {
            // Estimate based on certificate size
            let cert_size = cert_info.certificate_length_estimate.unwrap_or(1000);
            match cert_size {
                0..=500 => 20,
                501..=1000 => 40,
                1001..=2000 => 80,
                2001..=4000 => 150,
                _ => 300,
            }
        } else {
            0
        }
    }

    fn calculate_network_overhead(&self, result: &ScanResult) -> u64 {
        // Estimate additional network overhead beyond base TLS handshake
        // Base TLS handshake is not overhead - it's the baseline
        let mut overhead = 0u64;

        // Add overhead for PQC extensions (additional data transfer)
        if result.pqc_extensions.kem || result.pqc_extensions.kem_group {
            overhead += 50; // Reduced from 100 - PQC extensions add some overhead but not excessive
        }

        // Add overhead for large certificates (additional data transfer)
        if let Some(ref cert_info) = result.certificate {
            let cert_size = cert_info.certificate_length_estimate.unwrap_or(1000);
            // Only count overhead for certificates larger than typical (1500 bytes)
            if cert_size > 1500 {
                overhead += ((cert_size - 1500) / 20) as u64; // Rough estimate for extra bytes
            }
        }

        overhead
    }

    /// Calculate overhead share as percentage of the handshake itself (0-100%)
    /// This represents what portion of the handshake time is spent on overhead components
    fn calculate_overhead_share_percent(&self, result: &ScanResult) -> f64 {
        let handshake_duration = result.handshake_duration_ms.unwrap_or(0) as f64;
        if handshake_duration == 0.0 {
            return 0.0;
        }

        let pqc_overhead = self.calculate_pqc_overhead(result) as f64;
        let cert_overhead = self.calculate_certificate_overhead(result) as f64;
        let network_overhead = self.calculate_network_overhead(result) as f64;

        // Total overhead components
        let total_overhead = pqc_overhead + cert_overhead + network_overhead;

        // Calculate as percentage of handshake duration (0-100%)
        // Cap at 100% to ensure it represents a share, not an excess
        let share_percent = (total_overhead / handshake_duration) * 100.0;
        share_percent.min(100.0)
    }

    /// Calculate overhead as percentage relative to baseline (can be > 100%)
    /// This represents how much longer the handshake takes compared to a baseline classical handshake
    /// Formula: overhead_vs_baseline_percent = ((handshake_duration - baseline) / baseline) * 100
    fn calculate_overhead_vs_baseline_percent(&self, result: &ScanResult) -> f64 {
        let handshake_duration = result.handshake_duration_ms.unwrap_or(0) as f64;
        if handshake_duration == 0.0 {
            return 0.0;
        }

        // Baseline: typical TLS 1.3 handshake with small certificate (~150ms)
        let baseline_handshake_ms = 150.0;

        if baseline_handshake_ms == 0.0 {
            return 0.0;
        }

        // Calculate how much longer this handshake is compared to baseline
        // Formula: ((actual - baseline) / baseline) * 100
        // Example: handshake=450ms, baseline=150ms → ((450-150)/150)*100 = 200%
        // This means "this handshake takes 200% more time than baseline" (3x longer)

        // Can be negative if handshake is faster than baseline (rare but possible)
        // Can be > 100% if handshake is much slower than baseline
        ((handshake_duration - baseline_handshake_ms) / baseline_handshake_ms) * 100.0
    }

    fn identify_optimization_opportunities(&self, result: &ScanResult) -> Vec<String> {
        let mut opportunities = Vec::new();

        let handshake_duration = result.handshake_duration_ms.unwrap_or(0);

        // Check for slow handshake
        if handshake_duration > 800 {
            opportunities.push(
                "Consider using session resumption for faster subsequent handshakes".to_string(),
            );
        }

        // Check for large certificates
        if let Some(ref cert_info) = result.certificate {
            if let Some(cert_size) = cert_info.certificate_length_estimate {
                if cert_size > 2000 {
                    opportunities.push(
                        "Large certificate detected - consider optimizing certificate size"
                            .to_string(),
                    );
                }
            }
        }

        // Check for multiple PQC algorithms
        let pqc_count = result
            .key_exchange
            .iter()
            .filter(|kex| kex.contains("ML-KEM") || kex.contains("Kyber"))
            .count();
        if pqc_count > 2 {
            opportunities
                .push("Multiple PQC algorithms may increase handshake overhead".to_string());
        }

        // Check for missing optimizations
        if result.tls_features.session_ticket == Some(false) {
            opportunities.push(
                "Session tickets not enabled - consider enabling for performance".to_string(),
            );
        }

        opportunities
    }

    #[allow(dead_code)]
    fn generate_performance_warnings(&self, result: &ScanResult) -> Vec<PerformanceWarning> {
        let mut warnings = Vec::new();

        let handshake_duration = result.handshake_duration_ms.unwrap_or(0);

        // Check for slow handshake
        if handshake_duration > 1000 {
            warnings.push(PerformanceWarning {
                level: WarningLevel::Warning,
                category: "Handshake Performance".to_string(),
                message: format!("Slow handshake detected: {}ms", handshake_duration),
                impact: "Slow handshakes may impact user experience".to_string(),
                recommendation: Some(
                    "Consider optimizing TLS configuration or using session resumption".to_string(),
                ),
            });
        }

        // Check for large certificates
        if let Some(ref cert_info) = result.certificate {
            if let Some(cert_size) = cert_info.certificate_length_estimate {
                if cert_size > 3000 {
                    warnings.push(PerformanceWarning {
                        level: WarningLevel::Warning,
                        category: "Certificate Size".to_string(),
                        message: format!("Large certificate detected: {} bytes", cert_size),
                        impact: "Large certificates increase handshake overhead and may impact performance".to_string(),
                        recommendation: Some("Consider using smaller certificates or reducing the number of SAN entries".to_string()),
                    });
                }
            }
        }

        // Check for excessive PQC overhead
        let pqc_overhead = self.calculate_pqc_overhead(result);
        if pqc_overhead > 200 {
            warnings.push(PerformanceWarning {
                level: WarningLevel::Info,
                category: "PQC Overhead".to_string(),
                message: format!("High PQC overhead detected: {}ms", pqc_overhead),
                impact:
                    "PQC algorithms provide quantum resistance but increase computational overhead"
                        .to_string(),
                recommendation: Some(
                    "Consider balancing security and performance requirements".to_string(),
                ),
            });
        }

        warnings
    }

    fn generate_recommendations(
        &self,
        result: &ScanResult,
        security_score: &SecurityScore,
    ) -> Vec<HashMap<String, String>> {
        let mut recommendations = Vec::new();

        // Security recommendations
        if security_score.overall < 80 {
            recommendations.push({
                let mut rec = HashMap::new();
                rec.insert("category".to_string(), "Security".to_string());
                rec.insert("priority".to_string(), "high".to_string());
                rec.insert(
                    "message".to_string(),
                    "Overall security score is below recommended threshold".to_string(),
                );
                rec.insert(
                    "action".to_string(),
                    "Review and improve TLS configuration".to_string(),
                );
                rec
            });
        }

        // Performance recommendations (suggestion 8.4: alert when duration > 2000 ms)
        let handshake_duration = result.handshake_duration_ms.unwrap_or(0);
        if handshake_duration > 2000 {
            recommendations.push({
                let mut rec = HashMap::new();
                rec.insert("category".to_string(), "Performance".to_string());
                rec.insert("priority".to_string(), "high".to_string());
                rec.insert("message".to_string(), format!("Handshake duration {} ms exceeds 2000 ms threshold", handshake_duration));
                rec.insert("action".to_string(), "Consider tuning timeouts or concurrency; identify slow endpoints using performance_analysis and handshake_duration_ms".to_string());
                rec
            });
        } else if handshake_duration > 600 {
            recommendations.push({
                let mut rec = HashMap::new();
                rec.insert("category".to_string(), "Performance".to_string());
                rec.insert("priority".to_string(), "medium".to_string());
                rec.insert(
                    "message".to_string(),
                    "Handshake duration exceeds optimal range".to_string(),
                );
                rec.insert(
                    "action".to_string(),
                    "Consider enabling session resumption and optimizing certificate size"
                        .to_string(),
                );
                rec
            });
        }

        // PQC recommendations
        if result
            .key_exchange
            .iter()
            .any(|kex| kex.contains("ML-KEM") || kex.contains("Kyber"))
        {
            recommendations.push({
                let mut rec = HashMap::new();
                rec.insert("category".to_string(), "PQC".to_string());
                rec.insert("priority".to_string(), "low".to_string());
                rec.insert(
                    "message".to_string(),
                    "PQC algorithms are properly configured".to_string(),
                );
                rec.insert(
                    "action".to_string(),
                    "Monitor for new PQC standards and updates".to_string(),
                );
                rec
            });
        }

        recommendations
    }
}

pub fn output_results(result: &ScanResult, format: OutputFormat) {
    let formatter = OutputFormatter::new(format);
    let output = formatter.format_result(result);
    println!("{}", output);
}

/// Generate a comprehensive report in markdown format
pub fn generate_markdown_report(result: &ScanResult) -> String {
    let mut report = String::new();

    report.push_str(&"# PQC TLS Scan Report\n\n".to_string());
    report.push_str(&format!("**Target:** {}\n", result.target));
    report.push_str(&format!(
        "**Client Profile:** {}\n",
        result.client_profile_used
    ));
    if let Some(duration) = result.handshake_duration_ms {
        report.push_str(&format!("**Handshake Duration:** {}ms\n", duration));
    }
    report.push_str(&format!(
        "**Scan Date:** {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    report.push_str("## TLS Configuration\n\n");
    report.push_str(&format!(
        "- **TLS Version:** {}\n",
        result.analysis.tls_version
    ));
    report.push_str(&format!(
        "- **Cipher Suite:** {}\n",
        result.analysis.cipher_suite
    ));

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
        report.push_str(&format!(
            "- **Public Key Algorithm:** {}",
            cert.public_key_algorithm
        ));
        if let Some(size) = cert.key_size {
            report.push_str(&format!(" ({} bits)", size));
        }
        report.push('\n');
        report.push_str(&format!(
            "- **Signature Algorithm:** {}\n",
            cert.signature_algorithm
        ));
    } else {
        report.push_str("- **Certificate not available**\n");
    }

    if result.fallback.enabled {
        report.push_str("\n## Fallback Testing\n\n");
        report.push_str(&format!(
            "- **Enabled:** {}\n",
            if result.fallback.enabled { "Yes" } else { "No" }
        ));
        report.push_str(&format!(
            "- **Used:** {}\n",
            if result.fallback.used { "Yes" } else { "No" }
        ));
        if result.fallback.used && !result.fallback.attempted_profiles.is_empty() {
            report.push_str(&format!(
                "- **Attempted Profiles:** {}\n",
                result.fallback.attempted_profiles.join(", ")
            ));
        }
    }

    report.push_str("\n## Recommendations\n\n");
    if result.pqc_detected {
        report.push_str(
            "✅ This server is **quantum-ready** with Post-Quantum Cryptography support.\n\n",
        );

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
    use crate::types::{CertificateInfo, HandshakeProfile, HandshakeResult, PqcExtensions};

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
                signature_algorithm_oid: Some("1.2.840.113549.1.1.11".to_string()), // RSA-SHA256 OID
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
            pqc_signature_used: Some(false),
            tls_features: TlsFeatures::default(),
            handshake_duration_ms: Some(150),
            client_profile_used: HandshakeProfile::CloudflarePqc,
            extension_map: crate::types::ExtensionMap::default(),
            connection_type: None,
            cipher_suite_reason: None,
        };

        result.update_from_handshake(handshake_result);

        assert_eq!(result.target, "example.com:443");
        assert_eq!(result.analysis.tls_version, "TLS 1.3");
        assert!(result.analysis.pqc_detected);
        assert_eq!(result.handshake_duration_ms, Some(150));
        // HandshakeProfile::CloudflarePqc maps to "Fallback" in update_from_handshake
        assert_eq!(result.client_profile_used, "Fallback");
    }

    #[test]
    fn test_json_serialization() {
        let result = ScanResult::new("test.com:443".to_string());
        let json = serde_json::to_string(&result)
            .expect("JSON serialization should never fail for ScanResult");
        assert!(json.contains("test.com:443"));
    }
}
