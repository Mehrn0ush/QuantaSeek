use crate::types::{PqcAnalysis, SignatureNegotiationStatus};

/// Detects post-quantum signature algorithms from captured handshake data.
///
/// Codepoints and OIDs come from [`crate::constants`]; nothing here is
/// inferred from hostnames, certificate sizes or string heuristics.
#[derive(Default)]
pub struct SignatureDetector;

impl SignatureDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect PQC signature algorithms from handshake data.
    ///
    /// ServerHello never carries `signature_algorithms` (RFC 8446 §4.2), so the
    /// only source here is the signature algorithm of a captured certificate.
    pub fn detect_pqc_signatures(
        &self,
        _raw_server_hello: &[u8],
        raw_certificate: &[u8],
        tls_version: &str,
        certificate_visible: bool,
    ) -> (Vec<String>, SignatureNegotiationStatus, Option<String>) {
        if tls_version != "1.3" {
            return (Vec::new(), SignatureNegotiationStatus::NotApplicable, None);
        }

        if certificate_visible {
            if let Some(cert_signature) = self.extract_certificate_signature(raw_certificate) {
                if self.is_pqc_signature_algorithm(&cert_signature) {
                    return (
                        vec![cert_signature.clone()],
                        SignatureNegotiationStatus::Negotiated,
                        Some(cert_signature),
                    );
                }
            }
        }

        (Vec::new(), SignatureNegotiationStatus::Unknown, None)
    }

    /// Extract the signature algorithm from a DER certificate.
    fn extract_certificate_signature(&self, cert_data: &[u8]) -> Option<String> {
        if cert_data.len() < 4 {
            return None;
        }
        let parser = crate::cert::CertificateParser::new();
        let cert_info = parser.parse_certificate(cert_data).ok()?;
        if let Some(ref oid) = cert_info.signature_algorithm_oid {
            if crate::constants::is_pqc_oid(oid) {
                return Some(format!("pqc_sig_oid:{}", oid));
            }
        }
        Some(cert_info.signature_algorithm)
    }

    /// True for a PQC TLS signature scheme name or a `pqc_sig_oid:` label.
    fn is_pqc_signature_algorithm(&self, sig_alg: &str) -> bool {
        if let Some(oid) = sig_alg.strip_prefix("pqc_sig_oid:") {
            return crate::constants::is_pqc_oid(oid);
        }
        crate::constants::is_pqc_signature_scheme_name(sig_alg)
    }

    /// Update PQC analysis with signature detection results
    pub fn update_analysis(
        &self,
        analysis: &mut PqcAnalysis,
        detected_signatures: &[String],
        negotiation_status: SignatureNegotiationStatus,
        used_signature: Option<String>,
    ) {
        // Update signature algorithms list
        analysis.pqc_signature_algorithms = detected_signatures.to_vec();

        // Update signature negotiation status
        analysis.signature_negotiation_status = negotiation_status.clone();

        // Update used signature algorithm
        analysis.pqc_signature_algorithm = used_signature.clone();

        // Update signature usage status based on negotiation status
        // FIXED: Set pqc_signature_used to None when status is Unknown
        match negotiation_status {
            SignatureNegotiationStatus::Negotiated => {
                analysis.pqc_signature_used = Some(true);
                if !detected_signatures.is_empty() {
                    analysis.pqc_signature_status = format!(
                        "Negotiated: {} algorithms detected",
                        detected_signatures.len()
                    );
                } else {
                    analysis.pqc_signature_status =
                        "Negotiated via certificate signature".to_string();
                }
            }
            SignatureNegotiationStatus::NotOffered => {
                analysis.pqc_signature_used = Some(false);
                analysis.pqc_signature_status = "Not offered by client or server".to_string();
            }
            SignatureNegotiationStatus::Rejected => {
                analysis.pqc_signature_used = Some(false);
                analysis.pqc_signature_status = "Rejected by server during negotiation".to_string();
            }
            SignatureNegotiationStatus::NotApplicable => {
                analysis.pqc_signature_used = Some(false);
                analysis.pqc_signature_status = "Not applicable (TLS 1.2 or earlier)".to_string();
            }
            SignatureNegotiationStatus::Unknown => {
                // FIXED: Set to None when Unknown (TLS 1.3 encrypted)
                analysis.pqc_signature_used = None;
                if used_signature.is_some() {
                    analysis.pqc_signature_status =
                        "Detected via certificate analysis (TLS 1.3 encrypted)".to_string();
                } else if !detected_signatures.is_empty() {
                    analysis.pqc_signature_status = format!(
                        "{} algorithms detected but usage unclear (TLS 1.3 encrypted)",
                        detected_signatures.len()
                    );
                } else {
                    // No observable signature data – treat as genuinely unknown rather than
                    // a \"not implemented\" scanner feature gap.
                    analysis.pqc_signature_status =
                        "Unknown (no observable PQC signature data; TLS 1.3 handshake encrypted)"
                            .to_string();
                }
            }
        }

        // Add detailed information about detected algorithms
        if !detected_signatures.is_empty() {
            let algorithm_details = detected_signatures.join(", ");
            if !analysis
                .pqc_signature_status
                .contains("algorithms detected")
            {
                analysis
                    .pqc_signature_status
                    .push_str(&format!(" - Detected: {}", algorithm_details));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_signature_detection() {
        let detector = SignatureDetector::new();
        assert!(detector.is_pqc_signature_algorithm("mldsa65"));
        assert!(detector.is_pqc_signature_algorithm("slhdsa_sha2_128s"));
        assert!(detector.is_pqc_signature_algorithm("pqc_sig_oid:2.16.840.1.101.3.4.3.18"));
        assert!(!detector.is_pqc_signature_algorithm("pqc_sig_oid:1.2.840.113549.1.1.11"));
        assert!(!detector.is_pqc_signature_algorithm("RSA-SHA256"));
        assert!(!detector.is_pqc_signature_algorithm("ECDSA-SHA256"));
        // Substring matches must not count: "lms" appears in many strings.
        assert!(!detector.is_pqc_signature_algorithm("helms"));
    }

    #[test]
    fn tls12_is_not_applicable() {
        let detector = SignatureDetector::new();
        let (sigs, status, used) = detector.detect_pqc_signatures(&[], &[], "1.2", true);
        assert!(sigs.is_empty());
        assert_eq!(status, SignatureNegotiationStatus::NotApplicable);
        assert!(used.is_none());
    }
}
