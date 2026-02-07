use crate::types::CertificateInfo;
use anyhow::{anyhow, Result};
use x509_parser::der_parser::asn1_rs::FromDer;
use x509_parser::der_parser::asn1_rs::Oid;
use x509_parser::prelude::*;

// Note: ASN.1 DER constants and OIDs are not used in the current implementation
// as we rely on the x509-parser crate for certificate parsing

pub struct CertificateParser;

impl Default for CertificateParser {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_certificate(&self, data: &[u8]) -> Result<CertificateInfo> {
        // Use x509-parser to parse the certificate
        let (_, cert) = X509Certificate::from_der(data)
            .map_err(|e| anyhow!("Failed to parse X.509 certificate: {:?}", e))?;

        // Extract subject and issuer
        let subject = self.format_name(&cert.tbs_certificate.subject);
        let issuer = self.format_name(&cert.tbs_certificate.issuer);

        // Extract public key algorithm and size
        let (public_key_algorithm, key_size) =
            self.extract_public_key_info(&cert.tbs_certificate.subject_pki);

        // Extract signature algorithm (this is the algorithm used to sign the certificate)
        let sig_oid = &cert.signature_algorithm.algorithm;
        // FIXED: Use to_string() method - same as used in oid_to_signature_algorithm_name
        // This is the proven method that works in other parts of the code
        // Always store the OID string, even if empty (for debugging purposes)
        let signature_algorithm_oid = Some(sig_oid.to_string());
        let signature_algorithm = self.oid_to_signature_algorithm_name(sig_oid);

        // Extract validity dates
        let valid_from = cert
            .tbs_certificate
            .validity
            .not_before
            .to_rfc2822()
            .unwrap_or_else(|_| "Unknown".to_string());
        let valid_to = cert
            .tbs_certificate
            .validity
            .not_after
            .to_rfc2822()
            .unwrap_or_else(|_| "Unknown".to_string());

        // Extract SAN (Subject Alternative Name) if available
        let san = self.extract_san(&cert.tbs_certificate);

        // Calculate certificate length estimate (DER format)
        let certificate_length_estimate = Some(data.len() as u32);

        let certificate_info = CertificateInfo {
            subject,
            issuer,
            public_key_algorithm,
            signature_algorithm,
            signature_algorithm_oid,
            key_size,
            valid_from,
            valid_to,
            san,
            certificate_length_estimate,
            algorithm_consistency: false, // Will be set below
        };

        // Validate algorithm consistency
        let algorithm_consistency = CertificateParser::validate_algorithm_consistency(
            &certificate_info.public_key_algorithm,
            &certificate_info.signature_algorithm,
        );

        Ok(CertificateInfo {
            algorithm_consistency,
            ..certificate_info
        })
    }

    fn format_name(&self, name: &X509Name) -> String {
        // Try to extract Common Name (CN) first
        if let Some(cn) = name.iter_common_name().next() {
            if let Ok(cn_str) = cn.as_str() {
                return cn_str.to_string();
            }
        }

        // Fallback to full name formatting
        name.iter()
            .filter_map(|rdn| {
                rdn.iter()
                    .filter_map(|attr| {
                        let oid_str = attr.attr_type().to_string();
                        let value = attr.as_str().ok()?;
                        Some(format!("{}={}", oid_str, value))
                    })
                    .next()
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn extract_public_key_info(&self, subject_pki: &SubjectPublicKeyInfo) -> (String, Option<u32>) {
        let algorithm = self.oid_to_algorithm_name(&subject_pki.algorithm.algorithm);
        let key_size = self.estimate_key_size(&algorithm, &subject_pki.subject_public_key.data);

        // If key size extraction failed, try to estimate based on algorithm and data length
        let key_size = key_size.or_else(|| {
            match algorithm.as_str() {
                "RSA" | "RSA-SHA256" | "RSA-SHA384" | "RSA-SHA512" => {
                    // Estimate RSA key size from data length
                    let data_len = subject_pki.subject_public_key.data.len();
                    if data_len > 0 {
                        // Rough estimate: RSA key size is typically data_len * 8 - some overhead
                        let estimated_bits = (data_len * 8).saturating_sub(64);
                        if (1024..=8192).contains(&estimated_bits) {
                            Some(estimated_bits as u32)
                        } else {
                            // Fallback to common RSA key sizes
                            Some(2048)
                        }
                    } else {
                        Some(2048) // Default fallback
                    }
                }
                "ECDSA" | "ECDSA P-256" | "ECDSA-SHA256" => Some(256),
                "ECDSA P-384" | "ECDSA-SHA384" => Some(384),
                "ECDSA P-521" | "ECDSA-SHA512" => Some(521),
                _ => None,
            }
        });

        (algorithm, key_size)
    }

    fn oid_to_algorithm_name(&self, oid: &Oid) -> String {
        match oid.to_string().as_str() {
            "1.2.840.113549.1.1.1" => "RSA".to_string(),
            "1.2.840.10045.2.1" => "ECDSA".to_string(),
            "1.2.840.10045.3.1.7" => "ECDSA P-256".to_string(),
            "1.3.132.0.34" => "ECDSA P-384".to_string(),
            "1.3.132.0.35" => "ECDSA P-521".to_string(),
            "1.2.840.113549.1.1.11" => "RSA-SHA256".to_string(),
            "1.2.840.113549.1.1.12" => "RSA-SHA384".to_string(),
            "1.2.840.113549.1.1.13" => "RSA-SHA512".to_string(),
            "1.2.840.10045.4.3.2" => "ECDSA-SHA256".to_string(),
            "1.2.840.10045.4.3.3" => "ECDSA-SHA384".to_string(),
            "1.2.840.10045.4.3.4" => "ECDSA-SHA512".to_string(),
            // PQC OIDs (draft/experimental)
            "1.3.6.1.4.1.2.267.1.6.5" => "Dilithium3".to_string(),
            "1.3.6.1.4.1.2.267.1.6.7" => "Dilithium5".to_string(),
            "1.3.6.1.4.1.2.267.1.5.3" => "Falcon-512".to_string(),
            "1.3.6.1.4.1.2.267.1.5.4" => "Falcon-1024".to_string(),
            "1.3.6.1.4.1.2.267.1.1.1" => "Kyber512".to_string(),
            "1.3.6.1.4.1.2.267.1.1.2" => "Kyber768".to_string(),
            "1.3.6.1.4.1.2.267.1.1.3" => "Kyber1024".to_string(),
            "1.3.6.1.4.1.2.267.1.1.4" => "ML-KEM-512".to_string(),
            "1.3.6.1.4.1.2.267.1.1.5" => "ML-KEM-768".to_string(),
            "1.3.6.1.4.1.2.267.1.1.6" => "ML-KEM-1024".to_string(),
            _ => format!("OID({})", oid),
        }
    }

    fn estimate_key_size(&self, algorithm: &str, key_data: &[u8]) -> Option<u32> {
        match algorithm {
            "RSA" | "RSA-SHA256" | "RSA-SHA384" | "RSA-SHA512" => {
                self.extract_rsa_key_size(key_data).ok()
            }
            "ECDSA" | "ECDSA P-256" | "ECDSA-SHA256" => Some(256),
            "ECDSA P-384" | "ECDSA-SHA384" => Some(384),
            "ECDSA P-521" | "ECDSA-SHA512" => Some(521),
            "Dilithium3" => Some(1952),
            "Dilithium5" => Some(2592),
            "Falcon-512" => Some(896),
            "Falcon-1024" => Some(1792),
            "Kyber512" | "ML-KEM-512" => Some(512),
            "Kyber768" | "ML-KEM-768" => Some(768),
            "Kyber1024" | "ML-KEM-1024" => Some(1024),
            _ => None,
        }
    }

    fn extract_rsa_key_size(&self, key_data: &[u8]) -> Result<u32> {
        // Parse RSA public key from DER
        if key_data.len() < 2 {
            return Err(anyhow!(
                "Invalid RSA key data: too short ({} bytes)",
                key_data.len()
            ));
        }

        // Skip the first byte (unused bits indicator for BIT STRING)
        let data = if key_data[0] == 0 {
            &key_data[1..]
        } else {
            key_data
        };

        // Parse SEQUENCE
        if data.is_empty() || data[0] != 0x30 {
            return Err(anyhow!(
                "Expected SEQUENCE for RSA public key, got 0x{:02x}",
                data[0]
            ));
        }

        // Parse modulus (first INTEGER in the sequence)
        let mut pos = 2; // Skip tag and length
        if pos >= data.len() {
            return Err(anyhow!("Data too short after SEQUENCE"));
        }

        if data[pos] != 0x02 {
            return Err(anyhow!(
                "Expected INTEGER for RSA modulus, got 0x{:02x}",
                data[pos]
            ));
        }
        pos += 1;

        if pos >= data.len() {
            return Err(anyhow!("Data too short after INTEGER tag"));
        }

        // Read length
        let length = if data[pos] & 0x80 == 0 {
            data[pos] as usize
        } else {
            let len_bytes = (data[pos] & 0x7f) as usize;
            pos += 1;
            if pos + len_bytes > data.len() {
                return Err(anyhow!("Invalid RSA key length encoding"));
            }
            let mut length = 0u32;
            for &byte in &data[pos..pos + len_bytes] {
                length = (length << 8) | byte as u32;
            }
            length as usize
        };
        pos += 1;

        if pos + length > data.len() {
            return Err(anyhow!("Modulus data extends beyond available data"));
        }

        // Calculate actual modulus size in bits
        // Account for leading zero byte if present (for padding)
        let modulus_data = &data[pos..pos + length];
        let actual_bits = if !modulus_data.is_empty() && modulus_data[0] == 0 {
            (modulus_data.len() - 1) * 8
        } else {
            modulus_data.len() * 8
        };

        // Validate reasonable key size
        if !(512..=8192).contains(&actual_bits) {
            return Err(anyhow!("Unreasonable RSA key size: {} bits", actual_bits));
        }

        Ok(actual_bits as u32)
    }

    fn extract_san(&self, tbs_certificate: &TbsCertificate) -> Option<String> {
        // Look for Subject Alternative Name extension
        for extension in tbs_certificate.extensions() {
            if extension.oid.to_string() == "2.5.29.17" {
                // Subject Alternative Name OID
                // Try to parse the SAN extension value
                if let Ok(san_names) = self.parse_san_extension(extension.value) {
                    return Some(san_names);
                }
            }
        }

        None
    }

    fn parse_san_extension(&self, san_data: &[u8]) -> Result<String> {
        // Simplified SAN parser that looks for DNS name patterns
        // This is a more robust approach than complex ASN.1 parsing

        let mut dns_names = Vec::new();
        let mut pos = 0;

        while pos < san_data.len() {
            // Look for DNS name tag (0x82) - ContextSpecific(2)
            if pos + 2 < san_data.len() && san_data[pos] == 0x82 {
                let length = san_data[pos + 1] as usize;
                if pos + 2 + length <= san_data.len() {
                    let dns_data = &san_data[pos + 2..pos + 2 + length];
                    if let Ok(dns_str) = String::from_utf8(dns_data.to_vec()) {
                        // Validate it looks like a DNS name
                        if dns_str.contains('.') && !dns_str.contains('\0') && dns_str.len() > 1 {
                            dns_names.push(dns_str);
                        }
                    }
                }
                pos += 2 + length;
            } else {
                pos += 1;
            }
        }

        // Also try to find DNS names in the raw data as a fallback
        if dns_names.is_empty() {
            let data_str = String::from_utf8_lossy(san_data);
            // Look for patterns that might be DNS names
            for word in data_str.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-') {
                if word.contains('.')
                    && word.len() > 3
                    && !word.starts_with('.')
                    && !word.ends_with('.')
                {
                    // Basic DNS name validation
                    if word
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
                    {
                        dns_names.push(word.to_string());
                    }
                }
            }
        }

        if dns_names.is_empty() {
            // Final fallback: indicate presence but parsing failed
            Ok("DNS names present (parsing failed)".to_string())
        } else {
            // Remove duplicates and join
            dns_names.sort();
            dns_names.dedup();
            Ok(dns_names.join(", "))
        }
    }

    fn oid_to_signature_algorithm_name(&self, oid: &Oid) -> String {
        match oid.to_string().as_str() {
            // RSA signature algorithms
            "1.2.840.113549.1.1.11" => "RSA-SHA256".to_string(),
            "1.2.840.113549.1.1.12" => "RSA-SHA384".to_string(),
            "1.2.840.113549.1.1.13" => "RSA-SHA512".to_string(),
            "1.2.840.113549.1.1.5" => "RSA-SHA1".to_string(),

            // ECDSA signature algorithms
            "1.2.840.10045.4.3.2" => "ECDSA-SHA256".to_string(),
            "1.2.840.10045.4.3.3" => "ECDSA-SHA384".to_string(),
            "1.2.840.10045.4.3.4" => "ECDSA-SHA512".to_string(),
            "1.2.840.10045.4.1" => "ECDSA-SHA1".to_string(),

            // EdDSA signature algorithms
            "1.3.101.112" => "Ed25519".to_string(),
            "1.3.101.113" => "Ed448".to_string(),

            // PQC signature algorithms (draft/experimental)
            "1.3.6.1.4.1.2.267.1.6.5" => "Dilithium3".to_string(),
            "1.3.6.1.4.1.2.267.1.6.7" => "Dilithium5".to_string(),
            "1.3.6.1.4.1.2.267.1.5.3" => "Falcon-512".to_string(),
            "1.3.6.1.4.1.2.267.1.5.4" => "Falcon-1024".to_string(),

            _ => format!("OID({})", oid),
        }
    }

    pub fn validate_algorithm_consistency(
        public_key_algorithm: &str,
        signature_algorithm: &str,
    ) -> bool {
        // Algorithm consistency check: Validates if the certificate's public key algorithm
        // and signature algorithm (used by issuer to sign this certificate) form a valid combination.
        //
        // IMPORTANT: signature_algorithm refers to the algorithm used by the ISSUER to sign
        // this certificate, NOT the algorithm of the certificate's own public key.
        // It is NORMAL for an ECDSA public key to be signed with RSA (or vice versa).
        // Example: Google certificates often have ECDSA public keys signed with RSA-SHA256.
        //
        // This function returns true if the combination is valid/normal, false if inconsistent.

        let pub_key_lower = public_key_algorithm.to_lowercase();
        let sig_lower = signature_algorithm.to_lowercase();

        // Check for actual inconsistencies (same certificate, incompatible algorithms)
        match (pub_key_lower.as_str(), sig_lower.as_str()) {
            // Valid combinations for same certificate
            ("rsa", sig) if sig.contains("rsa") => true,
            ("ecdsa", sig) if sig.contains("ecdsa") => true,
            ("ed25519", "ed25519") => true,
            ("ed448", "ed448") => true,
            // PQC signature algorithms can be used with any public key
            (_, sig)
                if sig.contains("dilithium")
                    || sig.contains("falcon")
                    || sig.contains("sphincs") =>
            {
                true
            }
            // Mixed issuer-subject algorithms are normal, not inconsistent
            // ECDSA leaf certificate signed by RSA issuer (common in practice)
            ("ecdsa", sig) if sig.contains("rsa") => true,
            // RSA leaf certificate signed by ECDSA issuer (less common but valid)
            ("rsa", sig) if sig.contains("ecdsa") => true,
            // Invalid combinations (should not occur in valid certificates)
            _ => false,
        }
    }

    /// Validate if a hostname matches the certificate's SAN or subject
    pub fn validate_hostname_match(hostname: &str, san: &Option<String>, subject: &str) -> bool {
        let hostname_lower = hostname.to_lowercase();

        // First check SAN if available
        if let Some(ref san_str) = san {
            if Self::hostname_matches_san(&hostname_lower, san_str) {
                return true;
            }
            // RFC 5280: If SAN is present, it is the authoritative source
            // Do not fall back to subject CN when SAN is present
            return false;
        }

        // Fallback to subject CN check only when SAN is not present
        Self::hostname_matches_subject(&hostname_lower, subject)
    }

    /// Query Certificate Transparency logs for certificate information
    ///
    /// NOTE: This is a placeholder implementation. In a real implementation, you would:
    /// 1. Query multiple CT log servers (e.g., Google, Cloudflare, DigiCert)
    /// 2. Parse the returned certificate data
    /// 3. Extract signature algorithms and other details
    ///
    /// FIXED: Do not return mock data - return None to indicate unavailability
    /// Mock data is unreliable and misleading. Certificate information should only
    /// come from real TLS handshakes or real CT log API queries.
    pub async fn query_ct_logs(_hostname: &str) -> Result<Option<CertificateInfo>> {
        // FIXED: Do not return mock certificate data
        // CT log queries require real API integration with CT log servers
        // Returning None indicates that certificate information is not available
        // without real CT log API implementation
        Ok(None)
    }

    /// Extract PQC signature algorithms from CT log data
    pub fn extract_pqc_signatures_from_ct(cert_info: &CertificateInfo) -> Vec<String> {
        let mut pqc_signatures = Vec::new();

        // Analyze certificate for PQC signature indicators
        let cert_str = format!(
            "{} {} {}",
            cert_info.public_key_algorithm, cert_info.signature_algorithm, cert_info.subject
        )
        .to_lowercase();

        // Look for PQC signature algorithm indicators
        if cert_str.contains("dilithium") {
            if cert_str.contains("2") {
                pqc_signatures.push("Dilithium2".to_string());
            } else if cert_str.contains("3") {
                pqc_signatures.push("Dilithium3".to_string());
            } else if cert_str.contains("5") {
                pqc_signatures.push("Dilithium5".to_string());
            }
        }

        if cert_str.contains("falcon") {
            if cert_str.contains("512") {
                pqc_signatures.push("Falcon512".to_string());
            } else if cert_str.contains("1024") {
                pqc_signatures.push("Falcon1024".to_string());
            }
        }

        if cert_str.contains("sphincs") {
            pqc_signatures.push("SPHINCS+-SHA256-128f-simple".to_string());
        }

        pqc_signatures
    }

    /// Check if hostname matches any DNS name in SAN
    pub fn hostname_matches_san(hostname: &str, san: &str) -> bool {
        // Split SAN into individual DNS names
        let dns_names: Vec<&str> = san.split(',').map(|s| s.trim()).collect();

        for dns_name in dns_names {
            if Self::hostname_matches_dns_name(hostname, dns_name) {
                return true;
            }
        }

        false
    }

    /// Check if hostname matches a specific DNS name (including wildcards)
    pub fn hostname_matches_dns_name(hostname: &str, dns_name: &str) -> bool {
        // Handle empty strings
        if hostname.is_empty() || dns_name.is_empty() {
            return false;
        }

        let hostname_lower = hostname.to_lowercase();
        let dns_name_lower = dns_name.to_lowercase();

        // Exact match
        if hostname_lower == dns_name_lower {
            return true;
        }

        // Wildcard match (e.g., *.example.com matches sub.example.com)
        if let Some(wildcard_domain) = dns_name_lower.strip_prefix("*.") {
            // Remove "*."

            // RFC 6125: Wildcard should not match the domain itself
            if hostname_lower == wildcard_domain {
                return false;
            }

            // Check if hostname ends with the wildcard domain
            if hostname_lower.ends_with(wildcard_domain) {
                // Find the position of the last dot before the wildcard domain
                let wildcard_start = hostname_lower.len() - wildcard_domain.len();
                if wildcard_start > 0 {
                    let hostname_before_wildcard = &hostname_lower[..wildcard_start - 1]; // -1 to remove the dot
                                                                                          // Ensure the part before the wildcard domain is not empty and doesn't contain dots
                    if !hostname_before_wildcard.is_empty()
                        && !hostname_before_wildcard.contains('.')
                    {
                        // Additional check: ensure we're not matching a top-level domain
                        // This prevents *.com from matching example.com
                        if wildcard_domain.contains('.') {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if hostname matches the subject CN
    pub fn hostname_matches_subject(hostname: &str, subject: &str) -> bool {
        let subject_lower = subject.to_lowercase();

        // Extract CN from subject (format: "CN=example.com, O=Organization, C=US")
        if let Some(cn_start) = subject_lower.find("cn=") {
            let cn_part = &subject_lower[cn_start..];
            if let Some(cn_end) = cn_part.find(',') {
                let cn = &cn_part[3..cn_end].trim(); // Remove "cn=" and trim
                return Self::hostname_matches_dns_name(hostname, cn);
            } else {
                // No comma found, take the rest
                let cn = &cn_part[3..].trim();
                return Self::hostname_matches_dns_name(hostname, cn);
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_matches_dns_name_exact() {
        // Test exact matches
        assert!(CertificateParser::hostname_matches_dns_name(
            "example.com",
            "example.com"
        ));
        assert!(CertificateParser::hostname_matches_dns_name(
            "www.example.com",
            "www.example.com"
        ));
        assert!(CertificateParser::hostname_matches_dns_name(
            "sub.example.com",
            "sub.example.com"
        ));

        // Test case insensitivity
        assert!(CertificateParser::hostname_matches_dns_name(
            "Example.Com",
            "example.com"
        ));
        assert!(CertificateParser::hostname_matches_dns_name(
            "example.com",
            "EXAMPLE.COM"
        ));

        // Test non-matches
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "example.org"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "www.example.com",
            "example.com"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "www.example.com"
        ));
    }

    #[test]
    fn test_hostname_matches_dns_name_wildcard() {
        // Test valid wildcard matches
        assert!(CertificateParser::hostname_matches_dns_name(
            "sub.example.com",
            "*.example.com"
        ));
        assert!(CertificateParser::hostname_matches_dns_name(
            "api.example.com",
            "*.example.com"
        ));
        assert!(CertificateParser::hostname_matches_dns_name(
            "www.example.com",
            "*.example.com"
        ));

        // Test wildcard with multiple subdomains
        assert!(CertificateParser::hostname_matches_dns_name(
            "api.sub.example.com",
            "*.sub.example.com"
        ));

        // Test case insensitivity for wildcards
        assert!(CertificateParser::hostname_matches_dns_name(
            "Sub.Example.Com",
            "*.example.com"
        ));
        assert!(CertificateParser::hostname_matches_dns_name(
            "sub.example.com",
            "*.EXAMPLE.COM"
        ));
    }

    #[test]
    fn test_hostname_matches_dns_name_wildcard_invalid() {
        // Test invalid wildcard matches (RFC 6125 rules)

        // Wildcard should not match the domain itself
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "*.example.com"
        ));

        // Wildcard should not match multiple levels
        assert!(!CertificateParser::hostname_matches_dns_name(
            "api.sub.example.com",
            "*.example.com"
        ));

        // Wildcard should not match IP addresses
        assert!(!CertificateParser::hostname_matches_dns_name(
            "192.168.1.1",
            "*.example.com"
        ));

        // Wildcard should not match invalid domains
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "*.com"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "*.org"
        ));

        // Wildcard should not match empty subdomain
        assert!(!CertificateParser::hostname_matches_dns_name(
            ".example.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_hostname_matches_dns_name_edge_cases() {
        // Test edge cases
        assert!(!CertificateParser::hostname_matches_dns_name(
            "",
            "example.com"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            ""
        ));
        assert!(!CertificateParser::hostname_matches_dns_name("", ""));

        // Test with dots
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example..com",
            "*.example.com"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "*.example..com"
        ));

        // Test with special characters
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example-com",
            "*.example.com"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "*.example-com"
        ));
    }

    #[test]
    fn test_hostname_matches_san() {
        // Test SAN with single entry
        assert!(CertificateParser::hostname_matches_san(
            "example.com",
            "example.com"
        ));
        assert!(CertificateParser::hostname_matches_san(
            "www.example.com",
            "*.example.com"
        ));

        // Test SAN with multiple entries
        let san = "example.com, *.example.com, api.example.com";
        assert!(CertificateParser::hostname_matches_san("example.com", san));
        assert!(CertificateParser::hostname_matches_san(
            "www.example.com",
            san
        ));
        assert!(CertificateParser::hostname_matches_san(
            "api.example.com",
            san
        ));
        assert!(!CertificateParser::hostname_matches_san("other.com", san));

        // Test SAN with spaces
        let san_with_spaces = " example.com , *.example.com , api.example.com ";
        assert!(CertificateParser::hostname_matches_san(
            "example.com",
            san_with_spaces
        ));
        assert!(CertificateParser::hostname_matches_san(
            "www.example.com",
            san_with_spaces
        ));

        // Test empty SAN
        assert!(!CertificateParser::hostname_matches_san("example.com", ""));
    }

    #[test]
    fn test_hostname_matches_subject() {
        // Test subject CN extraction and matching
        let subject = "CN=example.com, O=Organization, C=US";
        assert!(CertificateParser::hostname_matches_subject(
            "example.com",
            subject
        ));
        assert!(!CertificateParser::hostname_matches_subject(
            "www.example.com",
            subject
        ));

        // Test subject with wildcard CN
        let subject_wildcard = "CN=*.example.com, O=Organization, C=US";
        assert!(!CertificateParser::hostname_matches_subject(
            "example.com",
            subject_wildcard
        ));
        assert!(CertificateParser::hostname_matches_subject(
            "www.example.com",
            subject_wildcard
        ));

        // Test subject with different case
        let subject_upper = "CN=EXAMPLE.COM, O=Organization, C=US";
        assert!(CertificateParser::hostname_matches_subject(
            "example.com",
            subject_upper
        ));

        // Test subject with hostname in different case
        let subject_lower = "CN=example.com, O=Organization, C=US";
        assert!(CertificateParser::hostname_matches_subject(
            "EXAMPLE.COM",
            subject_lower
        ));

        // Test subject without CN
        let subject_no_cn = "O=Organization, C=US";
        assert!(!CertificateParser::hostname_matches_subject(
            "example.com",
            subject_no_cn
        ));

        // Test subject with CN at end
        let subject_cn_end = "O=Organization, C=US, CN=example.com";
        assert!(CertificateParser::hostname_matches_subject(
            "example.com",
            subject_cn_end
        ));

        // Test subject with multiple CNs (should match first)
        let subject_multiple_cn = "CN=example.com, CN=other.com, O=Organization";
        assert!(CertificateParser::hostname_matches_subject(
            "example.com",
            subject_multiple_cn
        ));
        assert!(!CertificateParser::hostname_matches_subject(
            "other.com",
            subject_multiple_cn
        ));
    }

    #[test]
    fn test_validate_hostname_match() {
        // Test with SAN match
        let san = Some("example.com, *.example.com".to_string());
        let subject = "CN=other.com, O=Organization, C=US";

        assert!(CertificateParser::validate_hostname_match(
            "example.com",
            &san,
            subject
        ));
        assert!(CertificateParser::validate_hostname_match(
            "www.example.com",
            &san,
            subject
        ));
        assert!(!CertificateParser::validate_hostname_match(
            "other.com",
            &san,
            subject
        ));

        // Test with SAN None, subject match
        let san_none: Option<String> = None;
        let subject_match = "CN=example.com, O=Organization, C=US";

        assert!(CertificateParser::validate_hostname_match(
            "example.com",
            &san_none,
            subject_match
        ));
        assert!(!CertificateParser::validate_hostname_match(
            "www.example.com",
            &san_none,
            subject_match
        ));

        // Test with neither SAN nor subject match
        let san_no_match = Some("other.com".to_string());
        let subject_no_match = "CN=other.com, O=Organization, C=US";

        assert!(!CertificateParser::validate_hostname_match(
            "example.com",
            &san_no_match,
            subject_no_match
        ));

        // Test case insensitivity
        assert!(CertificateParser::validate_hostname_match(
            "EXAMPLE.COM",
            &san,
            subject
        ));
        assert!(CertificateParser::validate_hostname_match(
            "Example.Com",
            &san,
            subject
        ));
    }

    #[test]
    fn test_real_world_examples() {
        // Test real-world certificate examples

        // Google certificate
        let google_san = Some("google.com, *.google.com, *.googleapis.com".to_string());
        let google_subject = "CN=google.com, O=Google LLC, C=US";

        assert!(CertificateParser::validate_hostname_match(
            "google.com",
            &google_san,
            google_subject
        ));
        assert!(CertificateParser::validate_hostname_match(
            "www.google.com",
            &google_san,
            google_subject
        ));
        assert!(CertificateParser::validate_hostname_match(
            "maps.google.com",
            &google_san,
            google_subject
        ));
        assert!(CertificateParser::validate_hostname_match(
            "api.googleapis.com",
            &google_san,
            google_subject
        ));
        assert!(!CertificateParser::validate_hostname_match(
            "google.org",
            &google_san,
            google_subject
        ));

        // Cloudflare certificate
        let cloudflare_san = Some("*.cloudflare.com, cloudflare.com, *.cloudflare.net".to_string());
        let cloudflare_subject = "CN=*.cloudflare.com, O=Cloudflare Inc, C=US";

        assert!(CertificateParser::validate_hostname_match(
            "cloudflare.com",
            &cloudflare_san,
            cloudflare_subject
        ));
        assert!(CertificateParser::validate_hostname_match(
            "www.cloudflare.com",
            &cloudflare_san,
            cloudflare_subject
        ));
        assert!(CertificateParser::validate_hostname_match(
            "api.cloudflare.com",
            &cloudflare_san,
            cloudflare_subject
        ));
        assert!(CertificateParser::validate_hostname_match(
            "cdn.cloudflare.net",
            &cloudflare_san,
            cloudflare_subject
        ));
        assert!(!CertificateParser::validate_hostname_match(
            "cloudflare.org",
            &cloudflare_san,
            cloudflare_subject
        ));

        // GitHub certificate
        let github_san = Some("github.com, *.github.com, *.githubusercontent.com".to_string());
        let github_subject = "CN=github.com, O=GitHub Inc, C=US";

        assert!(CertificateParser::validate_hostname_match(
            "github.com",
            &github_san,
            github_subject
        ));
        assert!(CertificateParser::validate_hostname_match(
            "api.github.com",
            &github_san,
            github_subject
        ));
        assert!(CertificateParser::validate_hostname_match(
            "raw.githubusercontent.com",
            &github_san,
            github_subject
        ));
        assert!(!CertificateParser::validate_hostname_match(
            "github.org",
            &github_san,
            github_subject
        ));
    }

    #[test]
    fn test_edge_cases_and_security() {
        // Test potential security issues

        // Test for wildcard abuse prevention
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "*.com"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "*.org"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "*"
        ));

        // Test for null byte injection (should not panic)
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com\0",
            "example.com"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "example.com\0"
        ));

        // Test for very long hostnames
        let long_hostname = "a".repeat(1000) + ".example.com";
        let long_dns_name = "a".repeat(1000) + ".example.com";
        assert!(CertificateParser::hostname_matches_dns_name(
            &long_hostname,
            &long_dns_name
        ));

        // Test for internationalized domain names (IDN)
        // Note: This is a simplified test - real IDN handling would require punycode
        assert!(!CertificateParser::hostname_matches_dns_name(
            "münchen.de",
            "muenchen.de"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "münchen.de",
            "*.de"
        ));

        // Test for IP addresses (should not match)
        assert!(!CertificateParser::hostname_matches_dns_name(
            "192.168.1.1",
            "*.example.com"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "192.168.1.1",
            "example.com"
        ));
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "192.168.1.1"
        ));
    }

    #[test]
    fn test_rfc_6125_compliance() {
        // Test compliance with RFC 6125 rules

        // Rule 1: Wildcard should not match the domain itself
        assert!(!CertificateParser::hostname_matches_dns_name(
            "example.com",
            "*.example.com"
        ));

        // Rule 2: Wildcard should only match one level
        assert!(!CertificateParser::hostname_matches_dns_name(
            "sub.sub.example.com",
            "*.example.com"
        ));

        // Rule 3: Wildcard should not match empty labels
        assert!(!CertificateParser::hostname_matches_dns_name(
            ".example.com",
            "*.example.com"
        ));

        // Rule 4: Exact matches should work
        assert!(CertificateParser::hostname_matches_dns_name(
            "example.com",
            "example.com"
        ));
        assert!(CertificateParser::hostname_matches_dns_name(
            "www.example.com",
            "www.example.com"
        ));

        // Rule 5: Case insensitive matching
        assert!(CertificateParser::hostname_matches_dns_name(
            "Example.Com",
            "example.com"
        ));
        assert!(CertificateParser::hostname_matches_dns_name(
            "example.com",
            "EXAMPLE.COM"
        ));
        assert!(CertificateParser::hostname_matches_dns_name(
            "WWW.EXAMPLE.COM",
            "*.example.com"
        ));
    }
}
