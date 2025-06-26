use crate::types::CertificateInfo;
use anyhow::{Result, anyhow};
use x509_parser::prelude::*;
use x509_parser::der_parser::asn1_rs::FromDer;
use x509_parser::der_parser::asn1_rs::Oid;

// ASN.1 DER constants
const ASN1_SEQUENCE: u8 = 0x30;
const ASN1_SET: u8 = 0x31;
const ASN1_INTEGER: u8 = 0x02;
const ASN1_BIT_STRING: u8 = 0x03;
const ASN1_OID: u8 = 0x06;
const ASN1_UTF8_STRING: u8 = 0x0c;
const ASN1_PRINTABLE_STRING: u8 = 0x13;
const ASN1_T61_STRING: u8 = 0x14;
const ASN1_IA5_STRING: u8 = 0x16;

// Common OIDs
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_ECDSA_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

// Hypothetical PQC OIDs (these would be real OIDs in practice)
const OID_DILITHIUM3: &[u8] = &[0x2b, 0x65, 0x70, 0x01]; // Draft OID
const OID_DILITHIUM5: &[u8] = &[0x2b, 0x65, 0x70, 0x02]; // Draft OID
const OID_KYBER1024: &[u8] = &[0x2b, 0x65, 0x6f, 0x01]; // Draft OID
const OID_KYBER768: &[u8] = &[0x2b, 0x65, 0x6f, 0x02]; // Draft OID

// X.509 attribute type OIDs
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

pub struct CertificateParser;

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
        let (public_key_algorithm, key_size) = self.extract_public_key_info(&cert.tbs_certificate.subject_pki);
        
        // Extract signature algorithm (this is the algorithm used to sign the certificate)
        let signature_algorithm = self.oid_to_signature_algorithm_name(&cert.signature_algorithm.algorithm);
        
        // Extract validity dates
        let valid_from = cert.tbs_certificate.validity.not_before.to_rfc2822().unwrap_or_else(|_| "Unknown".to_string());
        let valid_to = cert.tbs_certificate.validity.not_after.to_rfc2822().unwrap_or_else(|_| "Unknown".to_string());
        
        // Extract SAN (Subject Alternative Name) if available
        let san = self.extract_san(&cert.tbs_certificate);
        
        // Calculate certificate length estimate (DER format)
        let certificate_length_estimate = Some(data.len() as u32);
        
        let certificate_info = CertificateInfo {
            subject,
            issuer,
            public_key_algorithm,
            signature_algorithm,
            key_size,
            valid_from,
            valid_to,
            san,
            certificate_length_estimate,
            algorithm_consistency: false, // Will be set below
        };
        
        // Validate algorithm consistency
        let algorithm_consistency = CertificateParser::validate_algorithm_consistency(&certificate_info.public_key_algorithm, &certificate_info.signature_algorithm);
        
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
                        if estimated_bits >= 1024 && estimated_bits <= 8192 {
                            Some(estimated_bits as u32)
                        } else {
                            // Fallback to common RSA key sizes
                            Some(2048)
                        }
                    } else {
                        Some(2048) // Default fallback
                    }
                },
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
            },
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
            return Err(anyhow!("Invalid RSA key data: too short ({} bytes)", key_data.len()));
        }
        
        // Skip the first byte (unused bits indicator for BIT STRING)
        let data = if key_data[0] == 0 { &key_data[1..] } else { key_data };
        
        // Parse SEQUENCE
        if data.is_empty() || data[0] != 0x30 {
            return Err(anyhow!("Expected SEQUENCE for RSA public key, got 0x{:02x}", data[0]));
        }
        
        // Parse modulus (first INTEGER in the sequence)
        let mut pos = 2; // Skip tag and length
        if pos >= data.len() {
            return Err(anyhow!("Data too short after SEQUENCE"));
        }
        
        if data[pos] != 0x02 {
            return Err(anyhow!("Expected INTEGER for RSA modulus, got 0x{:02x}", data[pos]));
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
        if actual_bits < 512 || actual_bits > 8192 {
            return Err(anyhow!("Unreasonable RSA key size: {} bits", actual_bits));
        }
        
        Ok(actual_bits as u32)
    }

    fn extract_san(&self, tbs_certificate: &TbsCertificate) -> Option<String> {
        // Look for Subject Alternative Name extension
        for extension in tbs_certificate.extensions() {
            if extension.oid.to_string() == "2.5.29.17" { // Subject Alternative Name OID
                // Try to parse the SAN extension value
                if let Ok(san_names) = self.parse_san_extension(&extension.value) {
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
                if word.contains('.') && word.len() > 3 && !word.starts_with('.') && !word.ends_with('.') {
                    // Basic DNS name validation
                    if word.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
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

    pub fn validate_algorithm_consistency(public_key_algorithm: &str, signature_algorithm: &str) -> bool {
        match (public_key_algorithm, signature_algorithm) {
            // Valid combinations
            ("RSA", sig) if sig.contains("RSA") => true,
            ("ECDSA", sig) if sig.contains("ECDSA") => true,
            ("Ed25519", "Ed25519") => true,
            ("Ed448", "Ed448") => true,
            // PQC signature algorithms can be used with any public key
            (_, sig) if sig.contains("Dilithium") || sig.contains("Falcon") || sig.contains("SPHINCS") => true,
            // Invalid combinations
            _ => false,
        }
    }
} 