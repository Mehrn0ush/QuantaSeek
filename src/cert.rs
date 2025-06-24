use crate::types::CertificateInfo;
use anyhow::{Result, anyhow};

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
        let mut parser = DerParser::new(data);
        self.parse_x509_certificate(&mut parser)
    }

    fn parse_x509_certificate(&self, parser: &mut DerParser) -> Result<CertificateInfo> {
        // Parse the outer SEQUENCE (Certificate)
        let (tag, _length) = parser.read_tag_length()?;
        if tag != ASN1_SEQUENCE {
            return Err(anyhow!("Expected SEQUENCE for Certificate"));
        }

        // Parse tbsCertificate (SEQUENCE)
        let (tag, tbs_length) = parser.read_tag_length()?;
        if tag != ASN1_SEQUENCE {
            return Err(anyhow!("Expected SEQUENCE for tbsCertificate"));
        }

        let tbs_start = parser.position();
        let tbs_end = tbs_start + tbs_length;

        let mut cert_info = CertificateInfo {
            subject: "Unknown".to_string(),
            public_key_algorithm: "Unknown".to_string(),
            signature_algorithm: "Unknown".to_string(),
            key_size: None,
        };

        // Parse tbsCertificate contents
        self.parse_tbs_certificate(parser, &mut cert_info, tbs_end)?;

        // Parse signatureAlgorithm (after tbsCertificate)
        if parser.position() < parser.data().len() {
            if let Ok(sig_alg) = self.parse_algorithm_identifier(parser) {
                cert_info.signature_algorithm = sig_alg;
            }
        }

        Ok(cert_info)
    }

    fn parse_tbs_certificate(&self, parser: &mut DerParser, cert_info: &mut CertificateInfo, end_pos: usize) -> Result<()> {
        // Skip version (optional, context-specific tag [0])
        if parser.position() < end_pos {
            let peek_tag = parser.peek_tag()?;
            if peek_tag == 0xa0 { // Context-specific [0]
                parser.skip_element()?;
            }
        }

        // Skip serialNumber
        if parser.position() < end_pos {
            parser.skip_element()?;
        }

        // Parse signature algorithm (within tbsCertificate)
        if parser.position() < end_pos {
            if let Ok(sig_alg) = self.parse_algorithm_identifier(parser) {
                cert_info.signature_algorithm = sig_alg;
            }
        }

        // Skip issuer
        if parser.position() < end_pos {
            parser.skip_element()?;
        }

        // Skip validity
        if parser.position() < end_pos {
            parser.skip_element()?;
        }

        // Parse subject
        if parser.position() < end_pos {
            if let Ok(subject) = self.parse_name(parser) {
                cert_info.subject = subject;
            }
        }

        // Parse subjectPublicKeyInfo
        if parser.position() < end_pos {
            self.parse_subject_public_key_info(parser, cert_info)?;
        }

        Ok(())
    }

    fn parse_algorithm_identifier(&self, parser: &mut DerParser) -> Result<String> {
        let (tag, _length) = parser.read_tag_length()?;
        if tag != ASN1_SEQUENCE {
            return Err(anyhow!("Expected SEQUENCE for AlgorithmIdentifier"));
        }

        // Parse algorithm OID
        let (tag, length) = parser.read_tag_length()?;
        if tag != ASN1_OID {
            return Err(anyhow!("Expected OID for algorithm"));
        }

        let oid_data = parser.read_bytes(length)?;
        let algorithm = self.oid_to_algorithm_name(oid_data);

        // Skip parameters (if present)
        if parser.has_more_in_current_element() {
            parser.skip_element()?;
        }

        Ok(algorithm)
    }

    fn parse_subject_public_key_info(&self, parser: &mut DerParser, cert_info: &mut CertificateInfo) -> Result<()> {
        let (tag, _length) = parser.read_tag_length()?;
        if tag != ASN1_SEQUENCE {
            return Err(anyhow!("Expected SEQUENCE for SubjectPublicKeyInfo"));
        }

        // Parse algorithm
        if let Ok(pub_key_alg) = self.parse_algorithm_identifier(parser) {
            cert_info.public_key_algorithm = pub_key_alg;
        }

        // Parse subjectPublicKey (BIT STRING)
        let (tag, length) = parser.read_tag_length()?;
        if tag == ASN1_BIT_STRING {
            let key_data = parser.read_bytes(length)?;
            if !key_data.is_empty() {
                // Skip the first byte (unused bits indicator)
                let actual_key = &key_data[1..];
                cert_info.key_size = self.estimate_key_size(&cert_info.public_key_algorithm, actual_key);
            }
        }

        Ok(())
    }

    fn parse_name(&self, parser: &mut DerParser) -> Result<String> {
        let (tag, _length) = parser.read_tag_length()?;
        if tag != ASN1_SEQUENCE {
            return Err(anyhow!("Expected SEQUENCE for Name"));
        }

        let mut cn = String::new();

        // Parse RDNSequence (sequence of relative distinguished names)
        while parser.has_more_in_current_element() {
            if let Ok(rdn) = self.parse_relative_distinguished_name(parser) {
                if !rdn.is_empty() && cn.is_empty() {
                    cn = rdn; // Take the first CN we find
                }
            }
        }

        Ok(if cn.is_empty() { "Unknown".to_string() } else { cn })
    }

    fn parse_relative_distinguished_name(&self, parser: &mut DerParser) -> Result<String> {
        let (tag, _length) = parser.read_tag_length()?;
        if tag != ASN1_SET {
            return Err(anyhow!("Expected SET for RelativeDistinguishedName"));
        }

        // Parse AttributeTypeAndValue
        while parser.has_more_in_current_element() {
            let (tag, _length) = parser.read_tag_length()?;
            if tag == ASN1_SEQUENCE {
                // Parse attribute type (OID)
                let (tag, length) = parser.read_tag_length()?;
                if tag == ASN1_OID {
                    let oid_data = parser.read_bytes(length)?;
                    
                    // Check if this is a CN attribute
                    if oid_data == OID_COMMON_NAME {
                        // Parse attribute value
                        let (tag, length) = parser.read_tag_length()?;
                        if matches!(tag, ASN1_UTF8_STRING | ASN1_PRINTABLE_STRING | ASN1_T61_STRING | ASN1_IA5_STRING) {
                            let value_data = parser.read_bytes(length)?;
                            if let Ok(cn) = String::from_utf8(value_data.to_vec()) {
                                return Ok(cn);
                            }
                        }
                    } else {
                        // Skip the attribute value
                        parser.skip_element()?;
                    }
                }
            }
        }

        Ok(String::new())
    }

    fn oid_to_algorithm_name(&self, oid: &[u8]) -> String {
        match oid {
            OID_RSA_ENCRYPTION => "rsa".to_string(),
            OID_ECDSA_PUBLIC_KEY => "ecdsa".to_string(),
            OID_SHA256_WITH_RSA => "sha256WithRSAEncryption".to_string(),
            OID_ECDSA_WITH_SHA256 => "ecdsa-with-SHA256".to_string(),
            OID_DILITHIUM3 => "dilithium3".to_string(),
            OID_DILITHIUM5 => "dilithium5".to_string(),
            OID_KYBER1024 => "kyber1024".to_string(),
            OID_KYBER768 => "kyber768".to_string(),
            _ => format!("unknown({})", hex::encode(oid)),
        }
    }

    fn estimate_key_size(&self, algorithm: &str, key_data: &[u8]) -> Option<u32> {
        match algorithm {
            "rsa" => {
                // For RSA, try to parse the public key and extract modulus size
                if let Ok(key_size) = self.extract_rsa_key_size(key_data) {
                    Some(key_size)
                } else {
                    // Default estimates based on common key sizes
                    match key_data.len() {
                        270..=290 => Some(2048),
                        390..=410 => Some(3072),
                        520..=540 => Some(4096),
                        _ => Some(2048), // Default assumption
                    }
                }
            }
            "ecdsa" => {
                // Common ECDSA key sizes
                match key_data.len() {
                    65 => Some(256), // P-256
                    97 => Some(384), // P-384
                    133 => Some(521), // P-521
                    _ => Some(256), // Default assumption
                }
            }
            "dilithium3" => Some(1952), // Dilithium3 public key size
            "dilithium5" => Some(2592), // Dilithium5 public key size
            "kyber1024" => Some(1568), // Kyber1024 public key size
            "kyber768" => Some(1184), // Kyber768 public key size
            _ => None,
        }
    }

    fn extract_rsa_key_size(&self, key_data: &[u8]) -> Result<u32> {
        let mut parser = DerParser::new(key_data);
        
        // Parse RSA public key structure: SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let (tag, _length) = parser.read_tag_length()?;
        if tag != ASN1_SEQUENCE {
            return Err(anyhow!("Expected SEQUENCE for RSA public key"));
        }

        // Parse modulus
        let (tag, length) = parser.read_tag_length()?;
        if tag == ASN1_INTEGER {
            let modulus_data = parser.read_bytes(length)?;
            // Skip leading zero byte if present
            let modulus_bits = if !modulus_data.is_empty() && modulus_data[0] == 0 {
                (modulus_data.len() - 1) * 8
            } else {
                modulus_data.len() * 8
            };
            return Ok(modulus_bits as u32);
        }

        Err(anyhow!("Could not extract RSA key size"))
    }
}

struct DerParser<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> DerParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn data(&self) -> &[u8] {
        self.data
    }

    fn position(&self) -> usize {
        self.position
    }

    fn peek_tag(&self) -> Result<u8> {
        if self.position >= self.data.len() {
            return Err(anyhow!("Unexpected end of data"));
        }
        Ok(self.data[self.position])
    }

    fn read_tag_length(&mut self) -> Result<(u8, usize)> {
        if self.position >= self.data.len() {
            return Err(anyhow!("Unexpected end of data"));
        }

        let tag = self.data[self.position];
        self.position += 1;

        let length = self.read_length()?;
        Ok((tag, length))
    }

    fn read_length(&mut self) -> Result<usize> {
        if self.position >= self.data.len() {
            return Err(anyhow!("Unexpected end of data"));
        }

        let first_byte = self.data[self.position];
        self.position += 1;

        if first_byte & 0x80 == 0 {
            // Short form
            Ok(first_byte as usize)
        } else {
            // Long form
            let length_of_length = (first_byte & 0x7f) as usize;
            if length_of_length == 0 {
                return Err(anyhow!("Indefinite length not supported"));
            }
            if length_of_length > 4 {
                return Err(anyhow!("Length too long"));
            }
            if self.position + length_of_length > self.data.len() {
                return Err(anyhow!("Insufficient data for length"));
            }

            let mut length = 0usize;
            for _ in 0..length_of_length {
                length = (length << 8) | (self.data[self.position] as usize);
                self.position += 1;
            }
            Ok(length)
        }
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        if self.position + length > self.data.len() {
            return Err(anyhow!("Insufficient data"));
        }

        let start = self.position;
        self.position += length;
        Ok(&self.data[start..self.position])
    }

    fn skip_element(&mut self) -> Result<()> {
        let (_tag, length) = self.read_tag_length()?;
        if self.position + length > self.data.len() {
            return Err(anyhow!("Insufficient data to skip"));
        }
        self.position += length;
        Ok(())
    }

    fn has_more_in_current_element(&self) -> bool {
        self.position < self.data.len()
    }
} 