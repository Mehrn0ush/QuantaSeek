//! X.509 algorithm naming. Chain validation is done by rustls/webpki; this
//! module only names what the certificates contain.

use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

/// Classical public-key algorithm OIDs: (oid, name, source).
const CLASSICAL_KEYS: &[(&str, &str, &str)] = &[
    ("1.2.840.113549.1.1.1", "RSA", "RFC 8017"),
    ("1.2.840.113549.1.1.10", "RSA-PSS", "RFC 4055"),
    ("1.2.840.10045.2.1", "ECDSA", "RFC 5480"),
    ("1.3.101.112", "Ed25519", "RFC 8410"),
    ("1.3.101.113", "Ed448", "RFC 8410"),
];

/// Classical signature algorithm OIDs: (oid, name, source).
const CLASSICAL_SIGNATURES: &[(&str, &str, &str)] = &[
    ("1.2.840.113549.1.1.5", "RSA-SHA1", "RFC 8017"),
    ("1.2.840.113549.1.1.10", "RSA-PSS", "RFC 4055"),
    ("1.2.840.113549.1.1.11", "RSA-SHA256", "RFC 8017"),
    ("1.2.840.113549.1.1.12", "RSA-SHA384", "RFC 8017"),
    ("1.2.840.113549.1.1.13", "RSA-SHA512", "RFC 8017"),
    ("1.2.840.10045.4.1", "ECDSA-SHA1", "RFC 3279"),
    ("1.2.840.10045.4.3.2", "ECDSA-SHA256", "RFC 5758"),
    ("1.2.840.10045.4.3.3", "ECDSA-SHA384", "RFC 5758"),
    ("1.2.840.10045.4.3.4", "ECDSA-SHA512", "RFC 5758"),
    ("1.3.101.112", "Ed25519", "RFC 8410"),
    ("1.3.101.113", "Ed448", "RFC 8410"),
];

fn lookup(table: &[(&str, &'static str, &str)], oid: &str) -> Option<&'static str> {
    table.iter().find(|(o, _, _)| *o == oid).map(|(_, n, _)| *n)
}

/// True if the OID is a classical key or signature algorithm QuantaSeek names.
pub fn is_known_classical_oid(oid: &str) -> bool {
    lookup(CLASSICAL_KEYS, oid).is_some() || lookup(CLASSICAL_SIGNATURES, oid).is_some()
}

/// Name for a SubjectPublicKeyInfo algorithm OID.
pub fn public_key_algorithm_name(oid: &str) -> String {
    if let Some(pq) = crate::constants::pqc_oid(oid) {
        return pq.name.to_string();
    }
    lookup(CLASSICAL_KEYS, oid)
        .map(str::to_string)
        .unwrap_or_else(|| format!("OID({})", oid))
}

/// Name for a certificate signatureAlgorithm OID.
pub fn signature_algorithm_name(oid: &str) -> String {
    if let Some(pq) = crate::constants::pqc_oid(oid) {
        return pq.name.to_string();
    }
    lookup(CLASSICAL_SIGNATURES, oid)
        .map(str::to_string)
        .unwrap_or_else(|| format!("OID({})", oid))
}

/// Key size in bits for RSA and the named EC curves; None when not parsed.
pub fn public_key_size_bits(spki: &SubjectPublicKeyInfo) -> Option<u32> {
    match spki.algorithm.algorithm.to_id_string().as_str() {
        "1.3.101.112" => return Some(256),
        "1.3.101.113" => return Some(456),
        "1.2.840.10045.2.1" => {
            let curve = spki.algorithm.parameters.as_ref()?.as_oid().ok()?;
            return match curve.to_id_string().as_str() {
                "1.2.840.10045.3.1.7" => Some(256), // secp256r1, RFC 5480
                "1.3.132.0.34" => Some(384),        // secp384r1, RFC 5480
                "1.3.132.0.35" => Some(521),        // secp521r1, RFC 5480
                _ => None,
            };
        }
        _ => {}
    }
    match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => u32::try_from(rsa.key_size()).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classical_tables_cite_sources_and_do_not_overlap_pq_oids() {
        for (oid, name, source) in CLASSICAL_KEYS.iter().chain(CLASSICAL_SIGNATURES) {
            assert!(!name.is_empty() && !source.is_empty(), "{oid}");
            assert!(crate::constants::pqc_oid(oid).is_none(), "{oid}");
        }
    }

    #[test]
    fn names() {
        assert_eq!(
            signature_algorithm_name("1.2.840.113549.1.1.11"),
            "RSA-SHA256"
        );
        assert_eq!(
            signature_algorithm_name("2.16.840.1.101.3.4.3.18"),
            "id-ml-dsa-65"
        );
        assert_eq!(
            public_key_algorithm_name("2.16.840.1.101.3.4.4.2"),
            "id-alg-ml-kem-768"
        );
        assert_eq!(signature_algorithm_name("1.2.3.4"), "OID(1.2.3.4)");
        assert!(is_known_classical_oid("1.2.840.10045.2.1"));
        assert!(!is_known_classical_oid("2.16.840.1.101.3.4.3.18"));
    }
}
