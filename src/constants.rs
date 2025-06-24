//! TLS PQC Constants and References
//! 
//! This module contains all PQC-related constants used in the TLS scanner,
//! along with their IETF draft references and current status.

// ============================================================================
// IETF DRAFT REFERENCES
// ============================================================================

// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
// - Standard TLS 1.3 constants

// draft-ietf-tls-hybrid-design-04: Hybrid key exchange for TLS 1.3
// - Hybrid key exchange group definitions
// - https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design-04

// draft-ietf-tls-pq-sig-00: Post-Quantum Signatures for TLS 1.3
// - PQC signature algorithm definitions
// - https://datatracker.ietf.org/doc/html/draft-ietf-tls-pq-sig-00

// ============================================================================
// EXTENSION IDs
// ============================================================================

/// Standard TLS Extensions (RFC 8446)
pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
pub const EXT_KEY_SHARE: u16 = 0x0033;

/// PQC Extensions (Experimental/Draft)
/// Note: These are hypothetical extensions for future PQC support
pub const EXT_PQC_KEM: u16 = 0xfe33; // Hypothetical PQC KEM extension
pub const EXT_PQC_KEM_GROUP: u16 = 0xfe34; // Hypothetical PQC KEM group extension

// ============================================================================
// NAMED GROUPS (Key Exchange)
// ============================================================================

/// Standard Named Groups (RFC 8446)
pub const NAMED_GROUP_X25519: u16 = 0x001d;
pub const NAMED_GROUP_SECP256R1: u16 = 0x0017;

/// PQC Named Groups (draft-ietf-tls-hybrid-design-04)
/// 
/// Hybrid groups combine classical and post-quantum algorithms:
/// - X25519 provides classical security
/// - PQC algorithms provide post-quantum security
pub const NAMED_GROUP_X25519_KYBER512: u16 = 0xfe30; // X25519Kyber512Draft00 (obsolete)
pub const NAMED_GROUP_X25519_KYBER768: u16 = 0x6399; // X25519Kyber768Draft00 
pub const NAMED_GROUP_X25519_MLKEM768: u16 = 0x11ec; // X25519MLKEM768 (recommended)
pub const NAMED_GROUP_P256_KYBER768: u16 = 0x639a; // P256Kyber768Draft00

/// Pure PQC Groups (draft-ietf-tls-hybrid-design-04)
pub const NAMED_GROUP_KYBER768: u16 = 0x001c; // Kyber768 (pure PQC)
pub const NAMED_GROUP_KYBER1024: u16 = 0xfe31; // Kyber1024 (pure PQC)

// ============================================================================
// SIGNATURE ALGORITHMS
// ============================================================================

/// Standard Signature Algorithms (RFC 8446)
pub const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const SIG_RSA_PSS_SHA256: u16 = 0x0804;

/// PQC Signature Algorithms (draft-ietf-tls-pq-sig-00)
/// 
/// These are based on the NIST PQC standardization process:
/// - Dilithium2: Level 2 security (recommended for most use cases)
/// - Dilithium3: Level 3 security (higher security, larger keys)
/// - Dilithium5: Level 5 security (highest security, largest keys)
/// 
/// Note: These are draft codepoints and may change in final RFC
pub const SIG_DILITHIUM2: u16 = 0x0b01; // Dilithium2 (Level 2)
pub const SIG_DILITHIUM3: u16 = 0x0b02; // Dilithium3 (Level 3)
pub const SIG_DILITHIUM5: u16 = 0x0b03; // Dilithium5 (Level 5)

/// Extended PQC Signature Algorithms (Experimental/Draft)
/// These codepoints are used in various experiments and implementations
pub const SIG_DILITHIUM2_DRAFT: u16 = 0xfea0; // Dilithium2 (draft)
pub const SIG_P256_DILITHIUM2: u16 = 0xfea1; // P-256 + Dilithium2 (Hybrid)
pub const SIG_RSA3072_DILITHIUM2: u16 = 0xfea2; // RSA-3072 + Dilithium2
pub const SIG_DILITHIUM3_DRAFT: u16 = 0xfea3; // Dilithium3 (draft)
pub const SIG_P384_DILITHIUM3: u16 = 0xfea4; // P-384 + Dilithium3 (Hybrid)
pub const SIG_DILITHIUM5_DRAFT: u16 = 0xfea5; // Dilithium5 (draft)
pub const SIG_P521_DILITHIUM5: u16 = 0xfea6; // P-521 + Dilithium5 (Hybrid)
pub const SIG_FALCON512: u16 = 0xfea7; // Falcon-512
pub const SIG_FALCON1024: u16 = 0xfea8; // Falcon-1024
pub const SIG_SPHINCS_PLUS: u16 = 0xfea9; // SPHINCS+

// ============================================================================
// CIPHER SUITES
// ============================================================================

/// Standard TLS 1.3 Cipher Suites (RFC 8446)
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// PQC Hybrid Cipher Suites (draft-ietf-tls-hybrid-design-04)
/// 
/// These combine classical AEAD with hybrid key exchange:
/// - Classical part: AES-GCM or ChaCha20-Poly1305 for data encryption
/// - Hybrid part: X25519 + PQC for key exchange
pub const TLS_HYBRID_X25519_MLKEM768_SHA384: u16 = 0x11ec;
pub const TLS_HYBRID_ECDHE_KYBER768_X25519_SHA384: u16 = 0x6399;

/// Experimental PQC Cipher Suite
pub const TLS_PQC_HYBRID: u16 = 0xfe00; // Generic PQC hybrid placeholder

// ============================================================================
// TLS VERSIONS
// ============================================================================

pub const TLS_VERSION_1_0: u16 = 0x0301;
pub const TLS_VERSION_1_1: u16 = 0x0302;
pub const TLS_VERSION_1_2: u16 = 0x0303;
pub const TLS_VERSION_1_3: u16 = 0x0304;

// ============================================================================
// TLS CONTENT TYPES
// ============================================================================

pub const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const TLS_CONTENT_TYPE_ALERT: u8 = 0x15;
pub const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

// ============================================================================
// TLS ALERT CODES
// ============================================================================

/// TLS Alert Descriptions (RFC 5246, RFC 8446)
pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub const ALERT_DECODE_ERROR: u8 = 50;
pub const ALERT_PROTOCOL_VERSION: u8 = 70;
pub const ALERT_INSUFFICIENT_SECURITY: u8 = 86;
pub const ALERT_INTERNAL_ERROR: u8 = 90;

// ============================================================================
// KEY SIZES (in bytes)
// ============================================================================

/// Key sizes for different algorithms
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
pub const KYBER768_PUBLIC_KEY_SIZE: usize = 1184;
pub const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;
pub const DILITHIUM2_PUBLIC_KEY_SIZE: usize = 1312;
pub const DILITHIUM3_PUBLIC_KEY_SIZE: usize = 1952;
pub const DILITHIUM5_PUBLIC_KEY_SIZE: usize = 2592;

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Check if a named group is PQC-related
pub fn is_pqc_group(group: u16) -> bool {
    matches!(group,
        NAMED_GROUP_X25519_KYBER512 |
        NAMED_GROUP_X25519_KYBER768 |
        NAMED_GROUP_X25519_MLKEM768 |
        NAMED_GROUP_P256_KYBER768 |
        NAMED_GROUP_KYBER768 |
        NAMED_GROUP_KYBER1024
    )
}

/// Check if a signature algorithm is PQC-related
pub fn is_pqc_signature_algorithm(algorithm: u16) -> bool {
    matches!(algorithm,
        SIG_DILITHIUM2 |
        SIG_DILITHIUM3 |
        SIG_DILITHIUM5 |
        SIG_DILITHIUM2_DRAFT |
        SIG_P256_DILITHIUM2 |
        SIG_RSA3072_DILITHIUM2 |
        SIG_DILITHIUM3_DRAFT |
        SIG_P384_DILITHIUM3 |
        SIG_DILITHIUM5_DRAFT |
        SIG_P521_DILITHIUM5 |
        SIG_FALCON512 |
        SIG_FALCON1024 |
        SIG_SPHINCS_PLUS
    )
}

/// Check if a cipher suite is PQC-related
pub fn is_pqc_cipher_suite(suite: u16) -> bool {
    matches!(suite,
        TLS_HYBRID_X25519_MLKEM768_SHA384 |
        TLS_HYBRID_ECDHE_KYBER768_X25519_SHA384 |
        TLS_PQC_HYBRID
    )
}

/// Get human-readable name for a named group
pub fn get_group_name(group: u16) -> String {
    match group {
        NAMED_GROUP_X25519 => "x25519".to_string(),
        NAMED_GROUP_SECP256R1 => "secp256r1".to_string(),
        NAMED_GROUP_X25519_KYBER512 => "X25519+Kyber512Draft00".to_string(),
        NAMED_GROUP_X25519_KYBER768 => "X25519+Kyber768Draft00".to_string(),
        NAMED_GROUP_X25519_MLKEM768 => "X25519+ML-KEM768".to_string(),
        NAMED_GROUP_P256_KYBER768 => "P256+Kyber768Draft00".to_string(),
        NAMED_GROUP_KYBER768 => "Kyber768".to_string(),
        NAMED_GROUP_KYBER1024 => "Kyber1024".to_string(),
        _ => format!("unknown(0x{:04x})", group),
    }
}

/// Get human-readable name for a signature algorithm
pub fn get_signature_algorithm_name(algorithm: u16) -> String {
    match algorithm {
        SIG_RSA_PKCS1_SHA256 => "rsa_pkcs1_sha256".to_string(),
        SIG_ECDSA_SECP256R1_SHA256 => "ecdsa_secp256r1_sha256".to_string(),
        SIG_RSA_PSS_SHA256 => "rsa_pss_rsae_sha256".to_string(),
        SIG_DILITHIUM2 => "dilithium2".to_string(),
        SIG_DILITHIUM3 => "dilithium3".to_string(),
        SIG_DILITHIUM5 => "dilithium5".to_string(),
        SIG_DILITHIUM2_DRAFT => "dilithium2_draft".to_string(),
        SIG_P256_DILITHIUM2 => "p256_dilithium2_hybrid".to_string(),
        SIG_RSA3072_DILITHIUM2 => "rsa3072_dilithium2_hybrid".to_string(),
        SIG_DILITHIUM3_DRAFT => "dilithium3_draft".to_string(),
        SIG_P384_DILITHIUM3 => "p384_dilithium3_hybrid".to_string(),
        SIG_DILITHIUM5_DRAFT => "dilithium5_draft".to_string(),
        SIG_P521_DILITHIUM5 => "p521_dilithium5_hybrid".to_string(),
        SIG_FALCON512 => "falcon512".to_string(),
        SIG_FALCON1024 => "falcon1024".to_string(),
        SIG_SPHINCS_PLUS => "sphincs_plus".to_string(),
        _ => format!("unknown(0x{:04x})", algorithm),
    }
}

/// The official PQC signature OIDs from RFC 8391, RFC 9332, etc.
/// A complete list of all post‑quantum and composite signature algorithm OIDs
/// as specified by NIST FIPS 203/204/205, NIST PQC drafts, OQS, and IETF composite drafts.
pub const PQC_SIGNATURE_OIDS: &[&str] = &[
    // ——— NIST FIPS 204 (ML‑DSA) ———
    "2.16.840.1.101.3.4.3.17", // ML‑DSA‑44
    "2.16.840.1.101.3.4.3.18", // ML‑DSA‑65
    "2.16.840.1.101.3.4.3.19", // ML‑DSA‑87
    // ——— NIST FIPS 205 (SLH‑DSA) ———
    "2.16.840.1.101.3.4.3.20", // SLH‑DSA‑SHA2‑128s
    "2.16.840.1.101.3.4.3.21", // SLH‑DSA‑SHA2‑128f
    "2.16.840.1.101.3.4.3.22", // SLH‑DSA‑SHA2‑192s
    "2.16.840.1.101.3.4.3.23", // SLH‑DSA‑SHA2‑192f
    "2.16.840.1.101.3.4.3.24", // SLH‑DSA‑SHA2‑256s
    "2.16.840.1.101.3.4.3.25", // SLH‑DSA‑SHA2‑256f
    "2.16.840.1.101.3.4.3.26", // SLH‑DSA‑SHAKE‑128s
    "2.16.840.1.101.3.4.3.27", // SLH‑DSA‑SHAKE‑128f
    "2.16.840.1.101.3.4.3.28", // SLH‑DSA‑SHAKE‑192s
    "2.16.840.1.101.3.4.3.29", // SLH‑DSA‑SHAKE‑192f
    "2.16.840.1.101.3.4.3.30", // SLH‑DSA‑SHAKE‑256s
    "2.16.840.1.101.3.4.3.31", // SLH‑DSA‑SHAKE‑256f
    // ——— NIST Pre‑Hash variants ———
    "2.16.840.1.101.3.4.3.32", // HASH‑ML‑DSA‑44 (SHA‑512)
    "2.16.840.1.101.3.4.3.33", // HASH‑ML‑DSA‑65 (SHA‑512)
    "2.16.840.1.101.3.4.3.34", // HASH‑ML‑DSA‑87 (SHA‑512)
    "2.16.840.1.101.3.4.3.35", // HASH‑SLH‑DSA‑SHA2‑128s (SHA‑256)
    "2.16.840.1.101.3.4.3.36", // HASH‑SLH‑DSA‑SHA2‑128f (SHA‑256)
    "2.16.840.1.101.3.4.3.37", // HASH‑SLH‑DSA‑SHA2‑192s (SHA‑512)
    "2.16.840.1.101.3.4.3.38", // HASH‑SLH‑DSA‑SHA2‑192f (SHA‑512)
    "2.16.840.1.101.3.4.3.39", // HASH‑SLH‑DSA‑SHA2‑256s (SHA‑512)
    "2.16.840.1.101.3.4.3.40", // HASH‑SLH‑DSA‑SHA2‑256f (SHA‑512)
    "2.16.840.1.101.3.4.3.41", // HASH‑SLH‑DSA‑SHAKE‑128s
    "2.16.840.1.101.3.4.3.42", // HASH‑SLH‑DSA‑SHAKE‑128f
    "2.16.840.1.101.3.4.3.43", // HASH‑SLH‑DSA‑SHAKE‑192s
    "2.16.840.1.101.3.4.3.44", // HASH‑SLH‑DSA‑SHAKE‑192f
    "2.16.840.1.101.3.4.3.45", // HASH‑SLH‑DSA‑SHAKE‑256s
    "2.16.840.1.101.3.4.3.46", // HASH‑SLH‑DSA‑SHAKE‑256f
    // ——— NIST PQC Round‑3 (OQS) signature OIDs ———
    // Dilithium (ML‑DSA) family
    "1.3.6.1.4.1.2.267.7.4.4", // id‑dilithium2
    "1.3.6.1.4.1.2.267.7.6.5", // id‑dilithium3
    "1.3.6.1.4.1.2.267.7.8.7", // id‑dilithium5
    // AES variants (benchmarking only)
    "1.3.6.1.4.1.2.267.11.4.4", // DilithiumAES2
    "1.3.6.1.4.1.2.267.11.6.5", // DilithiumAES3
    "1.3.6.1.4.1.2.267.11.8.7", // DilithiumAES5
    // Falcon (prototype)
    "1.3.9999",     // Falcon‑512 (experimental)
    "1.3.9999.3.9", // Falcon‑1024 (experimental)
    // SPHINCS+ (OQS Round 3)
    "1.3.9999.6.4.1",  // SPHINCS+-SHA256-128f-robust
    "1.3.9999.6.4.4",  // SPHINCS+-SHA256-128f-simple
    "1.3.9999.6.4.7",  // SPHINCS+-SHA256-128s-robust
    "1.3.9999.6.4.10", // SPHINCS+-SHA256-128s-simple
    "1.3.9999.6.5.1",  // SPHINCS+-SHA256-192f-robust
    "1.3.9999.6.5.3",  // SPHINCS+-SHA256-192f-simple
    "1.3.9999.6.5.5",  // SPHINCS+-SHA256-192s-robust
    "1.3.9999.6.5.7",  // SPHINCS+-SHA256-192s-simple
    "1.3.9999.6.6.1",  // SPHINCS+-SHA256-256f-robust
    "1.3.9999.6.6.3",  // SPHINCS+-SHA256-256f-simple
    "1.3.9999.6.6.5",  // SPHINCS+-SHA256-256s-robust
    "1.3.9999.6.6.7",  // SPHINCS+-SHA256-256s-simple
    // ——— IETF Composite Signatures (draft-ietf-lamps-pq-composite-sigs) ———
    // MLDSA44 composites
    "2.16.840.1.114027.80.8.1.21", // id‑MLDSA44‑RSA2048‑PSS
    "2.16.840.1.114027.80.8.1.22", // id‑MLDSA44‑RSA2048‑PKCS15
    "2.16.840.1.114027.80.8.1.23", // id‑MLDSA44‑Ed25519
    "2.16.840.1.114027.80.8.1.24", // id‑MLDSA44‑ECDSA‑P256
    // MLDSA65 composites
    "2.16.840.1.114027.80.8.1.26", // id‑MLDSA65‑RSA3072‑PSS
    "2.16.840.1.114027.80.8.1.27", // id‑MLDSA65‑RSA3072‑PKCS15
    "2.16.840.1.114027.80.8.1.30", // id‑MLDSA65‑Ed25519
    "2.16.840.1.114027.80.8.1.28", // id‑MLDSA65‑ECDSA‑P384
    "2.16.840.1.114027.80.8.1.29", // id‑MLDSA65‑ECDSA‑brainpoolP256r1
    // MLDSA87 composites
    "2.16.840.1.114027.80.8.1.31", // id‑MLDSA87‑ECDSA‑P384
    "2.16.840.1.114027.80.8.1.32", // id‑MLDSA87‑ECDSA‑brainpoolP384r1
    "2.16.840.1.114027.80.8.1.33", // id‑MLDSA87‑Ed448
    // ——— Explicit Composite Signature OIDs ———
    "2.16.840.1.114027.80.5.1",    // ExplicitCompositeSignature
    "2.16.840.1.114027.80.5.1.1",  // id‑Dilithium3‑RSA‑PKCS15‑SHA256
    "2.16.840.1.114027.80.5.1.2",  // id‑Dilithium3‑ECDSA‑P256‑SHA256
    "2.16.840.1.114027.80.5.1.3",  // id‑Dilithium3‑ECDSA‑brainpoolP256r1‑SHA256
    "2.16.840.1.114027.80.5.1.4",  // id‑Dilithium3‑Ed25519
    "2.16.840.1.114027.80.5.1.5",  // id‑Dilithium5‑ECDSA‑P384‑SHA384
    "2.16.840.1.114027.80.5.1.6",  // id‑Dilithium5‑ECDSA‑brainpoolP384r1‑SHA384
    "2.16.840.1.114027.80.5.1.7",  // id‑Dilithium5‑Ed448
    "2.16.840.1.114027.80.5.1.8",  // id‑Falcon512‑ECDSA‑P256‑SHA256
    "2.16.840.1.114027.80.5.1.9",  // id‑Falcon512‑ECDSA‑brainpoolP256r1‑SHA256
    "2.16.840.1.114027.80.5.1.10", // id‑Falcon512‑Ed25519
];

/// Check if a signature OID is PQC-related
pub fn is_pqc_oid(oid: &str) -> bool {
    PQC_SIGNATURE_OIDS.contains(&oid)
} 