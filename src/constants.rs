//! TLS and X.509 codepoint registry.
//!
//! Every entry cites its source. Values were checked against the primary
//! registries and RFC texts on 2026-11-13:
//!
//! - IANA TLS Supported Groups:
//!   <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8>
//! - IANA TLS SignatureScheme:
//!   <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme>
//! - IANA TLS ExtensionType Values:
//!   <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml>
//! - NIST CSOR algorithm registrations (sigAlgs 2.16.840.1.101.3.4.3, kems 2.16.840.1.101.3.4.4):
//!   <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>
//! - RFC 10024 (ECDHE-MLKEM hybrids for TLS 1.3), RFC 9881 (ML-DSA in X.509),
//!   RFC 9909 (SLH-DSA in X.509), RFC 9935 (ML-KEM in X.509),
//!   RFC 10073 (Composite ML-DSA in X.509).
//!
//! Do not add a codepoint or OID here without a citation. Draft-only
//! assignments are marked [`Status::Draft`] and must be re-checked when the
//! draft is published or expires.

// ============================================================================
// EXTENSION IDs (IANA TLS ExtensionType Values)
// ============================================================================

pub const EXT_SERVER_NAME: u16 = 0x0000; // RFC 6066
pub const EXT_STATUS_REQUEST: u16 = 0x0005; // RFC 6066
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a; // RFC 8422, RFC 7919
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d; // RFC 8446
pub const EXT_ALPN: u16 = 0x0010; // RFC 7301
pub const EXT_PRE_SHARED_KEY: u16 = 0x0029; // RFC 8446
pub const EXT_EARLY_DATA: u16 = 0x002a; // RFC 8446
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b; // RFC 8446
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d; // RFC 8446
pub const EXT_KEY_SHARE: u16 = 0x0033; // RFC 8446

/// Name of a TLS extension codepoint, per the IANA ExtensionType registry.
pub fn extension_name(ext: u16) -> Option<&'static str> {
    Some(match ext {
        0 => "server_name",
        1 => "max_fragment_length",
        2 => "client_certificate_url",
        3 => "trusted_ca_keys",
        4 => "truncated_hmac",
        5 => "status_request",
        6 => "user_mapping",
        7 => "client_authz",
        8 => "server_authz",
        9 => "cert_type",
        10 => "supported_groups",
        11 => "ec_point_formats",
        12 => "srp",
        13 => "signature_algorithms",
        14 => "use_srtp",
        15 => "heartbeat",
        16 => "application_layer_protocol_negotiation",
        17 => "status_request_v2",
        18 => "signed_certificate_timestamp",
        19 => "client_certificate_type",
        20 => "server_certificate_type",
        21 => "padding",
        22 => "encrypt_then_mac",
        23 => "extended_main_secret",
        24 => "token_binding",
        25 => "cached_info",
        26 => "tls_lts",
        27 => "compress_certificate",
        28 => "record_size_limit",
        29 => "pwd_protect",
        30 => "pwd_clear",
        31 => "password_salt",
        32 => "ticket_pinning",
        33 => "tls_cert_with_extern_psk",
        34 => "delegated_credential",
        35 => "session_ticket",
        36 => "TLMSP",
        37 => "TLMSP_proxying",
        38 => "TLMSP_delegate",
        39 => "supported_ekt_ciphers",
        41 => "pre_shared_key",
        42 => "early_data",
        43 => "supported_versions",
        44 => "cookie",
        45 => "psk_key_exchange_modes",
        47 => "certificate_authorities",
        48 => "oid_filters",
        49 => "post_handshake_auth",
        50 => "signature_algorithms_cert",
        51 => "key_share",
        52 => "transparency_info",
        53 => "connection_id (deprecated)",
        54 => "connection_id",
        55 => "external_id_hash",
        56 => "external_session_id",
        57 => "quic_transport_parameters",
        65037 => "encrypted_client_hello",
        65281 => "renegotiation_info",
        _ => return None,
    })
}

// ============================================================================
// NAMED GROUPS (IANA TLS Supported Groups)
// ============================================================================

/// Standardisation status of a codepoint or OID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Published in an RFC or FIPS.
    Standard,
    /// Assigned by IANA from an Internet-Draft that is not yet an RFC.
    Draft,
    /// Pre-standard codepoint that the registry marks obsolete.
    Obsolete,
}

/// Cryptographic family of a key-exchange group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    /// Classical (EC)DH only. Not quantum-resistant.
    Classical,
    /// Classical ECDH combined with a post-quantum KEM.
    Hybrid,
    /// Post-quantum KEM only.
    PurePq,
}

#[derive(Debug, Clone, Copy)]
pub struct NamedGroup {
    pub code: u16,
    /// IANA registry name.
    pub name: &'static str,
    pub kind: GroupKind,
    /// The post-quantum component, if any (e.g. "ML-KEM-768").
    pub pq_kem: Option<&'static str>,
    pub status: Status,
    /// Document the IANA entry references.
    pub reference: &'static str,
}

const fn group(
    code: u16,
    name: &'static str,
    kind: GroupKind,
    pq_kem: Option<&'static str>,
    status: Status,
    reference: &'static str,
) -> NamedGroup {
    NamedGroup {
        code,
        name,
        kind,
        pq_kem,
        status,
        reference,
    }
}

use GroupKind::{Classical, Hybrid, PurePq};

/// Named groups QuantaSeek can name. Source: IANA TLS Supported Groups,
/// retrieved 2026-11-13. Values not listed are reported as `unknown(0x....)`.
pub const NAMED_GROUPS: &[NamedGroup] = &[
    // Classical groups
    group(
        0x0017,
        "secp256r1",
        Classical,
        None,
        Status::Standard,
        "RFC 8422",
    ),
    group(
        0x0018,
        "secp384r1",
        Classical,
        None,
        Status::Standard,
        "RFC 8422",
    ),
    group(
        0x0019,
        "secp521r1",
        Classical,
        None,
        Status::Standard,
        "RFC 8422",
    ),
    group(
        0x001d,
        "x25519",
        Classical,
        None,
        Status::Standard,
        "RFC 8446, RFC 7748",
    ),
    group(
        0x001e,
        "x448",
        Classical,
        None,
        Status::Standard,
        "RFC 8446, RFC 7748",
    ),
    group(
        0x0100,
        "ffdhe2048",
        Classical,
        None,
        Status::Standard,
        "RFC 7919",
    ),
    group(
        0x0101,
        "ffdhe3072",
        Classical,
        None,
        Status::Standard,
        "RFC 7919",
    ),
    group(
        0x0102,
        "ffdhe4096",
        Classical,
        None,
        Status::Standard,
        "RFC 7919",
    ),
    group(
        0x0103,
        "ffdhe6144",
        Classical,
        None,
        Status::Standard,
        "RFC 7919",
    ),
    group(
        0x0104,
        "ffdhe8192",
        Classical,
        None,
        Status::Standard,
        "RFC 7919",
    ),
    // Pure ML-KEM (FIPS 203). IANA: 512-514, draft-ietf-tls-mlkem.
    group(
        512,
        "MLKEM512",
        PurePq,
        Some("ML-KEM-512"),
        Status::Draft,
        "draft-ietf-tls-mlkem",
    ),
    group(
        513,
        "MLKEM768",
        PurePq,
        Some("ML-KEM-768"),
        Status::Draft,
        "draft-ietf-tls-mlkem",
    ),
    group(
        514,
        "MLKEM1024",
        PurePq,
        Some("ML-KEM-1024"),
        Status::Draft,
        "draft-ietf-tls-mlkem",
    ),
    // ECDHE + ML-KEM hybrids
    group(
        4585,
        "SecP256r1MLKEM512",
        Hybrid,
        Some("ML-KEM-512"),
        Status::Draft,
        "draft-rosomakho-tls-ecdhe-mlkem512",
    ),
    group(
        4586,
        "MLKEM512X25519",
        Hybrid,
        Some("ML-KEM-512"),
        Status::Draft,
        "draft-rosomakho-tls-ecdhe-mlkem512",
    ),
    group(
        4587,
        "SecP256r1MLKEM768",
        Hybrid,
        Some("ML-KEM-768"),
        Status::Standard,
        "RFC 10024",
    ), // 0x11EB
    group(
        4588,
        "X25519MLKEM768",
        Hybrid,
        Some("ML-KEM-768"),
        Status::Standard,
        "RFC 10024",
    ), // 0x11EC
    group(
        4589,
        "SecP384r1MLKEM1024",
        Hybrid,
        Some("ML-KEM-1024"),
        Status::Standard,
        "RFC 10024",
    ), // 0x11ED
    group(
        4590,
        "curveSM2MLKEM768",
        Hybrid,
        Some("ML-KEM-768"),
        Status::Draft,
        "draft-yang-tls-hybrid-sm2-mlkem",
    ),
    group(
        4591,
        "MLKEM1024X448",
        Hybrid,
        Some("ML-KEM-1024"),
        Status::Draft,
        "draft-preussmattsson-tls-mlkem1024-x448",
    ),
    // Pre-standard Kyber hybrids, obsoleted by RFC 10024 (IANA Recommended = D).
    group(
        25497,
        "X25519Kyber768Draft00",
        Hybrid,
        Some("Kyber768 (pre-FIPS 203)"),
        Status::Obsolete,
        "draft-tls-westerbaan-xyber768d00; obsoleted by RFC 10024",
    ), // 0x6399
    group(
        25498,
        "SecP256r1Kyber768Draft00",
        Hybrid,
        Some("Kyber768 (pre-FIPS 203)"),
        Status::Obsolete,
        "draft-kwiatkowski-tls-ecdhe-kyber; obsoleted by RFC 10024",
    ), // 0x639A
];

/// Commonly used group constants.
pub const NAMED_GROUP_X25519: u16 = 0x001d;
pub const NAMED_GROUP_SECP256R1: u16 = 0x0017;
pub const NAMED_GROUP_X25519_MLKEM768: u16 = 4588;
pub const NAMED_GROUP_SECP256R1_MLKEM768: u16 = 4587;
pub const NAMED_GROUP_SECP384R1_MLKEM1024: u16 = 4589;

/// Look up a named group by codepoint.
pub fn named_group(code: u16) -> Option<&'static NamedGroup> {
    NAMED_GROUPS.iter().find(|g| g.code == code)
}

/// Look up a named group by name (case-insensitive, ignoring '-' and '_').
pub fn named_group_by_name(name: &str) -> Option<&'static NamedGroup> {
    let norm = |s: &str| {
        s.chars()
            .filter(|c| *c != '-' && *c != '_')
            .collect::<String>()
            .to_ascii_lowercase()
    };
    let wanted = norm(name);
    NAMED_GROUPS.iter().find(|g| norm(g.name) == wanted)
}

/// True if the group includes a post-quantum KEM (hybrid or pure).
pub fn is_pqc_group(code: u16) -> bool {
    named_group(code).is_some_and(|g| g.kind != GroupKind::Classical)
}

/// Registry name for a named group, or `unknown(0x....)`.
pub fn get_group_name(code: u16) -> String {
    named_group(code)
        .map(|g| g.name.to_string())
        .unwrap_or_else(|| format!("unknown(0x{:04x})", code))
}

// ============================================================================
// SIGNATURE SCHEMES (IANA TLS SignatureScheme)
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct SignatureSchemeInfo {
    pub code: u16,
    /// IANA registry name.
    pub name: &'static str,
    pub post_quantum: bool,
    pub status: Status,
    pub reference: &'static str,
}

const fn sig(
    code: u16,
    name: &'static str,
    post_quantum: bool,
    status: Status,
    reference: &'static str,
) -> SignatureSchemeInfo {
    SignatureSchemeInfo {
        code,
        name,
        post_quantum,
        status,
        reference,
    }
}

/// Source: IANA TLS SignatureScheme, retrieved 2026-11-13.
pub const SIGNATURE_SCHEMES: &[SignatureSchemeInfo] = &[
    sig(
        0x0201,
        "rsa_pkcs1_sha1",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(0x0203, "ecdsa_sha1", false, Status::Standard, "RFC 8446"),
    sig(
        0x0401,
        "rsa_pkcs1_sha256",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x0403,
        "ecdsa_secp256r1_sha256",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x0501,
        "rsa_pkcs1_sha384",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x0503,
        "ecdsa_secp384r1_sha384",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x0601,
        "rsa_pkcs1_sha512",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x0603,
        "ecdsa_secp521r1_sha512",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x0804,
        "rsa_pss_rsae_sha256",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x0805,
        "rsa_pss_rsae_sha384",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x0806,
        "rsa_pss_rsae_sha512",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(0x0807, "ed25519", false, Status::Standard, "RFC 8446"),
    sig(0x0808, "ed448", false, Status::Standard, "RFC 8446"),
    sig(
        0x0809,
        "rsa_pss_pss_sha256",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x080a,
        "rsa_pss_pss_sha384",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x080b,
        "rsa_pss_pss_sha512",
        false,
        Status::Standard,
        "RFC 8446",
    ),
    sig(
        0x081a,
        "ecdsa_brainpoolP256r1tls13_sha256",
        false,
        Status::Standard,
        "RFC 8734",
    ),
    sig(
        0x081b,
        "ecdsa_brainpoolP384r1tls13_sha384",
        false,
        Status::Standard,
        "RFC 8734",
    ),
    sig(
        0x081c,
        "ecdsa_brainpoolP512r1tls13_sha512",
        false,
        Status::Standard,
        "RFC 8734",
    ),
    // ML-DSA (FIPS 204). draft-ietf-tls-mldsa (IESG-approved, not yet an RFC as of 2026-11-13).
    sig(
        0x0904,
        "mldsa44",
        true,
        Status::Draft,
        "draft-ietf-tls-mldsa",
    ),
    sig(
        0x0905,
        "mldsa65",
        true,
        Status::Draft,
        "draft-ietf-tls-mldsa",
    ),
    sig(
        0x0906,
        "mldsa87",
        true,
        Status::Draft,
        "draft-ietf-tls-mldsa",
    ),
    // SLH-DSA (FIPS 205). draft-reddy-tls-slhdsa.
    sig(
        0x0911,
        "slhdsa_sha2_128s",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x0912,
        "slhdsa_sha2_128f",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x0913,
        "slhdsa_sha2_192s",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x0914,
        "slhdsa_sha2_192f",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x0915,
        "slhdsa_sha2_256s",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x0916,
        "slhdsa_sha2_256f",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x0917,
        "slhdsa_shake_128s",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x0918,
        "slhdsa_shake_128f",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x0919,
        "slhdsa_shake_192s",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x091a,
        "slhdsa_shake_192f",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x091b,
        "slhdsa_shake_256s",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
    sig(
        0x091c,
        "slhdsa_shake_256f",
        true,
        Status::Draft,
        "draft-reddy-tls-slhdsa",
    ),
];

/// Look up a signature scheme by codepoint.
pub fn signature_scheme(code: u16) -> Option<&'static SignatureSchemeInfo> {
    SIGNATURE_SCHEMES.iter().find(|s| s.code == code)
}

/// True if the TLS signature scheme is a post-quantum scheme.
pub fn is_pqc_signature_algorithm(code: u16) -> bool {
    signature_scheme(code).is_some_and(|s| s.post_quantum)
}

/// Registry name for a signature scheme, or `unknown(0x....)`.
pub fn get_signature_algorithm_name(code: u16) -> String {
    signature_scheme(code)
        .map(|s| s.name.to_string())
        .unwrap_or_else(|| format!("unknown(0x{:04x})", code))
}

/// True if a signature scheme *name* (as produced by [`get_signature_algorithm_name`])
/// is a post-quantum scheme.
pub fn is_pqc_signature_scheme_name(name: &str) -> bool {
    SIGNATURE_SCHEMES
        .iter()
        .any(|s| s.post_quantum && s.name.eq_ignore_ascii_case(name))
}

// ============================================================================
// TLS 1.3 CIPHER SUITES (RFC 8446)
// ============================================================================
// Cipher suites carry no PQC information in TLS 1.3; PQC is negotiated via
// the supported_groups/key_share extensions.

pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// ============================================================================
// TLS VERSIONS / CONTENT TYPES / ALERTS (RFC 8446, RFC 5246)
// ============================================================================

pub const TLS_VERSION_1_0: u16 = 0x0301;
pub const TLS_VERSION_1_1: u16 = 0x0302;
pub const TLS_VERSION_1_2: u16 = 0x0303;
pub const TLS_VERSION_1_3: u16 = 0x0304;

pub const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const TLS_CONTENT_TYPE_ALERT: u8 = 0x15;
pub const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub const ALERT_DECODE_ERROR: u8 = 50;
pub const ALERT_PROTOCOL_VERSION: u8 = 70;
pub const ALERT_INSUFFICIENT_SECURITY: u8 = 86;
pub const ALERT_INTERNAL_ERROR: u8 = 90;

// ============================================================================
// KEY AND CIPHERTEXT SIZES (bytes)
// ============================================================================

pub const X25519_PUBLIC_KEY_SIZE: usize = 32; // RFC 7748
pub const MLKEM768_ENCAPSULATION_KEY_SIZE: usize = 1184; // FIPS 203, Table 3
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088; // FIPS 203, Table 3
pub const MLKEM1024_ENCAPSULATION_KEY_SIZE: usize = 1568; // FIPS 203, Table 3
pub const MLKEM1024_CIPHERTEXT_SIZE: usize = 1568; // FIPS 203, Table 3
pub const MLDSA44_PUBLIC_KEY_SIZE: usize = 1312; // FIPS 204, Table 2
pub const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952; // FIPS 204, Table 2
pub const MLDSA87_PUBLIC_KEY_SIZE: usize = 2592; // FIPS 204, Table 2

// ============================================================================
// X.509 ALGORITHM OIDs
// ============================================================================

/// What a post-quantum OID identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidKind {
    /// Pure ML-DSA signature / public key (RFC 9881).
    MlDsa,
    /// Pre-hash ML-DSA. RFC 9881 §8.3: MUST NOT appear in X.509 certificates.
    HashMlDsa,
    /// Pure SLH-DSA signature / public key (RFC 9909).
    SlhDsa,
    /// Pre-hash SLH-DSA (RFC 9909).
    HashSlhDsa,
    /// ML-KEM public key (RFC 9935). Never a signature algorithm.
    MlKem,
    /// Composite ML-DSA + traditional signature (RFC 10073).
    CompositeMlDsa,
}

#[derive(Debug, Clone, Copy)]
pub struct PqcOid {
    pub oid: &'static str,
    /// Name as written in the defining document's ASN.1 module.
    pub name: &'static str,
    pub kind: OidKind,
    pub reference: &'static str,
}

const fn oid(
    oid: &'static str,
    name: &'static str,
    kind: OidKind,
    reference: &'static str,
) -> PqcOid {
    PqcOid {
        oid,
        name,
        kind,
        reference,
    }
}

use OidKind::{CompositeMlDsa, HashMlDsa, HashSlhDsa, MlDsa, MlKem, SlhDsa};

/// Post-quantum algorithm OIDs. Sources: NIST CSOR registrations and the
/// RFCs cited per entry. Pre-standard OQS/draft OIDs (Dilithium, Falcon,
/// SPHINCS+, the old 2.16.840.1.114027.80.x composite arc) are deliberately
/// not included: they were never stable assignments.
pub const PQC_OIDS: &[PqcOid] = &[
    // FIPS 204 ML-DSA (RFC 9881)
    oid("2.16.840.1.101.3.4.3.17", "id-ml-dsa-44", MlDsa, "RFC 9881"),
    oid("2.16.840.1.101.3.4.3.18", "id-ml-dsa-65", MlDsa, "RFC 9881"),
    oid("2.16.840.1.101.3.4.3.19", "id-ml-dsa-87", MlDsa, "RFC 9881"),
    // FIPS 205 SLH-DSA (RFC 9909)
    oid(
        "2.16.840.1.101.3.4.3.20",
        "id-slh-dsa-sha2-128s",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.21",
        "id-slh-dsa-sha2-128f",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.22",
        "id-slh-dsa-sha2-192s",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.23",
        "id-slh-dsa-sha2-192f",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.24",
        "id-slh-dsa-sha2-256s",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.25",
        "id-slh-dsa-sha2-256f",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.26",
        "id-slh-dsa-shake-128s",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.27",
        "id-slh-dsa-shake-128f",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.28",
        "id-slh-dsa-shake-192s",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.29",
        "id-slh-dsa-shake-192f",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.30",
        "id-slh-dsa-shake-256s",
        SlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.31",
        "id-slh-dsa-shake-256f",
        SlhDsa,
        "RFC 9909",
    ),
    // HashML-DSA (NIST CSOR). RFC 9881 §8.3 forbids these in certificates.
    oid(
        "2.16.840.1.101.3.4.3.32",
        "id-hash-ml-dsa-44-with-sha512",
        HashMlDsa,
        "NIST CSOR; RFC 9881 §8.3",
    ),
    oid(
        "2.16.840.1.101.3.4.3.33",
        "id-hash-ml-dsa-65-with-sha512",
        HashMlDsa,
        "NIST CSOR; RFC 9881 §8.3",
    ),
    oid(
        "2.16.840.1.101.3.4.3.34",
        "id-hash-ml-dsa-87-with-sha512",
        HashMlDsa,
        "NIST CSOR; RFC 9881 §8.3",
    ),
    // HashSLH-DSA (RFC 9909)
    oid(
        "2.16.840.1.101.3.4.3.35",
        "id-hash-slh-dsa-sha2-128s-with-sha256",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.36",
        "id-hash-slh-dsa-sha2-128f-with-sha256",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.37",
        "id-hash-slh-dsa-sha2-192s-with-sha512",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.38",
        "id-hash-slh-dsa-sha2-192f-with-sha512",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.39",
        "id-hash-slh-dsa-sha2-256s-with-sha512",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.40",
        "id-hash-slh-dsa-sha2-256f-with-sha512",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.41",
        "id-hash-slh-dsa-shake-128s-with-shake128",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.42",
        "id-hash-slh-dsa-shake-128f-with-shake128",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.43",
        "id-hash-slh-dsa-shake-192s-with-shake256",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.44",
        "id-hash-slh-dsa-shake-192f-with-shake256",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.45",
        "id-hash-slh-dsa-shake-256s-with-shake256",
        HashSlhDsa,
        "RFC 9909",
    ),
    oid(
        "2.16.840.1.101.3.4.3.46",
        "id-hash-slh-dsa-shake-256f-with-shake256",
        HashSlhDsa,
        "RFC 9909",
    ),
    // FIPS 203 ML-KEM public keys (RFC 9935)
    oid(
        "2.16.840.1.101.3.4.4.1",
        "id-alg-ml-kem-512",
        MlKem,
        "RFC 9935",
    ),
    oid(
        "2.16.840.1.101.3.4.4.2",
        "id-alg-ml-kem-768",
        MlKem,
        "RFC 9935",
    ),
    oid(
        "2.16.840.1.101.3.4.4.3",
        "id-alg-ml-kem-1024",
        MlKem,
        "RFC 9935",
    ),
    // Composite ML-DSA (RFC 10073 §6)
    oid(
        "1.3.6.1.5.5.7.6.37",
        "id-MLDSA44-RSA2048-PSS-SHA256",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.38",
        "id-MLDSA44-RSA2048-PKCS15-SHA256",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.39",
        "id-MLDSA44-Ed25519-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.40",
        "id-MLDSA44-ECDSA-P256-SHA256",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.41",
        "id-MLDSA65-RSA3072-PSS-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.42",
        "id-MLDSA65-RSA3072-PKCS15-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.43",
        "id-MLDSA65-RSA4096-PSS-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.44",
        "id-MLDSA65-RSA4096-PKCS15-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.45",
        "id-MLDSA65-ECDSA-P256-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.46",
        "id-MLDSA65-ECDSA-P384-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.47",
        "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.48",
        "id-MLDSA65-Ed25519-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.49",
        "id-MLDSA87-ECDSA-P384-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.50",
        "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.51",
        "id-MLDSA87-Ed448-SHAKE256",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.52",
        "id-MLDSA87-RSA3072-PSS-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.53",
        "id-MLDSA87-RSA4096-PSS-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
    oid(
        "1.3.6.1.5.5.7.6.54",
        "id-MLDSA87-ECDSA-P521-SHA512",
        CompositeMlDsa,
        "RFC 10073",
    ),
];

/// Look up a post-quantum OID (dotted-decimal).
pub fn pqc_oid(dotted: &str) -> Option<&'static PqcOid> {
    PQC_OIDS.iter().find(|o| o.oid == dotted)
}

/// True if a certificate *signature* algorithm OID is post-quantum.
/// ML-KEM OIDs identify KEM keys and are never signature algorithms.
pub fn is_pqc_oid(dotted: &str) -> bool {
    pqc_oid(dotted).is_some_and(|o| o.kind != OidKind::MlKem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_codepoints_match_rfc_10024() {
        assert_eq!(
            named_group(0x11eb).map(|g| g.name),
            Some("SecP256r1MLKEM768")
        );
        assert_eq!(named_group(0x11ec).map(|g| g.name), Some("X25519MLKEM768"));
        assert_eq!(
            named_group(0x11ed).map(|g| g.name),
            Some("SecP384r1MLKEM1024")
        );
        assert_eq!(
            named_group(0x639a).map(|g| g.name),
            Some("SecP256r1Kyber768Draft00")
        );
        assert_eq!(
            named_group(0x6399).map(|g| g.status),
            Some(Status::Obsolete)
        );
    }

    #[test]
    fn classification() {
        assert!(is_pqc_group(4588));
        assert!(is_pqc_group(513));
        assert!(!is_pqc_group(0x001d));
        assert!(!is_pqc_group(4592)); // unassigned
        assert_eq!(get_group_name(0xabcd), "unknown(0xabcd)");
        assert_eq!(
            named_group_by_name("X25519MLKEM768").map(|g| g.code),
            Some(4588)
        );
        assert_eq!(named_group_by_name("x25519").map(|g| g.code), Some(0x001d));
    }

    #[test]
    fn signature_schemes() {
        assert!(is_pqc_signature_algorithm(0x0905));
        assert!(!is_pqc_signature_algorithm(0x0804));
        assert_eq!(get_signature_algorithm_name(0x0809), "rsa_pss_pss_sha256");
        assert_eq!(
            get_signature_algorithm_name(0x0503),
            "ecdsa_secp384r1_sha384"
        );
        assert!(is_pqc_signature_scheme_name("mldsa65"));
    }

    #[test]
    fn oids() {
        assert!(is_pqc_oid("2.16.840.1.101.3.4.3.18"));
        assert!(is_pqc_oid("1.3.6.1.5.5.7.6.45"));
        assert!(!is_pqc_oid("2.16.840.1.101.3.4.4.2")); // ML-KEM key, not a signature
        assert!(!is_pqc_oid("1.2.840.113549.1.1.11")); // sha256WithRSAEncryption
        assert!(!is_pqc_oid("2.16.840.1.114027.80.8.1.21")); // old draft arc
        assert_eq!(
            pqc_oid("2.16.840.1.101.3.4.3.33").map(|o| o.kind),
            Some(OidKind::HashMlDsa)
        );
        // No duplicates
        for (i, a) in PQC_OIDS.iter().enumerate() {
            assert!(
                PQC_OIDS[i + 1..].iter().all(|b| b.oid != a.oid),
                "{}",
                a.oid
            );
        }
        for (i, a) in NAMED_GROUPS.iter().enumerate() {
            assert!(
                NAMED_GROUPS[i + 1..].iter().all(|b| b.code != a.code),
                "{}",
                a.code
            );
        }
    }
}
