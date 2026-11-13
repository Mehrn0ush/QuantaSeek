//! Hand-built TLS 1.3 ClientHello and a parser for the server's first reply.
//!
//! Independent of rustls, so the prober can offer groups rustls does not
//! implement. Key shares are real keys (servers must validate ML-KEM
//! encapsulation keys and EC points, RFC 10024 §4.2), generated with
//! aws-lc-rs and thrown away: the prober never completes a handshake.

use crate::constants::{
    EXT_KEY_SHARE, EXT_PSK_KEY_EXCHANGE_MODES, EXT_SERVER_NAME, EXT_SIGNATURE_ALGORITHMS,
    EXT_SUPPORTED_GROUPS, EXT_SUPPORTED_VERSIONS, TLS_CONTENT_TYPE_ALERT,
    TLS_CONTENT_TYPE_HANDSHAKE, TLS_VERSION_1_3,
};
use crate::handshake::HELLO_RETRY_REQUEST_RANDOM;

/// padding extension (RFC 7685).
const EXT_PADDING: u16 = 0x0015;
/// TLS 1.3 cipher suites offered (RFC 8446 §B.4).
const CIPHER_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];
/// Signature schemes offered: every scheme in the registry table, so that
/// the server can choose any certificate it has (codes from constants.rs).
const SIGNATURE_SCHEMES: [u16; 29] = [
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0401,
    0x0501, 0x0601, 0x0904, 0x0905, 0x0906, 0x0911, 0x0912, 0x0913, 0x0914, 0x0915, 0x0916, 0x0917,
    0x0918, 0x0919, 0x091a, 0x091b, 0x091c,
];

/// A valid client key share for `group`, or None if the prober cannot
/// generate one. Formats: RFC 10024 §4.1 (hybrids), draft-ietf-tls-mlkem
/// (pure ML-KEM: the encapsulation key), RFC 8446 §4.2.8.2 (ECDHE,
/// uncompressed points; X25519 raw).
pub fn client_key_share(group: u16) -> Option<Vec<u8>> {
    use aws_lc_rs::agreement::{self, EphemeralPrivateKey};
    use aws_lc_rs::kem::{self, DecapsulationKey};
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let ecdh = |alg: &'static agreement::Algorithm| -> Option<Vec<u8>> {
        let key = EphemeralPrivateKey::generate(alg, &rng).ok()?;
        Some(key.compute_public_key().ok()?.as_ref().to_vec())
    };
    let mlkem = |alg| -> Option<Vec<u8>> {
        let dk = DecapsulationKey::generate(alg).ok()?;
        Some(
            dk.encapsulation_key()
                .ok()?
                .key_bytes()
                .ok()?
                .as_ref()
                .to_vec(),
        )
    };
    Some(match group {
        0x001d => ecdh(&agreement::X25519)?,
        0x0017 => ecdh(&agreement::ECDH_P256)?,
        0x0018 => ecdh(&agreement::ECDH_P384)?,
        0x0019 => ecdh(&agreement::ECDH_P521)?,
        512 => mlkem(&kem::ML_KEM_512)?,
        513 => mlkem(&kem::ML_KEM_768)?,
        514 => mlkem(&kem::ML_KEM_1024)?,
        // X25519MLKEM768: ML-KEM-768 ek || X25519 (RFC 10024 §4.1)
        4588 => [mlkem(&kem::ML_KEM_768)?, ecdh(&agreement::X25519)?].concat(),
        // SecP256r1MLKEM768: P-256 point || ML-KEM-768 ek
        4587 => [ecdh(&agreement::ECDH_P256)?, mlkem(&kem::ML_KEM_768)?].concat(),
        // SecP384r1MLKEM1024: P-384 point || ML-KEM-1024 ek
        4589 => [ecdh(&agreement::ECDH_P384)?, mlkem(&kem::ML_KEM_1024)?].concat(),
        _ => return None,
    })
}

/// Why the prober cannot offer a registered group.
pub fn unprobeable_reason(group: u16) -> &'static str {
    match group {
        0x001e => "no X448 implementation in aws-lc-rs",
        0x0100..=0x0104 => "finite-field DHE groups are not implemented by the prober",
        4585 | 4586 => "share format from draft-rosomakho-tls-ecdhe-mlkem512 not verified",
        4590 => "no SM2 implementation in aws-lc-rs",
        4591 => "no X448 implementation in aws-lc-rs",
        25497 | 25498 => {
            "pre-standard Kyber768 keys cannot be generated (aws-lc-rs has FIPS 203 ML-KEM only)"
        }
        _ => "no key share generator",
    }
}

/// Expected length of the server's key share for `group`, used to check a
/// ServerHello is well-formed (RFC 10024 §4.2, FIPS 203 Table 3).
pub fn server_share_len(group: u16) -> Option<usize> {
    Some(match group {
        0x001d => 32,
        0x0017 => 65,
        0x0018 => 97,
        0x0019 => 133,
        512 => 768,
        513 => 1088,
        514 => 1568,
        4588 => 1088 + 32,
        4587 => 65 + 1088,
        4589 => 97 + 1568,
        _ => return None,
    })
}

/// What the ClientHello offers.
#[derive(Debug, Clone, Default)]
pub struct ClientHelloSpec {
    pub server_name: Option<String>,
    /// supported_groups, in preference order.
    pub supported_groups: Vec<u16>,
    /// Groups to send key shares for, in order (each must be in
    /// `supported_groups` and probeable).
    pub key_shares: Vec<u16>,
    /// Pad the ClientHello message to at least this many bytes.
    pub pad_to: Option<usize>,
}

fn u16_vec(items: &[u16]) -> Vec<u8> {
    items.iter().flat_map(|i| i.to_be_bytes()).collect()
}

fn with_len16(body: &[u8]) -> Vec<u8> {
    let mut v = (body.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(body);
    v
}

fn extension(ext: u16, body: &[u8]) -> Vec<u8> {
    let mut v = ext.to_be_bytes().to_vec();
    v.extend(with_len16(body));
    v
}

/// Build the ClientHello handshake message (type 1). Returns None if a
/// requested key share cannot be generated.
pub fn client_hello(spec: &ClientHelloSpec) -> Option<Vec<u8>> {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    aws_lc_rs::rand::SecureRandom::fill(&rng, &mut random).ok()?;
    aws_lc_rs::rand::SecureRandom::fill(&rng, &mut session_id).ok()?;

    let mut exts = Vec::new();
    if let Some(name) = spec
        .server_name
        .as_deref()
        .filter(|n| n.parse::<std::net::IpAddr>().is_err())
    {
        // server_name_list with one host_name entry (RFC 6066 §3).
        let mut entry = vec![0u8];
        entry.extend(with_len16(name.as_bytes()));
        exts.extend(extension(EXT_SERVER_NAME, &with_len16(&entry)));
    }
    exts.extend(extension(EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]));
    exts.extend(extension(
        EXT_SUPPORTED_GROUPS,
        &with_len16(&u16_vec(&spec.supported_groups)),
    ));
    exts.extend(extension(
        EXT_SIGNATURE_ALGORITHMS,
        &with_len16(&u16_vec(&SIGNATURE_SCHEMES)),
    ));
    exts.extend(extension(EXT_PSK_KEY_EXCHANGE_MODES, &[1, 1])); // psk_dhe_ke
    let mut shares = Vec::new();
    for &group in &spec.key_shares {
        shares.extend(group.to_be_bytes());
        shares.extend(with_len16(&client_key_share(group)?));
    }
    exts.extend(extension(EXT_KEY_SHARE, &with_len16(&shares)));

    let mut body = vec![0x03, 0x03]; // legacy_version
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&session_id);
    body.extend(with_len16(&u16_vec(&CIPHER_SUITES)));
    body.extend_from_slice(&[1, 0]); // null compression

    if let Some(target) = spec.pad_to {
        // header(4) + body + extensions-length(2) + exts + padding ext header(4)
        let current = 4 + body.len() + 2 + exts.len() + 4;
        let pad = target.saturating_sub(current);
        exts.extend(extension(EXT_PADDING, &vec![0u8; pad]));
    }
    body.extend(with_len16(&exts));

    let mut msg = vec![1];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend(body);
    Some(msg)
}

/// Wrap a handshake message into TLS records of at most `max_fragment` bytes.
pub fn records(handshake: &[u8], max_fragment: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in handshake.chunks(max_fragment.clamp(1, 16384)) {
        out.extend_from_slice(&[TLS_CONTENT_TYPE_HANDSHAKE, 0x03, 0x01]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// A parsed ServerHello or HelloRetryRequest (RFC 8446 §4.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloInfo {
    pub hello_retry_request: bool,
    pub cipher_suite: u16,
    /// supported_versions selection; None means the server chose TLS ≤ 1.2.
    pub selected_version: Option<u16>,
    /// ServerHello: key_share group; HRR: the group requested.
    pub group: Option<u16>,
    /// Length of the server's key_exchange (ServerHello only).
    pub key_share_len: Option<usize>,
    pub extensions: Vec<u16>,
}

/// The server's first reply to a ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Hello(ServerHelloInfo),
    Alert { level: u8, description: u8 },
    Closed,
    Malformed(String),
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.data.len());
        let end = end.ok_or_else(|| format!("truncated at offset {}", self.pos))?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

/// Parse a ServerHello handshake message (type 2, with its 4-byte header).
pub fn parse_server_hello(msg: &[u8]) -> Result<ServerHelloInfo, String> {
    let mut r = Reader { data: msg, pos: 0 };
    if r.u8()? != 2 {
        return Err("not a ServerHello".into());
    }
    let len_bytes = r.take(3)?;
    let len = u32::from_be_bytes([0, len_bytes[0], len_bytes[1], len_bytes[2]]) as usize;
    if len != msg.len() - 4 {
        return Err(format!("length field {} != body {}", len, msg.len() - 4));
    }
    let _legacy_version = r.u16()?;
    let random = r.take(32)?;
    let hello_retry_request = random == HELLO_RETRY_REQUEST_RANDOM;
    let sid_len = r.u8()? as usize;
    if sid_len > 32 {
        return Err("session id longer than 32".into());
    }
    r.take(sid_len)?;
    let cipher_suite = r.u16()?;
    let _compression = r.u8()?;
    let mut info = ServerHelloInfo {
        hello_retry_request,
        cipher_suite,
        selected_version: None,
        group: None,
        key_share_len: None,
        extensions: Vec::new(),
    };
    if r.pos == msg.len() {
        return Ok(info); // TLS 1.2 ServerHello without extensions
    }
    let ext_len = r.u16()? as usize;
    let mut exts = Reader {
        data: r.take(ext_len)?,
        pos: 0,
    };
    if r.pos != msg.len() {
        return Err("trailing bytes after extensions".into());
    }
    while exts.pos < exts.data.len() {
        let ext = exts.u16()?;
        let body_len = exts.u16()? as usize;
        let mut body = Reader {
            data: exts.take(body_len)?,
            pos: 0,
        };
        if info.extensions.contains(&ext) {
            return Err(format!("duplicate extension {ext:#06x}"));
        }
        info.extensions.push(ext);
        match ext {
            EXT_SUPPORTED_VERSIONS => info.selected_version = Some(body.u16()?),
            EXT_KEY_SHARE if hello_retry_request => info.group = Some(body.u16()?),
            EXT_KEY_SHARE => {
                info.group = Some(body.u16()?);
                let n = body.u16()? as usize;
                body.take(n)?;
                info.key_share_len = Some(n);
            }
            _ => {}
        }
    }
    Ok(info)
}

/// Interpret the bytes received after sending a ClientHello. Returns None
/// while more bytes are needed.
pub fn parse_reply(received: &[u8], eof: bool) -> Option<Reply> {
    let mut handshake = Vec::new();
    let mut offset = 0;
    while offset + 5 <= received.len() {
        let content_type = received[offset];
        let len = u16::from_be_bytes([received[offset + 3], received[offset + 4]]) as usize;
        if len > 16384 + 2048 {
            return Some(Reply::Malformed(format!("record length {len}")));
        }
        if offset + 5 + len > received.len() {
            break;
        }
        let fragment = &received[offset + 5..offset + 5 + len];
        match content_type {
            TLS_CONTENT_TYPE_ALERT if handshake.is_empty() => {
                return Some(match fragment {
                    [level, description, ..] => Reply::Alert {
                        level: *level,
                        description: *description,
                    },
                    _ => Reply::Malformed("short alert".into()),
                });
            }
            TLS_CONTENT_TYPE_HANDSHAKE => {
                handshake.extend_from_slice(fragment);
                if handshake.len() >= 4 {
                    let msg_len =
                        u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
                    if msg_len > 65536 {
                        return Some(Reply::Malformed(format!("handshake length {msg_len}")));
                    }
                    if handshake.len() >= 4 + msg_len {
                        return Some(match parse_server_hello(&handshake[..4 + msg_len]) {
                            Ok(info) => Reply::Hello(info),
                            Err(e) => Reply::Malformed(e),
                        });
                    }
                }
            }
            other => return Some(Reply::Malformed(format!("unexpected record type {other}"))),
        }
        offset += 5 + len;
    }
    eof.then_some(Reply::Closed)
}

/// True if `version` from supported_versions is TLS 1.3.
pub fn is_tls13(version: Option<u16>) -> bool {
    version == Some(TLS_VERSION_1_3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_shares_have_rfc_10024_sizes() {
        for (group, len) in [
            (0x001d, 32),
            (0x0017, 65),
            (0x0018, 97),
            (0x0019, 133),
            (512, 800),
            (513, 1184),
            (514, 1568),
            (4588, 1216),
            (4587, 1249),
            (4589, 1665),
        ] {
            assert_eq!(
                client_key_share(group).map(|k| k.len()),
                Some(len),
                "{group:#06x}"
            );
        }
        assert!(client_key_share(25497).is_none());
    }

    #[test]
    fn client_hello_round_trips_and_pads() {
        let spec = ClientHelloSpec {
            server_name: Some("example.test".into()),
            supported_groups: vec![4588, 0x001d],
            key_shares: vec![4588],
            pad_to: None,
        };
        let ch = client_hello(&spec).unwrap();
        assert_eq!(ch[0], 1);
        assert_eq!(
            u32::from_be_bytes([0, ch[1], ch[2], ch[3]]) as usize,
            ch.len() - 4
        );
        let padded = client_hello(&ClientHelloSpec {
            pad_to: Some(4000),
            ..spec
        })
        .unwrap();
        assert!(
            padded.len() >= 4000 && padded.len() < 4010,
            "{}",
            padded.len()
        );
        let recs = records(&padded, 1000);
        assert_eq!(recs.len(), padded.len() + 5 * padded.len().div_ceil(1000));
    }

    fn server_hello(random: [u8; 32], exts: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&random);
        body.extend_from_slice(&[0, 0x13, 0x02, 0]);
        body.extend(with_len16(exts));
        let mut m = vec![2];
        m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        m.extend(body);
        m
    }

    #[test]
    fn parses_server_hello_and_hrr() {
        let mut exts = extension(EXT_SUPPORTED_VERSIONS, &[3, 4]);
        let mut ks = 4588u16.to_be_bytes().to_vec();
        ks.extend(with_len16(&[0u8; 1120]));
        exts.extend(extension(EXT_KEY_SHARE, &ks));
        let info = parse_server_hello(&server_hello([5; 32], &exts)).unwrap();
        assert!(!info.hello_retry_request);
        assert_eq!((info.group, info.key_share_len), (Some(4588), Some(1120)));
        assert!(is_tls13(info.selected_version));

        let mut exts = extension(EXT_SUPPORTED_VERSIONS, &[3, 4]);
        exts.extend(extension(EXT_KEY_SHARE, &0x0018u16.to_be_bytes()));
        let info = parse_server_hello(&server_hello(HELLO_RETRY_REQUEST_RANDOM, &exts)).unwrap();
        assert!(info.hello_retry_request);
        assert_eq!(info.group, Some(0x0018));
    }

    #[test]
    fn parse_reply_handles_alerts_fragmentation_and_eof() {
        assert_eq!(
            parse_reply(&[21, 3, 3, 0, 2, 2, 40], false),
            Some(Reply::Alert {
                level: 2,
                description: 40
            })
        );
        let mut exts = extension(EXT_SUPPORTED_VERSIONS, &[3, 4]);
        exts.extend(extension(
            EXT_KEY_SHARE,
            &[0, 0x1d, 0, 32]
                .iter()
                .copied()
                .chain([0u8; 32])
                .collect::<Vec<_>>(),
        ));
        let sh = server_hello([1; 32], &exts);
        let recs = records(&sh, 20);
        assert_eq!(parse_reply(&recs[..recs.len() - 1], false), None);
        assert!(
            matches!(parse_reply(&recs, false), Some(Reply::Hello(i)) if i.group == Some(0x1d))
        );
        assert_eq!(parse_reply(&[], true), Some(Reply::Closed));
        assert!(matches!(
            parse_reply(&[23, 3, 3, 0, 1, 0], false),
            Some(Reply::Malformed(_))
        ));
    }

    #[test]
    fn rejects_malformed_server_hellos() {
        let ok = server_hello([1; 32], &extension(EXT_SUPPORTED_VERSIONS, &[3, 4]));
        for cut in 0..ok.len() {
            let _ = parse_server_hello(&ok[..cut]);
        }
        let mut dup = extension(EXT_SUPPORTED_VERSIONS, &[3, 4]);
        dup.extend(extension(EXT_SUPPORTED_VERSIONS, &[3, 4]));
        assert!(parse_server_hello(&server_hello([1; 32], &dup)).is_err());
    }
}
