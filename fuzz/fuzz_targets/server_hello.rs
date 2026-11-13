//! Record splitter + ServerHello extraction + HelloRetryRequest check, fed
//! with the raw bytes a server sends (untrusted).
#![no_main]
use libfuzzer_sys::fuzz_target;
use quanta_seek::handshake::{is_hello_retry_request, server_hello_messages};

fuzz_target!(|records: &[u8]| {
    for msg in server_hello_messages(records) {
        // Every extracted message is a complete ServerHello: type 2 and a
        // length field matching its size.
        assert_eq!(msg[0], 2);
        let len = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(msg.len(), 4 + len);
        let _ = is_hello_retry_request(&msg);
    }
});
