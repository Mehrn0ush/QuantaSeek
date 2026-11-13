//! The prober's reply parser (ServerHello / HelloRetryRequest / alert),
//! fed with the bytes a server sends after our ClientHello (untrusted).
#![no_main]
use libfuzzer_sys::fuzz_target;
use quanta_seek::probe::wire::{parse_reply, parse_server_hello, Reply};

fuzz_target!(|data: &[u8]| {
    // Whole-buffer interpretation must agree with incremental arrival: a
    // reply decided on a prefix must not change as more bytes arrive.
    let full = parse_reply(data, false);
    for cut in (0..=data.len()).step_by(7) {
        if let Some(early) = parse_reply(&data[..cut], false) {
            assert_eq!(Some(early), full.clone());
            break;
        }
    }
    let _ = parse_reply(data, true);
    if let Some(Reply::Hello(info)) = &full {
        if info.hello_retry_request {
            assert!(info.key_share_len.is_none());
        }
    }
    let _ = parse_server_hello(data);
});
