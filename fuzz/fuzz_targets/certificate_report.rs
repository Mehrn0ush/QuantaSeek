//! The certificate parser wrapper, fed with DER the server sends (untrusted).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|der: &[u8]| {
    if let Ok(report) = quanta_seek::report::certificate_report(0, der) {
        // Serialisation must not fail for anything the parser accepted.
        serde_json::to_string(&report).unwrap();
    }
});
