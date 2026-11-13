//! Target string parsing (user input).
#![no_main]
use libfuzzer_sys::fuzz_target;
use quanta_seek::scan::Target;

fuzz_target!(|input: &str| {
    if let Ok(t) = Target::parse(input) {
        assert!(!t.host.is_empty());
        assert_ne!(t.port, Some(0));
    }
});
