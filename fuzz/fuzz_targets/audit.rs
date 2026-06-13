#![no_main]
//! Full CFB carving pipeline over arbitrary bytes — must never panic.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = cfb_forensic::audit_bytes(data);
});
