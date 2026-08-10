#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| radian_fuzz::run_f1ap(data));
