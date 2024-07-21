#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<u64>| {
    let mut replay = rustyguard::AntiReplay::default();
    for d in data {
        replay.check(d);
    }
});
