#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<u64>| {
    let mut replay = rustyguard::AntiReplay::default();

    let mut seen = std::collections::BTreeSet::new();
    let mut last = 0u64;

    for d in data {
        let allowed = seen.insert(d);
        let too_old = d < last && last - d >= 1984;
        last = u64::max(d, last);

        assert_eq!(replay.check(d), allowed && !too_old);
    }
});
