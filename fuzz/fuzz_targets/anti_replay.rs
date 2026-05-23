#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyguard_utils::anti_replay::{AntiReplay, WINDOW_SIZE};

fuzz_target!(|data: Vec<u64>| {
    let mut replay = AntiReplay::default();

    let mut seen = std::collections::BTreeSet::new();
    let mut last = 0u64;

    for d in data {
        let allowed = seen.insert(d);
        let too_old = d < last && last - d >= WINDOW_SIZE;
        last = u64::max(d, last);

        let accepted = replay.would_accept(d);
        if accepted {
            replay.mark_seen(d);
        }
        assert_eq!(accepted, allowed && !too_old);
    }
});
