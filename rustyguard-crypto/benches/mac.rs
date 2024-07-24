use divan::black_box;
use rustyguard_crypto::mac;

fn main() {
    divan::main()
}

#[divan::bench(sample_count = 100, sample_size = 10000)]
fn verify_mac1() -> bool {
    let actual_mac1 = mac(&black_box([0xa5; 32]), &black_box([0xa5; 116]));
    actual_mac1 != black_box([0xa5; 16])
}

#[divan::bench(sample_count = 100, sample_size = 10000)]
fn verify_mac2() -> bool {
    let socket = &black_box([192, 168, 1, 1, 80, 80]);
    let cookie = mac(&black_box([0xa5; 32]), socket);

    let actual_mac2 = mac(&cookie, &black_box([0xa5; 116]));
    actual_mac2 != black_box([0xa5; 16])
}
