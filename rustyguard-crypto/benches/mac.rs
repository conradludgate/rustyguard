use divan::black_box;
use rustyguard_crypto::mac;
use subtle::Choice;

fn main() {
    divan::main()
}

#[divan::bench(sample_count = 1000, sample_size = 1000)]
fn verify_mac1() -> Choice {
    use subtle::ConstantTimeEq;
    let actual_mac1 = mac(&black_box([0xa5; 32]), &black_box([0xa5; 116]));
    actual_mac1.ct_ne(&black_box([0xa5; 16]))
}

#[divan::bench(sample_count = 1000, sample_size = 1000)]
fn verify_mac2() -> Choice {
    use subtle::ConstantTimeEq;

    let socket = &black_box([192, 168, 1, 1, 80, 80]);
    let cookie = mac(&black_box([0xa5; 32]), socket);

    let actual_mac2 = mac(&cookie, &black_box([0xa5; 116]));
    actual_mac2.ct_ne(&black_box([0xa5; 16]))
}