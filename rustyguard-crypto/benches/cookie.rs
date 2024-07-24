use divan::black_box;
use hmac::digest::generic_array::GenericArray;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rustyguard_types::{Cookie, EncryptedCookie};

fn main() {
    divan::main()
}

#[divan::bench(sample_count = 100, sample_size = 10000)]
fn encrypt_cookie() -> EncryptedCookie {
    let mut rng = StdRng::from_seed(black_box([0; 32]));
    let mut nonce = [0; 24];
    rng.fill_bytes(&mut nonce);
    rustyguard_crypto::encrypt_cookie(
        Cookie(black_box([0xa5; 16])),
        &black_box(GenericArray::default()),
        &nonce,
        &black_box([0xa5; 16]),
    )
}
