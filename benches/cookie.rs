use chacha20poly1305::Key;
use divan::black_box;
use hmac::digest::generic_array::GenericArray;
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn main() {
    divan::main()
}

#[divan::bench(sample_count = 1000, sample_size = 1000)]
fn encrypt_cookie() -> EncryptedCookie {
    let mut rng = StdRng::from_seed(black_box([0; 32]));
    let mut nonce = [0; 24];
    rng.fill_bytes(&mut nonce);
    EncryptedCookie::encrypt_cookie(
        black_box([0xa5; 16]),
        &black_box(GenericArray::default()),
        &nonce,
        &black_box([0xa5; 16]),
    )
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct EncryptedCookie {
    msg: [u8; 16],
    tag: [u8; 16],
}

impl EncryptedCookie {
    pub(crate) fn encrypt_cookie(
        mut cookie: [u8; 16],
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
    ) -> Self {
        use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};

        let tag = XChaCha20Poly1305::new(key)
            .encrypt_in_place_detached(nonce.into(), aad, &mut cookie)
            .expect("cookie message should not be larger than max message size");

        Self {
            msg: cookie,
            tag: tag.into(),
        }
    }
}
