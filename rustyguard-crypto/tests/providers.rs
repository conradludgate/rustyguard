#![cfg(any(feature = "graviola", feature = "rustcrypto"))]

use rustyguard_crypto::{CryptoError, CryptoPrimatives, PublicKey, StaticPrivateKey};

fn hex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
}

fn vectors<C: CryptoPrimatives>() {
    // RFC 7748 section 6.1, https://www.rfc-editor.org/rfc/rfc7748#section-6.1
    let alice = StaticPrivateKey(hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let bob = PublicKey(hex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    ));
    assert_eq!(
        C::x25519_pubkey(&alice).0,
        hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        C::x25519(&alice, &bob).unwrap(),
        hex::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
    for value in [0, 1] {
        let mut public = [0; 32];
        public[0] = value;
        assert!(matches!(
            C::x25519(&alice, &PublicKey(public)),
            Err(CryptoError::KeyExchangeError)
        ));
    }

    // RFC 8439 section 2.8.2, https://www.rfc-editor.org/rfc/rfc8439#section-2.8.2
    let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex("070000004041424344454647");
    let aad = hex::<12>("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = hex::<114>(concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b6116"
    ));
    let mut payload = *plaintext;
    let mut tag = [0; 16];
    C::chacha20poly1305_enc(&key, &nonce, &aad, &mut payload, &mut tag);
    assert_eq!(payload, expected);
    assert_eq!(tag, hex::<16>("1ae10b594f09e26a7e902ecbd0600691"));

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert!(C::chacha20poly1305_dec(&key, &nonce, &aad, &mut payload, &bad_tag).is_err());
    payload = expected;
    assert!(C::chacha20poly1305_dec(&key, &nonce, b"different", &mut payload, &tag).is_err());
    payload = expected;
    C::chacha20poly1305_dec(&key, &nonce, &aad, &mut payload, &tag).unwrap();
    assert_eq!(&payload, plaintext);
}

#[cfg(feature = "graviola")]
#[test]
fn graviola_vectors() {
    vectors::<rustyguard_crypto::providers::Graviola>();
}

#[cfg(feature = "rustcrypto")]
#[test]
fn rustcrypto_vectors() {
    vectors::<rustyguard_crypto::providers::RustCrypto>();
}

#[cfg(all(feature = "graviola", feature = "rustcrypto"))]
#[test]
fn providers_agree_on_cookie_and_transport_boundaries() {
    use rustyguard_crypto::providers::{Graviola, RustCrypto};
    let key = [42; 32];
    for size in [0, 1, 15, 16, 17, 63, 64, 65, 1024, 1420] {
        for aad in [b"".as_slice(), b"associated data"] {
            let plaintext = vec![0x5a; size];
            let mut g = plaintext.clone();
            let mut r = plaintext.clone();
            let (mut gt, mut rt) = ([0; 16], [0; 16]);
            Graviola::chacha20poly1305_enc(&key, &[7; 12], aad, &mut g, &mut gt);
            RustCrypto::chacha20poly1305_enc(&key, &[7; 12], aad, &mut r, &mut rt);
            assert_eq!((&g, gt), (&r, rt));
            RustCrypto::chacha20poly1305_dec(&key, &[7; 12], aad, &mut g, &gt).unwrap();
            Graviola::chacha20poly1305_dec(&key, &[7; 12], aad, &mut r, &rt).unwrap();
            assert_eq!(g, plaintext);
            assert_eq!(r, plaintext);

            Graviola::xchacha20poly1305_enc(&key, &[7; 24], aad, &mut g, &mut gt);
            RustCrypto::xchacha20poly1305_enc(&key, &[7; 24], aad, &mut r, &mut rt);
            assert_eq!((&g, gt), (&r, rt));
            let mut bad_tag = gt;
            bad_tag[0] ^= 1;
            let mut tampered = g.clone();
            assert!(RustCrypto::xchacha20poly1305_dec(
                &key,
                &[7; 24],
                aad,
                &mut tampered,
                &bad_tag
            )
            .is_err());
            tampered.copy_from_slice(&g);
            assert!(RustCrypto::xchacha20poly1305_dec(
                &key,
                &[7; 24],
                b"wrong associated data",
                &mut tampered,
                &gt
            )
            .is_err());
            RustCrypto::xchacha20poly1305_dec(&key, &[7; 24], aad, &mut g, &gt).unwrap();
            Graviola::xchacha20poly1305_dec(&key, &[7; 24], aad, &mut r, &rt).unwrap();
            assert_eq!(g, plaintext);
            assert_eq!(r, plaintext);
        }
    }
}
