extern crate crypto_abstract;
extern crate ring;
extern crate untrusted;

use crypto_abstract::ToPublicKey;
use crypto_abstract::asym::enc;
use ring::rand::{SystemRandom, SecureRandom};

#[test]
fn x25519_encrypt_and_decrypt() {
    fn run() {
        // Generate key.
        let rng = SystemRandom::new();
        let key = enc::gen( &rng, &enc::Algorithm::AEX25519AesGcm256).unwrap();
        let public_key = ToPublicKey::to_public_key( &key);

        // Generate something to encrypt.
        let mut content = [0u8; 256].to_vec();
        rng.fill( &mut content).unwrap();

        // Encrypt content.
        let encrypted = enc::encrypt( &rng, &public_key, content.clone()).unwrap();

        // Decrypt content.
        let decrypted = enc::decrypt( &key, encrypted).unwrap();

        // Ensure decrypted content matches.
        assert_eq!( content, decrypted)
    }

    for _ in 1..100 {
        run()
    }
}

