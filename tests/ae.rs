extern crate crypto_abstract;
extern crate ring;
extern crate untrusted;

use crypto_abstract::ToPublicKey;
use crypto_abstract::asym::enc as ae;
use crypto_abstract::sym::enc as se;
use ring::rand::{SystemRandom, SecureRandom};

#[test]
fn x25519_encrypt_and_decrypt() {
    fn run() {
        // Generate key.
        let rng = SystemRandom::new();
        let key = ae::gen( &rng, &ae::Algorithm::AEX25519).unwrap();
        let public_key = ToPublicKey::to_public_key( &key);

        // Generate something to encrypt.
        let mut content = [0u8; 256].to_vec();
        rng.fill( &mut content).unwrap();

        // Encrypt content.
        let encrypted = ae::encrypt( &rng, &se::Algorithm::SEAesGcm256, &public_key, content.clone()).unwrap();

        // Decrypt content.
        let decrypted = ae::decrypt( &rng, &key, encrypted).unwrap();

        // Ensure decrypted content matches.
        assert_eq!( content, decrypted)
    }

    for _ in 1..100 {
        run()
    }
}

