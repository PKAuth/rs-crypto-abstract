extern crate crypto_abstract;
extern crate ring;
extern crate untrusted;

// TODO: ensure our topublickey matches ring's XXX

use crypto_abstract::ToPublicKey;
use crypto_abstract::asym::auth;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use untrusted::Input;

#[test] 
fn to_public_key_test() {
    fn run() {
        // Generate key.
        let rng = SystemRandom::new();
        let key = auth::gen( &rng, &auth::Algorithm::AAEd25519).unwrap();

        // Extract public key.
        let auth::PublicKey::AAEd25519( pkak) = ToPublicKey::to_public_key( &key);

        // Extract public key via ring.
        let auth::PrivateKey::AAEd25519( key) = key;
        let key = Ed25519KeyPair::from_pkcs8( Input::from( key.as_ref())).unwrap();
        let rk = key.public_key_bytes();

        // Ensure outputs match.
        assert_eq!( pkak, rk);
    }

    for _ in 1..100 {
        run()
    }
}
