
use ring::agreement::*;
use ring::rand::SystemRandom;
use untrusted::Input;

use internal::{sha256, u8_to_fixed_length_32};
use sym::enc;
// TODO: Figure out how to import this... XXX
// use sym::enc::aesgcm256;

pub(super) fn gen( rng : &SystemRandom) -> Option<[u8; PRIVATEKEYLENGTH]> {
    let private_key = ReusablePrivateKey::generate( &X25519, rng).ok()?;

    let private_key = private_key.private_key_bytes();

    // Convert to 32 bytes.
    u8_to_fixed_length_32( private_key)
}

pub(super) fn encrypt( rng : &SystemRandom, public_key : &[u8;PUBLICKEYLENGTH], plaintext : Vec<u8>) -> Option<([u8;PUBLICKEYLENGTH], Vec<u8>, Vec<u8>)> {
    let ephemeral_key = EphemeralPrivateKey::generate( &X25519, rng).ok()?;

    let mut ephemeral_public_key = [0u8; PUBLICKEYLENGTH];
    ephemeral_key.compute_public_key( &mut ephemeral_public_key).ok()?;

    // TODO: Can we just use sha256 here? XXX
    let secret_key = agree_ephemeral( ephemeral_key, &X25519, Input::from( public_key), (), {|k| Ok( sha256( k))}).ok()?;

    // let secret_key = agree_ephemeral( ephemeral_key, &X25519, Input::from( public_key), (), {|k| 
    //     let salt = [];
    //     Ok( enc::derive_key( &enc::Algorithm::SEAesGcm256, &salt, k))
    // }).ok()?;
    // JP: For now doing 4000 rounds of pbkdf2 and an empty salt. Can we just sha256?
    // let secret_key = enc::Key::SEAesGcm256( secret_bits);

    let (nonce, encrypted) = enc::aesgcm256::encrypt( &rng, &secret_key, plaintext).ok()?;
    // let encrypted = enc::encrypt( &rng, &secret_key, plaintext).ok()?;

    Some( ( ephemeral_public_key, nonce, encrypted))
}

pub(super) fn decrypt( private_key : &[u8; PRIVATEKEYLENGTH], ciphertext : (&[u8;PUBLICKEYLENGTH], &Vec<u8>, Vec<u8>)) -> Option<Vec<u8>> {
    let (emphemeral_public_key, nonce, ciphertext) = ciphertext;

    let private_key = ReusablePrivateKey::from_bytes( &X25519, Input::from( private_key)).ok()?;

    let secret_key = agree_reusable( &private_key, &X25519, Input::from( emphemeral_public_key), (), {|k| Ok( sha256(k))}).ok()?;


    enc::aesgcm256::decrypt( &secret_key, nonce, ciphertext).ok()
}

// TODO: Figure these out XXX
pub(super) const PRIVATEKEYLENGTH : usize = 32;
pub(super) const PUBLICKEYLENGTH : usize = 1; 

// TODO: Get rid of this XXX
// pub(super) const SECRETKEYLENGTH : usize = 32;
