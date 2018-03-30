
use ring::agreement::*;
use ring::rand::SystemRandom;
use untrusted::Input;

// use internal::{sha256};
use sym::enc as se;
// TODO: Figure out how to import this... XXX
// use sym::enc::aesgcm256;

// use ToAlgorithm;

pub(super) fn gen( rng : &SystemRandom) -> Option<ReusablePrivateKey> {
    ReusablePrivateKey::generate( &X25519, rng).ok()
}

pub(crate) fn encrypt_symmetric_key( rng : &SystemRandom, algorithm : &se::Algorithm, public_key : &[u8;PUBLICKEYLENGTH]) -> Option<([u8;PUBLICKEYLENGTH], se::Key)> {
    let ephemeral_key = EphemeralPrivateKey::generate( &X25519, rng).ok()?;

    let mut ephemeral_public_key = [0u8; PUBLICKEYLENGTH];
    ephemeral_key.compute_public_key( &mut ephemeral_public_key).ok()?;

    // One iteration of pbkdf2 with sha256.
    let secret_key = agree_ephemeral( ephemeral_key, &X25519, Input::from( public_key), (), {|k| Ok( se::derive_key_with_iterations( algorithm, &[], k, 1))}).ok()?;

    Some( ( ephemeral_public_key, secret_key))
}

pub(crate) fn decrypt_symmetric_key( algorithm : &se::Algorithm, private_key : &ReusablePrivateKey, emphemeral_public_key : &[u8;PUBLICKEYLENGTH]) -> Option<se::Key> {
    agree_reusable( &private_key, &X25519, Input::from( emphemeral_public_key), (), {|k| Ok( se::derive_key_with_iterations( &algorithm, &[], k, 1))}).ok()
}

// pub(super) fn encrypt( rng : &SystemRandom, alg : &enc::Algorithm, public_key : &[u8;PUBLICKEYLENGTH], plaintext : Vec<u8>) -> Option<([u8;PUBLICKEYLENGTH], enc::CipherText)> {
//     let ephemeral_key = EphemeralPrivateKey::generate( &X25519, rng).ok()?;
// 
//     let mut ephemeral_public_key = [0u8; PUBLICKEYLENGTH];
//     ephemeral_key.compute_public_key( &mut ephemeral_public_key).ok()?;
// 
//     // TODO: Can we just use sha256 here? XXX
//     // let secret_key = agree_ephemeral( ephemeral_key, &X25519, Input::from( public_key), (), {|k| Ok( sha256( k))}).ok()?;
// 
//     // One iteration of pbkdf2 with sha256.
//     let secret_key = agree_ephemeral( ephemeral_key, &X25519, Input::from( public_key), (), {|k| Ok( enc::derive_key_with_iterations( alg, &[], k, 1))}).ok()?;
// 
//     // let (nonce, encrypted) = enc::aesgcm256::encrypt( &rng, &secret_key, plaintext).ok()?;
//     let encrypted = enc::encrypt( &rng, &secret_key, plaintext).ok()?;
// 
//     Some( ( ephemeral_public_key, encrypted))
// }
// 
// pub(super) fn decrypt( private_key : &ReusablePrivateKey, ciphertext : (&[u8;PUBLICKEYLENGTH], enc::CipherText)) -> Option<Vec<u8>> {
//     let (emphemeral_public_key, ciphertext) = ciphertext;
//     let alg = ToAlgorithm::to_algorithm( &ciphertext);
// 
//     // let secret_key = agree_reusable( &private_key, &X25519, Input::from( emphemeral_public_key), (), {|k| Ok( sha256(k))}).ok()?;
//     let secret_key = agree_reusable( &private_key, &X25519, Input::from( emphemeral_public_key), (), {|k| Ok( enc::derive_key_with_iterations( &alg, &[], k, 1))}).ok()?;
// 
//     // enc::aesgcm256::decrypt( &secret_key, nonce, ciphertext).ok()
//     enc::decrypt( &secret_key, ciphertext).ok()
// }

// TODO: Figure these out XXX
// pub(super) const PRIVATEKEYLENGTH : usize = 32;
pub(crate) const PUBLICKEYLENGTH : usize = 32; 

// TODO: Get rid of this XXX
// pub(super) const SECRETKEYLENGTH : usize = 32;
