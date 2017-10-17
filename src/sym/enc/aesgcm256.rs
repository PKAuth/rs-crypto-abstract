
// extern crate ring;
//
//use ring::aead;
//

// use core::array::FixedSizeArray;
use ring::aead;
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

pub(super) fn gen ( rng : &SystemRandom) -> Result<[u8; 256],Unspecified> {
    // Generate random key.
    let mut bytes : [u8; 256] = [0; 256];
    rng.fill( &mut bytes)?;

    Ok(bytes)
}

pub fn encrypt ( rng : &SystemRandom, key : &[u8;256], mut plaintext : Vec<u8>) -> Result<Vec<u8>, Unspecified> {
    // Convert key.
    let key = aead::SealingKey::new( &aead::AES_256_GCM, key)?;

    // Generate nonce.
    let mut nonce = vec![0; aead::AES_256_GCM.tag_len()]; // 32];
    rng.fill(&mut nonce)?;

    // TODO: Do we need to expand plaintext? XXX
    let l = plaintext.len() + aead::AES_256_GCM.tag_len();
    plaintext.resize( l, 0);

    // Encrypt key
    let len = aead::seal_in_place( &key, &nonce, &[], plaintext.as_mut_slice(), aead::AES_256_GCM.tag_len())?;

    // Truncate unused.
    Ok( plaintext[..len].to_vec())
}
