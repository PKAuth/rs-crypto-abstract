
// extern crate ring;
//
//use ring::aead;
//

// use core::array::FixedSizeArray;
use ring::aead;
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

pub(super) fn gen ( rng : &SystemRandom) -> Result<[u8; KEYLENGTH],Unspecified> {
    // Generate random key.
    let mut bytes : [u8; KEYLENGTH] = [0; KEYLENGTH];
    rng.fill( &mut bytes)?;

    Ok(bytes)
}

pub(crate) fn encrypt ( rng : &SystemRandom, key : &[u8;KEYLENGTH], mut plaintext : Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), Unspecified> {
    // Convert key.
    let key = aead::SealingKey::new( &aead::AES_256_GCM, key)?;

    // Generate nonce.
    let mut nonce = vec![0; 12]; // aead::AES_256_GCM.tag_len()]; // 32];
    rng.fill(&mut nonce)?;

    // TODO: Do we need to expand plaintext? XXX
    let l = plaintext.len() + aead::AES_256_GCM.tag_len();
    plaintext.resize( l, 0);

    // Encrypt.
    let len = aead::seal_in_place( &key, &nonce, &[], plaintext.as_mut_slice(), aead::AES_256_GCM.tag_len())?;

    // Truncate unused.
    let c = plaintext[..len].to_vec();
    Ok(( nonce, c))
}

pub(crate) fn decrypt ( key : &[u8;KEYLENGTH], nonce : &[u8], mut ciphertext : Vec<u8>) -> Result<Vec<u8>, Unspecified> {
    // Convert key.
    let key = aead::OpeningKey::new( &aead::AES_256_GCM, key)?;

    // TODO: Do we need to expand output? XXX

    // Decrypt.
    let res = aead::open_in_place( &key, nonce, &[], 0, ciphertext.as_mut_slice())?;

    Ok( res.to_vec())
}

pub(super) const KEYLENGTH : usize = 32;

