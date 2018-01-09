
use boolinator::Boolinator;
use ring::error::Unspecified;
use ring::rand::SystemRandom;
use ring::signature;
use ring::signature::{Ed25519KeyPair};
use untrusted::Input;

// Generates a private key.
pub(super) fn gen ( rng : &SystemRandom) -> Result<[u8; 85], Unspecified> {
    Ed25519KeyPair::generate_pkcs8( rng)
}

// Signs a message.
pub(super) fn sign( key : &[u8; PRIVATEKEYLENGTH], message : &Vec<u8>) -> Result<[u8; SIGNATURELENGTH], Unspecified> {
    let key = Ed25519KeyPair::from_pkcs8( Input::from( key))?;
    let sig = key.sign( &message);

    // Copy result to fixed length array.
    (sig.as_ref().len() == SIGNATURELENGTH).ok_or( Unspecified)?;
    let mut res = [0u8; SIGNATURELENGTH];
    for (place, element) in res.iter_mut().zip( sig.as_ref()) {
        *place = *element;
    }
    Ok( res)
}

// Verify a signature.
pub(super) fn verify( key : &[u8; PUBLICKEYLENGTH], message : &Vec<u8>, signature : &[u8; SIGNATURELENGTH]) -> bool {
    let signature = Input::from( signature.as_ref());
    let key = Input::from( key);
    let message = Input::from( message);
    let res = signature::verify( &signature::ED25519, key, message, signature);

    match res {
        Ok(()) => true,
        Err(_) => false
    }
}

pub(super) fn to_public_key( key : &[u8; PRIVATEKEYLENGTH]) -> [u8; PUBLICKEYLENGTH] {
    let mut p = [0; PUBLICKEYLENGTH];
    p.copy_from_slice( &key[PUBLICKEYPOSITION..PUBLICKEYPOSITION + PUBLICKEYLENGTH]);
    p
}

pub(super) const PRIVATEKEYLENGTH : usize = 85;
pub(super) const PUBLICKEYLENGTH : usize = 32;

pub(super) const PUBLICKEYPOSITION : usize = 53;

pub(super) const SIGNATURELENGTH : usize = 64;

