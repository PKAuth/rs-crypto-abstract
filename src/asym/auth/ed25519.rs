
use ring::error::Unspecified;
use ring::rand::SystemRandom;
use ring::signature;
use ring::signature::{Ed25519KeyPair, Signature};
use untrusted::Input;

// Generates a private key.
pub(super) fn gen ( rng : &SystemRandom) -> Result<[u8; 85], Unspecified> {
    Ed25519KeyPair::generate_pkcs8( rng)
}

// Signs a message.
pub(super) fn sign( key : &[u8; PRIVATEKEYLENGTH], message : &Vec<u8>) -> Result<Signature, Unspecified> {
    let key = Ed25519KeyPair::from_pkcs8( Input::from( key))?;
    Ok( key.sign( &message))
}

// Verify a signature.
pub(super) fn verify( key : &[u8; PUBLICKEYLENGTH], message : &Vec<u8>, signature : &Signature) -> bool {
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

