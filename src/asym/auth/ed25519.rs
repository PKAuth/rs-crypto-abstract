
use ring::error::Unspecified;
use ring::rand::SystemRandom;
use ring::signature;
use ring::signature::{Ed25519KeyPair, Signature};
use untrusted::Input;

// Generates a private key.
pub(super) fn gen ( rng : &SystemRandom) -> Result<Ed25519KeyPair, Unspecified> {
    let bytes = Ed25519KeyPair::generate_pkcs8( rng)?;

    Ed25519KeyPair::from_pkcs8( Input::from( &bytes))
}

// Signs a message.
pub(super) fn sign( key : &Ed25519KeyPair, message : &Vec<u8>) -> Signature {
    key.sign( &message)
}

// Verify a signature.
pub(super) fn verify( key : &Vec<u8>, message : &Vec<u8>, signature : &Signature) -> bool {
    let signature = Input::from( signature.as_ref());
    let key = Input::from( key);
    let message = Input::from( message);
    let res = signature::verify( &signature::ED25519, key, message, signature);

    match res {
        Ok(()) => true,
        Err(_) => false
    }
}
