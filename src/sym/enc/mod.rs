
pub(crate) mod aesgcm256;

// use sym::enc;
// use sym::enc::aesgcm256;
use ring::error::Unspecified;
use ring::rand::{SystemRandom};

use internal::{derive_key_256};
use ToAlgorithm;

#[derive(Eq,PartialEq)]
pub enum Algorithm {
    SEAesGcm256
}

#[derive(Clone)]
pub enum Key {
    SEAesGcm256( [u8; aesgcm256::KEYLENGTH])
}

pub enum CipherText {
    SEAesGcm256( Vec<u8>, Vec<u8>) // (Nonce, Ciphertext)
}

pub fn gen ( rng : &SystemRandom, alg : &Algorithm) -> Result<Key,Unspecified> {
    match alg {
        &Algorithm::SEAesGcm256 => Ok( Key::SEAesGcm256( aesgcm256::gen( rng)?))
    }
}

pub fn derive_key( alg : &Algorithm, salt : &[u8], password : &[u8]) -> Key {
    match alg {
        &Algorithm::SEAesGcm256 => Key::SEAesGcm256( derive_key_256( salt, password))
    }
}

pub fn encrypt ( rng : &SystemRandom, key : &Key, plaintext : Vec<u8>) -> Result<CipherText, Unspecified> {
    match key {
        &Key::SEAesGcm256( key) => {
            let (n, c) = aesgcm256::encrypt( &rng, &key, plaintext)?;
            Ok( CipherText::SEAesGcm256( n, c))
        }

    }
}

pub fn decrypt ( key : &Key, ciphertext : CipherText) -> Result<Vec<u8>, Unspecified> {
    match (key, ciphertext) {
        (&Key::SEAesGcm256( key), CipherText::SEAesGcm256( nonce, ciphertext)) =>
            aesgcm256::decrypt( &key, &nonce, ciphertext)
    }

}

impl ToAlgorithm for Key {
    type Algorithm = Algorithm;

    fn to_algorithm (&self) -> Self::Algorithm {
        match *self {
            Key::SEAesGcm256(_) => Algorithm::SEAesGcm256
        }
    }
}

impl ToAlgorithm for CipherText {
    type Algorithm = Algorithm;

    fn to_algorithm (&self) -> Self::Algorithm {
        match *self {
            CipherText::SEAesGcm256(_,_) => Algorithm::SEAesGcm256
        }
    }
}
