
mod aesgcm256;

// use sym::enc;
// use sym::enc::aesgcm256;
use ring::error::Unspecified;
use ring::rand::{SystemRandom};

use ToAlgorithm;

pub enum Algorithm {
    SEAesGcm256
}

pub enum Key {
    SEAesGcm256( [u8;256])
}

pub enum CipherText {
    SEAesGcm256( Vec<u8>)
}

pub fn gen ( rng : &SystemRandom, alg : Algorithm) -> Result<Key,Unspecified> {
    match alg {
        Algorithm::SEAesGcm256 => Ok( Key::SEAesGcm256( aesgcm256::gen( rng)?))
    }
}

pub fn encrypt ( rng : &SystemRandom, key : &Key, plaintext : Vec<u8>) -> Result<CipherText, Unspecified> {
    match key {
        &Key::SEAesGcm256( key) => Ok( CipherText::SEAesGcm256( aesgcm256::encrypt( &rng, &key, plaintext)?))
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
            CipherText::SEAesGcm256(_) => Algorithm::SEAesGcm256
        }
    }
}
