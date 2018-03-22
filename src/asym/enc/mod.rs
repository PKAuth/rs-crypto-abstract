
mod x25519aesgcm256;

use ring::agreement::ReusablePrivateKey;
use ring::rand::SystemRandom;

use internal::u8_to_fixed_length_32;
use sym::enc as se;

use ToAlgorithm;
use ToPublicKey;

// TODO: AERsa2048Oaep256 XXX
#[derive(Eq,PartialEq)]
pub enum Algorithm {
    AEX25519 // RFC7748
}

#[derive(Eq,PartialEq)]
pub enum PublicKey {
    AEX25519 ([u8;x25519aesgcm256::PUBLICKEYLENGTH])
}

pub enum PrivateKey {
    AEX25519 (ReusablePrivateKey)
}

pub enum CipherText {
    AEX25519 ([u8;x25519aesgcm256::PUBLICKEYLENGTH], se::CipherText)
}

pub fn gen( rng : &SystemRandom, alg : &Algorithm) -> Option<PrivateKey> {
    match alg {
        &Algorithm::AEX25519 => {
            Some( PrivateKey::AEX25519( x25519aesgcm256::gen( rng)?))
        }
    }
}

pub fn encrypt( rng : &SystemRandom, algorithm : &se::Algorithm, key : &PublicKey, message : Vec<u8>) -> Option<CipherText> {
    match key {
        &PublicKey::AEX25519( key) => {
            let (ephemeral_public_key, ciphertext) = x25519aesgcm256::encrypt( rng, algorithm, &key, message)?;
            Some( CipherText::AEX25519( ephemeral_public_key, ciphertext))
        }
    }
}

pub fn decrypt( private_key : &PrivateKey, ciphertext : CipherText) -> Option<Vec<u8>> {
    match private_key {
        &PrivateKey::AEX25519(ref private_key) => match ciphertext {
            CipherText::AEX25519(ephemeral_public_key, ciphertext) => {
                x25519aesgcm256::decrypt( &private_key, ( &ephemeral_public_key, ciphertext))
            }
        }
    }
}

impl ToAlgorithm for PublicKey {
    type Algorithm = Algorithm;

    fn to_algorithm( &self) -> Self::Algorithm {
        match *self {
            PublicKey::AEX25519(_) => Algorithm::AEX25519
        }
    }
}

impl ToAlgorithm for PrivateKey {
    type Algorithm = Algorithm;

    fn to_algorithm( &self) -> Self::Algorithm {
        match *self {
            PrivateKey::AEX25519(_) => Algorithm::AEX25519
        }
    }
}

impl ToAlgorithm for CipherText {
    type Algorithm = Algorithm;

    fn to_algorithm( &self) -> Self::Algorithm {
        match *self {
            CipherText::AEX25519(_,_) => Algorithm::AEX25519
        }
    }
}

impl ToPublicKey for PrivateKey {
    type PublicKey = PublicKey;

    fn to_public_key( &self) -> Self::PublicKey {
        match self {
            &PrivateKey::AEX25519(ref private_key) => {
                let public_key = u8_to_fixed_length_32( private_key.public_key_bytes()).unwrap();
                PublicKey::AEX25519( public_key)
            }
        }
    }
}
