
mod x25519aesgcm256;

use ring::agreement::ReusablePrivateKey;
use ring::rand::SystemRandom;

use internal::u8_to_fixed_length_32;

use ToAlgorithm;
use ToPublicKey;

// TODO: AERsa2048Oaep256 XXX
#[derive(Eq,PartialEq)]
pub enum Algorithm {
    AEX25519AesGcm256 // RFC7748
}

#[derive(Eq,PartialEq)]
pub enum PublicKey {
    AEX25519AesGcm256 ([u8;x25519aesgcm256::PUBLICKEYLENGTH])
}

pub enum PrivateKey {
    AEX25519AesGcm256 (ReusablePrivateKey)
}

pub enum CipherText {
    AEX25519AesGcm256 ([u8;x25519aesgcm256::PUBLICKEYLENGTH], Vec<u8>,Vec<u8>)
}

pub fn gen( rng : &SystemRandom, alg : &Algorithm) -> Option<PrivateKey> {
    match alg {
        &Algorithm::AEX25519AesGcm256 => {
            Some( PrivateKey::AEX25519AesGcm256( x25519aesgcm256::gen( rng)?))
        }
    }
}

pub fn encrypt( rng : &SystemRandom, key : &PublicKey, message : Vec<u8>) -> Option<CipherText> {
    match key {
        &PublicKey::AEX25519AesGcm256( key) => {
            let (ephemeral_public_key, nonce, ciphertext) = x25519aesgcm256::encrypt( rng, &key, message)?;
            Some( CipherText::AEX25519AesGcm256( ephemeral_public_key, nonce, ciphertext))
        }
    }
}

pub fn decrypt( private_key : &PrivateKey, ciphertext : CipherText) -> Option<Vec<u8>> {
    match private_key {
        &PrivateKey::AEX25519AesGcm256(ref private_key) => match ciphertext {
            CipherText::AEX25519AesGcm256(ephemeral_public_key, nonce, ciphertext) => {
                x25519aesgcm256::decrypt( &private_key, ( &ephemeral_public_key, &nonce, ciphertext))
            }
        }
    }
}

impl ToAlgorithm for PublicKey {
    type Algorithm = Algorithm;

    fn to_algorithm( &self) -> Self::Algorithm {
        match *self {
            PublicKey::AEX25519AesGcm256(_) => Algorithm::AEX25519AesGcm256
        }
    }
}

impl ToAlgorithm for PrivateKey {
    type Algorithm = Algorithm;

    fn to_algorithm( &self) -> Self::Algorithm {
        match *self {
            PrivateKey::AEX25519AesGcm256(_) => Algorithm::AEX25519AesGcm256
        }
    }
}

impl ToAlgorithm for CipherText {
    type Algorithm = Algorithm;

    fn to_algorithm( &self) -> Self::Algorithm {
        match *self {
            CipherText::AEX25519AesGcm256(_,_,_) => Algorithm::AEX25519AesGcm256
        }
    }
}

impl ToPublicKey for PrivateKey {
    type PublicKey = PublicKey;

    fn to_public_key( &self) -> Self::PublicKey {
        match self {
            &PrivateKey::AEX25519AesGcm256(ref private_key) => {
                let public_key = u8_to_fixed_length_32( private_key.public_key_bytes()).unwrap();
                PublicKey::AEX25519AesGcm256( public_key)
            }
        }
    }
}

