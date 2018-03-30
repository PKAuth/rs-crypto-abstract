
pub(crate) mod x25519;

use ring::agreement::ReusablePrivateKey;
use ring::rand::SystemRandom;

use internal::asym::enc::*;
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
    AEX25519 ([u8;x25519::PUBLICKEYLENGTH])
}

pub enum PrivateKey {
    AEX25519 (ReusablePrivateKey)
}

pub enum CipherText {
    CipherText (EncryptedKey, se::CipherText)
}

pub fn gen( rng : &SystemRandom, alg : &Algorithm) -> Option<PrivateKey> {
    match alg {
        &Algorithm::AEX25519 => {
            Some( PrivateKey::AEX25519( x25519::gen( rng)?))
        }
    }
}

pub fn encrypt( rng : &SystemRandom, algorithm : &se::Algorithm, key : &PublicKey, message : Vec<u8>) -> Option<CipherText> {
    let (encrypted_key, key) = encrypt_symmetric_key( rng, algorithm, key)?;

    let ciphertext = se::encrypt( rng, &key, message).ok()?;

    Some( CipherText::CipherText( encrypted_key, ciphertext))
}

pub fn decrypt( rng : &SystemRandom, private_key : &PrivateKey, CipherText::CipherText(encrypted_key, ciphertext) : CipherText) -> Option<Vec<u8>> {
    let key = decrypt_symmetric_key( rng, &ToAlgorithm::to_algorithm( &ciphertext), private_key, &encrypted_key)?;

    se::decrypt( &key, ciphertext).ok()
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

impl ToAlgorithm for EncryptedKey {
    type Algorithm = Algorithm;

    fn to_algorithm( &self) -> Self::Algorithm {
        match *self {
            EncryptedKey::AEX25519(_) => Algorithm::AEX25519
        }
    }
}

impl ToAlgorithm for CipherText {
    type Algorithm = Algorithm;

    fn to_algorithm( &self) -> Self::Algorithm {
        let CipherText::CipherText(ek, _) = self;
        ToAlgorithm::to_algorithm( ek)
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
