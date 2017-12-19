
mod ed25519;

use ring::error::Unspecified;
use ring::rand::SystemRandom;
use ring::signature;
// use ring::signature::Ed25519KeyPair;

use ToAlgorithm;
use ToPublicKey;

// TODO: AARsa2048Pss256 XXX

#[derive(Eq,PartialEq)]
pub enum Algorithm {
    AAEd25519
}

pub enum PublicKey {
    AAEd25519 ([u8; ed25519::PUBLICKEYLENGTH])
}

pub enum PrivateKey {
    AAEd25519 ([u8; ed25519::PRIVATEKEYLENGTH])
}

pub enum Signature {
    AAEd25519 (signature::Signature)
}

pub fn gen ( rng : &SystemRandom, alg : &Algorithm) -> Result<PrivateKey,Unspecified> {
    match alg {
        &Algorithm::AAEd25519 => Ok( PrivateKey::AAEd25519( ed25519::gen( rng)?))
    }
}

pub fn sign (key : &PrivateKey, message : &Vec<u8>) -> Result<Signature, Unspecified> {
    match key {
        &PrivateKey::AAEd25519( ref key) => Ok( Signature::AAEd25519( ed25519::sign( &key, &message)?))
    }
}

pub fn verify (key : &PublicKey, message : &Vec<u8>, signature : &Signature) -> bool {
    match ( key, signature) {
        (&PublicKey::AAEd25519( ref key), &Signature::AAEd25519( ref signature)) =>
            ed25519::verify( key, message, signature)
    }
}

impl ToAlgorithm for PublicKey {
    type Algorithm = Algorithm;

    fn to_algorithm (&self) -> Self::Algorithm {
        match *self {
            PublicKey::AAEd25519(_) => Algorithm::AAEd25519
        }
    }
}

impl ToAlgorithm for PrivateKey {
    type Algorithm = Algorithm;

    fn to_algorithm (&self) -> Self::Algorithm {
        match *self {
            PrivateKey::AAEd25519(_) => Algorithm::AAEd25519
        }
    }
}

impl ToAlgorithm for Signature {
    type Algorithm = Algorithm;

    fn to_algorithm (&self) -> Self::Algorithm {
        match *self {
            Signature::AAEd25519(_) => Algorithm::AAEd25519
        }
    }
}

impl ToPublicKey for PrivateKey {
    type PublicKey = PublicKey;

    fn to_public_key( &self) -> Self::PublicKey {
        match self {
            &PrivateKey::AAEd25519( ref key) => 
                PublicKey::AAEd25519( ed25519::to_public_key( key))
        }
    }
}
