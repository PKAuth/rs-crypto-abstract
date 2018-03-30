
use ring::rand::SystemRandom;

use asym::enc::{x25519, PublicKey, PrivateKey};
use sym::enc as se;

pub enum EncryptedKey {
    AEX25519 ( [u8;x25519::PUBLICKEYLENGTH])
}

pub fn encrypt_symmetric_key( rng : &SystemRandom, algorithm : &se::Algorithm, key : &PublicKey) -> Option<(EncryptedKey,se::Key)> {
    match key {
        PublicKey::AEX25519( key) => {
            let (pk, sk) = x25519::encrypt_symmetric_key( rng, algorithm, key)?;
            Some( ( EncryptedKey::AEX25519(pk), sk))
        }
    }
}

pub fn decrypt_symmetric_key( _rng : &SystemRandom, algorithm : &se::Algorithm, private_key : &PrivateKey, encrypted_key : &EncryptedKey) -> Option<se::Key> {
    match (private_key, encrypted_key) {
        (PrivateKey::AEX25519( private_key), EncryptedKey::AEX25519( ephemeral_public_key)) => {
            x25519::decrypt_symmetric_key( algorithm, private_key, ephemeral_public_key)
        }
    }
}

