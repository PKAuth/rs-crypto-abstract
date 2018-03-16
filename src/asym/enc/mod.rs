
mod x25519aesgcm256;

use ring::rand::SystemRandom;

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
    AEX25519AesGcm256 ([u8; x25519aesgcm256::PRIVATEKEYLENGTH])
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
    match (private_key, ciphertext) {
        (&PrivateKey::AEX25519AesGcm256(private_key), CipherText::AEX25519AesGcm256(ephemeral_public_key, nonce, ciphertext)) => {
            x25519aesgcm256::decrypt( &private_key, ( &ephemeral_public_key, &nonce, ciphertext))
        }
    }
}
