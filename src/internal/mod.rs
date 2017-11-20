
use ring::digest::{SHA256};
use ring::pbkdf2;

pub fn derive_key_256( salt : &Vec<u8>, password : &Vec<u8>) -> [u8;32] {
    let mut key = [0;32];
    pbkdf2::derive( &SHA256, 4000, &salt, &password, &mut key);
    key
}

