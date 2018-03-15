
use boolinator::Boolinator;
use ring::digest::{SHA256, digest};
use ring::pbkdf2;

pub fn derive_key_256( salt : &[u8], password : &[u8]) -> [u8;32] {
    let mut key = [0;32];
    pbkdf2::derive( &SHA256, 4000, &salt, &password, &mut key);
    key
}

pub fn sha256( data : &[u8]) -> [u8; 32] {
    let sha = digest( &SHA256, data);

    u8_to_fixed_length_32( sha.as_ref()).unwrap()
}

pub fn u8_to_fixed_length_32( data : &[u8]) -> Option<[u8; 32]> {
    // Check length.
    (data.len() == 32).as_option()?;

    // Copy result to fixed length array.
    let mut res = [0u8; 32];
    for (place, element) in res.iter_mut().zip( data) {
        *place = *element;
    }

    Some( res)
}

pub fn u8_to_fixed_length_64( data : &[u8]) -> Option<[u8; 64]> {
    // Check length.
    (data.len() == 64).as_option()?;

    // Copy result to fixed length array.
    let mut res = [0u8; 64];
    for (place, element) in res.iter_mut().zip( data) {
        *place = *element;
    }

    Some( res)
}

