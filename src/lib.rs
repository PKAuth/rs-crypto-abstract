#![deny(warnings)]

extern crate core;
extern crate ring;
extern crate untrusted;

pub mod asym;
mod internal;
pub mod sym;

pub trait ToAlgorithm {
    type Algorithm;
    fn to_algorithm(&self) -> Self::Algorithm;
}

pub trait ToPublicKey {
    type PublicKey;
    fn to_public_key( &self) -> Self::PublicKey;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
