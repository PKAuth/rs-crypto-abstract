
extern crate core;
extern crate ring;

pub mod sym;

pub trait ToAlgorithm {
    type Algorithm;
    fn to_algorithm(&self) -> Self::Algorithm;
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
