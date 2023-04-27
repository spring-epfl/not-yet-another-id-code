use blstrs::{Scalar, G1Projective};
use group::{ff::Field, Group};
use rand::RngCore;
use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Clone)]
pub struct PedersenParams {
    pub h: G1Projective,
}


impl PedersenParams {
    pub fn new(mut rng: impl RngCore) -> Self {
        Self{h: G1Projective::random(&mut rng)}
    }

    pub fn commit(&self, message: &Scalar, mut rng: impl RngCore) -> (G1Projective, Scalar) {
        let r = Scalar::random(&mut rng);

        (G1Projective::generator() * message + self.h * r, r)
    }

    pub fn verify(&self, message: &Scalar, commitment: &G1Projective, r: &Scalar) -> bool {
        G1Projective::generator() * message + self.h * r == *commitment
    }
}

