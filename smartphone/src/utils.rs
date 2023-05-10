use anyhow::{Error, Result};
use bincode::serialize;
use blstrs::{Scalar, G1Projective, G2Projective, Gt};
use group::Group;
use sha2::{Digest, Sha256};


pub fn g1_multi_exp<'a, I>(points_exp: I, size: usize) -> G1Projective
    where I: Iterator<Item = (&'a G1Projective, &'a Option<Scalar>)>
{
    if size > 0 {
        let mut points: Vec<G1Projective> = Vec::with_capacity(size);
        let mut scalars: Vec<Scalar> = Vec::with_capacity(size);

        for (&p, &a) in points_exp {
            match a {
                Some(s) => {
                    points.push(p);
                    scalars.push(s);
                },
                None => ()
            }
        }

        return G1Projective::multi_exp(points.as_slice(), scalars.as_slice());
    }
    return G1Projective::identity();
}

pub fn hash_points<'a, I1, I2, It>(ig1: I1, ig2: I2, igt: It, message: &[u8]) -> Result<[u8; 32]>
    where I1: Iterator<Item = &'a G1Projective>, I2: Iterator<Item = &'a G2Projective>, It : Iterator<Item = &'a Gt>
{
    let mut hasher = Sha256::new();

    for p in ig1 {
        hasher.update(p.to_compressed());
    }
    for p in ig2 {
        hasher.update(p.to_compressed());
    }
    for p in igt {
        hasher.update(serialize(p)?);
    }

    hasher.update(message);

    Ok(hasher.finalize().as_slice().try_into()?)
}


pub fn hash_challenge<'a, I1, I2, It>(ig1: I1, ig2: I2, igt: It, message: &[u8]) -> Result<Scalar>
    where I1: Iterator<Item = &'a G1Projective>, I2: Iterator<Item = &'a G2Projective>, It : Iterator<Item = &'a Gt>
{
    let mut hash: [u8; 32] = hash_points(ig1, ig2, igt, message)?;
    // ugly hack to ensure the points are always in F_q by removing the 2 most significant bits
    hash[31] &= 0x4f;

    Option::from(Scalar::from_bytes_le(&hash)).ok_or(Error::msg("Failed to hash bytes to a Scalar"))
}
