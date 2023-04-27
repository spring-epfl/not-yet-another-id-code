use std::iter::{empty, zip};
use anyhow::{Error, Result};
use array_init::{array_init, from_iter};
use blstrs::{pairing, G1Projective, G2Projective, Gt, Scalar};
use group::Curve;
use rand::RngCore;
use group::{Group, ff::Field};
use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;

use crate::utils::{g1_multi_exp, hash_challenge};


#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKey<const N_ATTR: usize> {
    pub g: G1Projective,
    #[serde(with = "BigArray")]
    pub gy: [G1Projective; N_ATTR],
    pub gt: G2Projective,
    pub gtx: G2Projective,
    #[serde(with = "BigArray")]
    pub gty: [G2Projective; N_ATTR],
}


#[derive(Serialize, Deserialize, Clone)]
pub struct PrivateKey<const N_ATTR: usize> {
    pub x: Scalar,
    pub gx: G1Projective,
    #[serde(with = "BigArray")]
    pub y: [Scalar; N_ATTR],
    pub public_key: PublicKey<N_ATTR>,
}


#[derive(Serialize, Deserialize, Clone)]
pub struct IssueRequest<const N_ATTR: usize> {
    pub commitment: G1Projective,
    pub challenge: Scalar,
    pub st: Scalar,
    #[serde(with = "BigArray")]
    pub sas: [Option<Scalar>; N_ATTR],
}


#[derive(Serialize, Deserialize, Clone)]
pub struct IssueRequestState<const N_ATTR: usize> {
    pub t: Scalar,
    #[serde(with = "BigArray")]
    pub user_attributes: [Option<Scalar>; N_ATTR],
}


#[derive(Serialize, Deserialize, Clone)]
pub struct Signature {
    pub sigma1: G1Projective,
    pub sigma2: G1Projective,
}


#[derive(Serialize, Deserialize, Clone)]
pub struct BlindSignature<const N_ATTR: usize> {
    pub sigma1: G1Projective,
    pub sigma2: G1Projective,
    #[serde(with = "BigArray")]
    pub issuer_attributes: [Option<Scalar>; N_ATTR],
}


#[derive(Serialize, Deserialize, Clone)]
pub struct AnonymousCredential<const N_ATTR: usize> {
    pub signature: Signature,
    #[serde(with = "BigArray")]
    pub attributes: [Scalar; N_ATTR],
}


#[derive(Serialize, Deserialize, Clone)]
pub struct DisclosureProof<const N_ATTR: usize> {
    pub sigma1: G1Projective,
    pub sigma2: G1Projective,
    pub challenge: Scalar,
    pub st: Scalar,
    #[serde(with = "BigArray")]
    pub sas: [Option<Scalar>; N_ATTR],
    #[serde(with = "BigArray")]
    pub attributes: [Option<Scalar>; N_ATTR],
}


impl<const N_ATTR: usize> PrivateKey<N_ATTR> {
    pub fn new(mut rng: impl RngCore) -> Result<PrivateKey<N_ATTR>> {
        let g = G1Projective::random(&mut rng);
        let gt = G2Projective::random(&mut rng);

        let x = Scalar::random(&mut rng);
        let y: [Scalar; N_ATTR] = array_init(|_| Scalar::random(&mut rng));

        let pk = PublicKey{
            g: g,
            gy: from_iter(y.iter().map(|yi| g * yi)).ok_or(Error::msg("Should not happen"))?,
            gt: gt,
            gtx: gt * x,
            gty: from_iter(y.iter().map(|yi| gt * yi)).ok_or(Error::msg("Should not happen"))?,
        };

        Ok(PrivateKey{
            x: x,
            gx: g * x,
            y: y,
            public_key: pk
        })
    }


    pub fn sign_issue_request(&self, request: &IssueRequest<N_ATTR>, issuer_attributes: &[Option<Scalar>; N_ATTR], mut rng: impl RngCore) -> Result<BlindSignature<N_ATTR>> {
        if self.public_key.gy.len() != issuer_attributes.len() {
            return Err(Error::msg("Invalid number of attributes"));
        }

        let pk = &self.public_key;

        // check proof

        let com_prime = g1_multi_exp(
            [(&pk.g, &Some(request.st)), (&request.commitment, &Some(-request.challenge))].into_iter().chain(
                zip(pk.gy.iter(), request.sas.iter())
            ),
            N_ATTR + 2
        );

        let challenge = hash_challenge([pk.g, com_prime].iter().chain(pk.gy.iter()), empty(), empty(), &[])?;
        if challenge != request.challenge {
            return Err(Error::msg("Invalid commitment"));
        }

        // Sign request

        let u = Scalar::random(&mut rng);

        let sigma1 = pk.g * u;

        let s2 = self.gx + request.commitment + g1_multi_exp(zip(pk.gy.iter(), issuer_attributes.iter()), N_ATTR);

        let sigma2 = s2 * u;

        Ok(BlindSignature{
            sigma1: sigma1,
            sigma2: sigma2,
            issuer_attributes: issuer_attributes.clone(),
        })

    }

}


impl<const N_ATTR: usize> PublicKey<N_ATTR> {

    pub fn issue_request(&self, attributes: &[Option<Scalar>; N_ATTR], mut rng: impl RngCore) -> Result<(IssueRequest<N_ATTR>, IssueRequestState<N_ATTR>)> {
        // Prepare commitment
        let t = Scalar::random(&mut rng);
        let rt = Scalar::random(&mut rng);
        let ras: [Option<Scalar>; N_ATTR] = from_iter(attributes.iter().map(
            |attr|
            match attr {
                Some(_) => Some(Scalar::random(&mut rng)),
                None => None
            }
        )).ok_or(Error::msg("Failed to generate randomizers"))?;

        let com = g1_multi_exp([(&self.g, &Some(t))].into_iter().chain(
            zip(self.gy.iter(), attributes.iter())
        ), N_ATTR + 1);
        let com_prime = g1_multi_exp([(&self.g, &Some(rt))].into_iter().chain(
            zip(self.gy.iter(), ras.iter())
        ), N_ATTR + 1);

        let challenge = hash_challenge([self.g, com_prime].iter().chain(self.gy.iter()), empty(), empty(), &[])?;

        let st = rt + challenge * t;
        let sas: [Option<Scalar>; N_ATTR] = from_iter(zip(ras.iter(), attributes.iter()).map(
            |(ra, attr)|
            match (ra, attr) {
                (Some(r), Some(a)) => Some(r + challenge * a),
                _ => None
            }
        )).ok_or(Error::msg("Failed to generate witnesses"))?;

        Ok((IssueRequest{commitment: com, challenge: challenge, st: st, sas: sas}, IssueRequestState{t: t, user_attributes: attributes.clone().into()}))
    }


    pub fn create_disclosure_proof(&self, credential: &AnonymousCredential<N_ATTR>, disclosed_attributes: &[bool; N_ATTR], mut rng: impl RngCore) -> Result<DisclosureProof<N_ATTR>> {
        let ts = Scalar::random(&mut rng);
        let rs = Scalar::random(&mut rng);

        let s1 = credential.signature.sigma1;
        let s2 = credential.signature.sigma2;

        let sp1 = s1 * rs;
        let sp2 = (s2 + (s1 * ts)) * rs;

        let sp1a = sp1.to_affine();

        // choose randomizers
        let rt = Scalar::random(&mut rng);
        let ras: [Option<Scalar>; N_ATTR] = from_iter(disclosed_attributes.iter().map(
            |&discl|
            if discl {
                return None;
            }
            else {
                return Some(Scalar::random(&mut rng));
            }
        )).ok_or(Error::msg("Failed to generate randomizers"))?;

        let attributes: [Option<Scalar>; N_ATTR] = from_iter(zip(credential.attributes.iter(), disclosed_attributes.iter()).map(
            |(&attr, &discl)|
            if discl {
                return Some(attr);
            }
            else {
                return None;
            }
        )).ok_or(Error::msg("Failed to extract attributes"))?;

        // compute commitment
        let com = pairing(&sp1a, &self.gt.to_affine()) * rt +
            zip(self.gty.iter(), ras.iter()).filter_map(
                |(gty, ra,)|
                match ra {
                    Some(a) => Some(pairing(&sp1a, &gty.to_affine()) * a),
                    None => None
                }
            ).sum::<Gt>();

        // Shamir's heuristic
        let challenge = hash_challenge([&sp1, &sp2].into_iter(), [&self.gt].into_iter().chain(self.gty.iter()), [&com].into_iter(), &[])?;

        // compute responses
        let st = rt + challenge * ts;
        let sas: [Option<Scalar>; N_ATTR] = from_iter(zip(ras.iter(), credential.attributes.iter()).map(
            |(ra, a)|
            match ra {
                Some(r) => Some(r + challenge * a),
                None => None
            }
        )).ok_or(Error::msg("Failed to generate witnesses"))?;

        Ok(DisclosureProof{sigma1: sp1, sigma2: sp2, challenge: challenge, st: st, sas: sas, attributes: attributes})
    }


    pub fn verify_disclosure_proof(&self, disclosure_proof: &DisclosureProof<N_ATTR>) -> Result<bool> {
        let sp1 = disclosure_proof.sigma1;
        let sp2 = disclosure_proof.sigma2;

        if bool::from(sp1.is_identity()) {
            return Ok(false);
        }

        let sp1a = sp1.to_affine();

        let com_prime = pairing(&sp2.to_affine(), &self.gt.to_affine()) -
            pairing(&sp1a, &self.gtx.to_affine()) -
            zip(self.gty.iter(), disclosure_proof.attributes.iter()).filter_map(
                |(gty, attr)|
                match attr {
                    Some(a) => Some(pairing(&sp1a, &gty.to_affine()) * a),
                    None => None
                }
            ).sum::<Gt>();

        let com = pairing(&sp1a, &self.gt.to_affine()) * disclosure_proof.st +
            zip(self.gty.iter(), disclosure_proof.sas.iter()).filter_map(
                |(gty, ra)|
                match ra {
                    Some(a) => Some(pairing(&sp1a, &gty.to_affine()) * a),
                    None => None
                }
            ).sum::<Gt>() - com_prime * disclosure_proof.challenge;

        let challenge = hash_challenge([&sp1, &sp2].into_iter(), [&self.gt].into_iter().chain(self.gty.iter()), [&com].into_iter(), &[])?;

        Ok(challenge == disclosure_proof.challenge)

    }

}


impl<const N_ATTR: usize> BlindSignature<N_ATTR> {
    pub fn unblind(&self, state: &IssueRequestState<N_ATTR>) -> Result<AnonymousCredential<N_ATTR>> {
        let sigma2 = self.sigma2 - (self.sigma1 * state.t);

        let attributes: [Scalar; N_ATTR] = from_iter(self.issuer_attributes.iter().zip(state.user_attributes.iter()).filter_map(
            |(ai, au)|
            match (ai, au) {
                (Some(a), None) => Some(*a),
                (None, Some(a)) => Some(*a),
                _ => None
            }
        )).ok_or(Error::msg("Failed to extract attributes"))?;

        if attributes.len() != self.issuer_attributes.len() {
            return Err(Error::msg("Invalid attributes"));
        }

        Ok(AnonymousCredential{signature: Signature {sigma1: self.sigma1, sigma2: sigma2}, attributes: attributes})
    }
}


#[cfg(test)]
mod tests {
    use blstrs::Scalar;
    use group::Group;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::{SeedableRng};

    use crate::pointcheval_sanders::PrivateKey;


    #[test]
    fn generated_keys_are_valid() {
        let mut rng = ChaCha20Rng::seed_from_u64(42 as u64);

        let sk: PrivateKey<2> = PrivateKey::new(&mut rng).unwrap();

        assert_eq!(sk.y.len(), 2);

        let pk = sk.public_key;
        assert!(!bool::from(pk.g.is_identity()));
        assert!(!bool::from(pk.gt.is_identity()));

        assert_eq!(pk.gy.len(), 2);
        assert_eq!(pk.gty.len(), 2);

        assert!(pk.gy[0] != pk.gy[1]);
        assert!(pk.gty[0] != pk.gty[1]);
    }

    #[test]
    fn sign_commitent() {
        let mut rng = ChaCha20Rng::seed_from_u64(42 as u64);
        let sk: PrivateKey<2> = PrivateKey::new(&mut rng).unwrap();
        let pk = &sk.public_key;

        let (req, blinding_param) = pk.issue_request(&[Some(Scalar::from(12)), None], &mut rng).unwrap();

        sk.sign_issue_request(&req, &[None, Some(Scalar::from(17))], &mut rng).unwrap().unblind(&blinding_param).unwrap();
    }

    #[test]
    fn verify_disclosure_proof() {
        let mut rng = ChaCha20Rng::seed_from_u64(42 as u64);
        let sk: PrivateKey<4> = PrivateKey::new(&mut rng).unwrap();
        let pk = &sk.public_key;

        let (req, blinding_param) = pk.issue_request(&[Some(Scalar::from(12)), Some(Scalar::from(9)), None, None], &mut rng).unwrap();

        let cred = sk.sign_issue_request(&req, &[None, None, Some(Scalar::from(5)), Some(Scalar::from(17))], &mut rng).unwrap().unblind(&blinding_param).unwrap();

        let dp = pk.create_disclosure_proof(&cred, &[true, false, false, false], &mut rng).unwrap();

        assert!(&pk.verify_disclosure_proof(&dp).unwrap_or(false));
    }
}
