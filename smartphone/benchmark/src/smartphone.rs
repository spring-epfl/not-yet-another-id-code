use std::collections::{HashMap, HashSet};
use std::iter::{zip, empty};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Error, Result};
use blstrs::{pairing, Scalar, G1Projective, Gt};
use group::{Curve, Group, ff::Field};
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{SeedableRng};
use serde::{Serialize, Deserialize};

use crate::pedersen::PedersenParams;
use crate::pointcheval_sanders::{AnonymousCredential, BlindSignature, IssueRequest, IssueRequestState, PrivateKey, PublicKey};
use crate::utils::{g1_multi_exp, hash_points, hash_challenge};


#[derive(Serialize, Deserialize, Clone)]
pub struct HouseholdRegister {
    pub sk: PrivateKey<3>,
    pub entitlement: Scalar,
    pub revocation: Scalar,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RegistrationStation {
    pub pedersen_params: PedersenParams,
    pub blocklist: Vec<(G1Projective, G1Projective)>,
    pub household_registers: HashMap<Box<str>, HouseholdRegister>,
    pub epoch: u64,
}


#[derive(Serialize, Deserialize, Clone)]
pub struct DistributionStation {
    pub pedersen_params: PedersenParams,
    pub distribution_list: Vec<G1Projective>,
    pub audit_records: Vec<(HouseholdDisclosureProof, Scalar, Scalar)>,
}


#[derive(Serialize, Deserialize, Clone)]
pub struct HouseholdPhoneBuilder {
    pub pk: PublicKey<3>,
    pub household_secret: Scalar,
}


#[derive(Serialize, Deserialize, Clone)]
pub struct HouseholdPhone {
    pub pedersen_params: PedersenParams,
    pub pk: PublicKey<3>,
    pub credential: AnonymousCredential<3>,
}


#[derive(Serialize, Deserialize, Clone)]
pub struct NonRevocationProof {
    pub h0: G1Projective,
    pub big_h0: G1Projective,
    pub com_aux: Vec<G1Projective>,
    pub challenge: Scalar,
    pub sa: Scalar,
    pub sb: Scalar,
}


#[derive(Serialize, Deserialize, Clone)]
pub struct HouseholdDisclosureProof {
    pub sigma1: G1Projective,
    pub sigma2: G1Projective,
    pub tau: G1Projective,
    pub non_revocation_proof: NonRevocationProof,
    pub com_ent: G1Projective,
    pub challenge: Scalar,
    pub st: Scalar,
    pub ssh: Scalar,
    pub svh: Scalar,
    pub sent: Scalar,
    pub sr: Scalar,
}

const ATTR_IDX_SECRET_HOUSEHOLD: usize = 0;
const ATTR_IDX_REVOCATION: usize = 1;
const ATTR_IDX_ENTITLEMENT: usize = 2;


#[derive(Serialize, Deserialize, Clone)]
pub struct AuditProof {
    pub ent_sum: Scalar,
    pub r_sum: Scalar,
    pub registers: Vec<HouseholdDisclosureProof>,
}


#[inline]
pub fn epoch() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}


#[inline]
fn gen_ai(len: usize, seed: &[u8; 32]) -> Vec<Option<Scalar>> {
    let mut a_gen = ChaCha20Rng::from_seed(seed.clone());
    (1..len).into_iter().map(|_| Some(Scalar::from(a_gen.next_u64()))).collect()
}


impl RegistrationStation {
    pub fn new(mut rng: impl RngCore) -> Self {
        Self{
            pedersen_params: PedersenParams::new(&mut rng),
            blocklist: Vec::new(),
            household_registers: HashMap::new(),
            epoch: 0u64
        }
    }


    pub fn register(&mut self, id: &str, ent: &Scalar, mut rng: impl RngCore) -> Result<PublicKey<3>> {
        let revocation = Scalar::random(&mut rng);
        let sk: PrivateKey<3> = PrivateKey::new(rng)?;
        let pk = sk.public_key.clone();
        self.household_registers.insert(
            id.into(),
            HouseholdRegister{sk: sk, entitlement: ent.clone(), revocation: revocation}
        ).map_or_else(|| Ok(()), |_| Err(Error::msg("id alredy registered in registration station")))?;
        Ok(pk)
    }


    pub fn sign_issue_request(&self, id: &str, request: &IssueRequest<3>, mut rng: impl RngCore) -> Result<BlindSignature<3>> {
        let reg = self.household_registers.get(id).ok_or(Error::msg("Household not found"))?;
        reg.sk.sign_issue_request(request, &[None, Some(reg.revocation), Some(reg.entitlement)], &mut rng)
    }
}


impl DistributionStation {
    pub fn new(pedersen_params: &PedersenParams) -> Self {
        Self {
            pedersen_params: pedersen_params.clone(),
            distribution_list: Vec::new(),
            audit_records: Vec::new(),
        }
    }


    pub fn verify_non_revocation_proof(&self, blocklist: &Vec<(G1Projective, G1Projective)>, p: &NonRevocationProof) -> Result<bool> {
        if p.com_aux.len() != blocklist.len() {
            return Err(Error::msg("The non revocation proof is not associated with blocklist"))
        }
        for ci in p.com_aux.iter() {
            if ci.is_identity().into() {
                return Err(Error::msg("An auxiliary commitment is the neutral element"));
            }
        }

        let seed = hash_points(
            blocklist.iter().map(|(a, _)| a)
                .chain(blocklist.iter().map(|(_, a)| a))
                .chain(p.com_aux.iter()),
            empty(),
            empty(),
            &[]
        )?;

        let ai = gen_ai(p.com_aux.len(), &seed);

        let h = p.h0 + g1_multi_exp(zip(blocklist.iter().map(|(h, _)| h), ai.iter()), blocklist.len());
        let big_h = p.big_h0 + g1_multi_exp(zip(blocklist.iter().map(|(_, h)| h), ai.iter()), blocklist.len());
        let com = g1_multi_exp(zip(p.com_aux.iter(), ai.iter()), p.com_aux.len());

        let big_r = h * p.sa + big_h * p.sb - com * p.challenge;

        let challenge = hash_challenge([&big_r, &h, &big_h].into_iter().chain(p.com_aux.iter()), empty(), empty(), &seed)?;

        Ok(p.challenge == challenge)
    }


    pub fn verify_entitlement(&self, ent: &Scalar, com_ent: &G1Projective, r: &Scalar) -> bool {
        self.pedersen_params.verify(ent, com_ent, r)
    }


    pub fn verify_disclosure_proof(&self, pk: &PublicKey<3>, epoch: u64, blocklist: &Vec<(G1Projective, G1Projective)>, p: &HouseholdDisclosureProof) -> Result<bool> {
        let sp1 = &p.sigma1;
        let sp2 = &p.sigma2;

        if bool::from(sp1.is_identity()) {
            return Ok(false);
        }

        let sp1a = sp1.to_affine();

        // recompute the first commitments
        let com_prime = pairing(&sp2.to_affine(), &pk.gt.to_affine()) -
            pairing(&sp1a, &pk.gtx.to_affine());

        let com = pairing(&sp1a, &pk.gt.to_affine()) * p.st +
            zip(pk.gty.iter(), [&p.ssh, &p.svh, &p.sent].into_iter()).map(
                |(gty, a)|
                pairing(&sp1a, &gty.to_affine()) * a
            ).sum::<Gt>() - com_prime * p.challenge;

        // recompute tau commitment
        let com_tau = G1Projective::hash_to_curve(&epoch.to_le_bytes(), &[0x3], &[0x5, 0xb]) * p.ssh - p.tau * p.challenge;

        // recompute entitlement commitment's commitment
        let com_com = G1Projective::generator() * p.sent + self.pedersen_params.h * p.sr - p.com_ent * p.challenge;

        // recompute revocation's commitment
        let com_h = &p.non_revocation_proof.h0 * p.svh - p.non_revocation_proof.big_h0 * p.challenge;

        // Shamir's heuristic
        let challenge = hash_challenge(
            [&sp1, &sp2, &com_tau, &com_com, &com_h].into_iter(),
            [&pk.gt].into_iter().chain(pk.gty.iter()),
            [&com].into_iter(),
            &[]
        )?;

        if challenge != p.challenge {
            println!("Challenge doesn't match :(");
            return Ok(false);
        }

        // Check revocation
        if ! self.verify_non_revocation_proof(&blocklist, &p.non_revocation_proof)? {
            return Ok(false);
        }

        // check distribution
        if self.distribution_list.contains(&p.tau) {
            return Ok(false);
        }

        // If all checks passed, the disclosure proof is valid
        Ok(true)
    }


    pub fn register_record(&mut self, p: &HouseholdDisclosureProof, ent: &Scalar, r: &Scalar) {
        self.audit_records.push((p.clone(), ent.clone(), r.clone()));
    }


    pub fn create_audit_proof(&self) -> Result<AuditProof> {
        let ent_sum = self.audit_records.iter().map(|r| r.1).sum::<Scalar>();
        let r_sum = self.audit_records.iter().map(|r| r.2).sum::<Scalar>();
        Ok(AuditProof{ ent_sum, r_sum, registers: self.audit_records.iter().map(|r| r.0.clone()).collect()})
    }
}


impl HouseholdPhoneBuilder {
    pub fn new(pk: &PublicKey<3>, mut rng: impl RngCore) -> Self {
        Self{pk: pk.clone(), household_secret: Scalar::random(&mut rng)}
    }


    pub fn issue_request(&self, mut rng: impl RngCore) -> Result<(IssueRequest<3>, IssueRequestState<3>)> {
        self.pk.issue_request(&[Some(self.household_secret), None, None], &mut rng)
    }


    pub fn unblind(&self, signature: &BlindSignature<3>, state: &IssueRequestState<3>, pedersen_params: &PedersenParams) -> Result<HouseholdPhone> {
        Ok(HouseholdPhone{
            pedersen_params: pedersen_params.clone(),
            pk: self.pk.clone(),
            credential: signature.unblind(state)?
        })
    }
}


impl HouseholdPhone {
    pub fn create_non_revocation_proof(&self, rev: &Scalar, blocklist: &Vec<(G1Projective, G1Projective)>, mut rng: impl RngCore) -> Result<NonRevocationProof> {
        let h0 = G1Projective::random(&mut rng);
        let big_h0 = h0 * &self.credential.attributes[ATTR_IDX_REVOCATION];

        // compute auxiliary commitments
        let r = Scalar::random(&mut rng);
        let com_aux: Vec<G1Projective> = blocklist.iter().map(|(hi, big_hi)| (hi * rev - big_hi) * r).collect();

        // Shamir heuristic to compute ai
        let seed = hash_points(
            blocklist.iter().map(|(a, _)| a)
                .chain(blocklist.iter().map(|(_, a)| a))
                .chain(com_aux.iter()),
                empty(),
                empty(),
                &[]
            )?;

        let ai = gen_ai(blocklist.len(), &seed);

        let h = h0 + g1_multi_exp(zip(blocklist.iter().map(|(h, _)| h), ai.iter()), blocklist.len());
        let big_h = big_h0 + g1_multi_exp(zip(blocklist.iter().map(|(_, h)| h), ai.iter()), blocklist.len());

        // the subprotocol starts here
        let a = r * rev;
        let b = -r;

        // Therefore:
        // h0 * a + big_h0 * b = h0 * (r * rev) + h0 * rev * (-r) = G1_0 (n.e. in G1)

        // blinding factors
        let ra = Scalar::random(&mut rng);
        let rb = Scalar::random(&mut rng);

        let big_r = h * ra + big_h * rb;
        // let com = h * a + big_h * b;

        //let challenge = hash_challenge([&com0, &com_c].into_iter().chain(coms.iter()), empty(), empty(), &seed)?;
        let challenge = hash_challenge([&big_r, &h, &big_h].into_iter().chain(com_aux.iter()), empty(), empty(), &seed)?;

        // responses
        let sa = ra + challenge * a;
        let sb = rb + challenge * b;

        Ok(NonRevocationProof { h0, big_h0, com_aux, challenge, sa, sb })
    }


    pub fn create_disclosure_proof(&mut self, epoch: u64, blocklist: &Vec<(G1Projective, G1Projective)>, mut rng: impl RngCore) -> Result<(HouseholdDisclosureProof, Scalar)> {

        // We have 4 commitments to compute in this variant of the disclosure proof.

        // Main commitment identical to the one is a disclosure proof with 3 hidden arguments and none disclosed.
        let ts = Scalar::random(&mut rng);
        let rs = Scalar::random(&mut rng);

        let s1 = self.credential.signature.sigma1;
        let s2 = self.credential.signature.sigma2;

        let sp1 = s1 * rs;
        let sp2 = (s2 + (s1 * ts)) * rs;

        let sp1a = sp1.to_affine();

        // choose randomizers
        let rt = Scalar::random(&mut rng);
        let rsh = Scalar::random(&mut rng);
        let rvh = Scalar::random(&mut rng);
        let rent = Scalar::random(&mut rng);

        // compute first commitment
        let com = pairing(&sp1a, &self.pk.gt.to_affine()) * rt +
            zip(self.pk.gty.iter(), [&rsh, &rvh, &rent].into_iter()).map(
                |(gty, ra,)|
                pairing(&sp1a, &gty.to_affine()) * ra
            ).sum::<Gt>();

        // Tau's commitment
        let tau = G1Projective::hash_to_curve(&epoch.to_le_bytes(), &[0x3], &[0x5, 0xb]) * self.credential.attributes[ATTR_IDX_SECRET_HOUSEHOLD];
        let com_tau = G1Projective::hash_to_curve(&epoch.to_le_bytes(), &[0x3], &[0x5, 0xb]) * rsh;

        // Entitlement comitment's commitment
        let (com_ent, r) = self.pedersen_params.commit(&self.credential.attributes[ATTR_IDX_ENTITLEMENT], &mut rng);
        let (com_com, rr) = self.pedersen_params.commit(&rent, &mut rng);

        let non_revocation_proof = self.create_non_revocation_proof(&self.credential.attributes[ATTR_IDX_REVOCATION], &blocklist, &mut rng)?;

        // revocation's commitment
        let h0 = &non_revocation_proof.h0;
        let com_h = h0 * rvh;

        // Shamir's heuristic
        let challenge = hash_challenge(
            [&sp1, &sp2, &com_tau, &com_com, &com_h].into_iter(),
            [&self.pk.gt].into_iter().chain(self.pk.gty.iter()),
            [&com].into_iter(),
            &[]
        )?;

        // compute responses
        let st = rt + challenge * ts;
        let ssh = rsh + challenge * self.credential.attributes[ATTR_IDX_SECRET_HOUSEHOLD];
        let svh = rvh + challenge * self.credential.attributes[ATTR_IDX_REVOCATION];
        let sent = rent + challenge * self.credential.attributes[ATTR_IDX_ENTITLEMENT];
        let sr = rr + challenge * r;

        Ok(
            (
                HouseholdDisclosureProof{
                    sigma1: sp1,
                    sigma2: sp2,
                    tau,
                    non_revocation_proof,
                    com_ent,
                    challenge,
                    st,
                    ssh,
                    svh,
                    sent,
                    sr
                },
                r
            )
        )
    }
}


impl AuditProof {
    pub fn verify(&self, pedersen_params: &PedersenParams, pk: &PublicKey<3>, blocklist: &Vec<(G1Projective, G1Projective)>, epoch: u64) -> Result<bool> {
        let distr = DistributionStation::new(pedersen_params);
        let mut tags: HashSet<[u8; 48]> = HashSet::with_capacity(self.registers.len());
        let mut com_sum = G1Projective::identity();
        for proof in self.registers.iter() {
            distr.verify_disclosure_proof(pk, epoch, blocklist, proof)?;
            if ! tags.insert(proof.tau.to_compressed()) {
                return Ok(false);
            }

            com_sum += proof.com_ent;
        }

        Ok(pedersen_params.verify(&self.ent_sum, &com_sum, &self.r_sum))
    }
}


#[cfg(test)]
mod tests {
    use blstrs::{Scalar, G1Projective};
    use group::Group;
    use group::ff::Field;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::{SeedableRng};

    use super::{ATTR_IDX_ENTITLEMENT, RegistrationStation, HouseholdPhoneBuilder, DistributionStation};


    #[test]
    fn full_circuit() {
        let mut rng = ChaCha20Rng::seed_from_u64(42 as u64);
        let mut registration_station = RegistrationStation::new(&mut rng);
        let mut distribution_station = DistributionStation::new(&registration_station.pedersen_params);
        let pk = registration_station.register("foo", &Scalar::from(1234u64), &mut rng).unwrap();

        let builder = HouseholdPhoneBuilder::new(&pk, &mut rng);
        let (request, state) = builder.issue_request(&mut rng).unwrap();
        let signature = registration_station.sign_issue_request("foo", &request, &mut rng).unwrap();
        let mut phone = builder.unblind(&signature, &state, &registration_station.pedersen_params).unwrap();

        let epoch = 1668172689u64;

        let (proof, r) = phone.create_disclosure_proof(epoch, &registration_station.blocklist, &mut rng).unwrap();
        assert!(distribution_station.verify_entitlement(&phone.credential.attributes[ATTR_IDX_ENTITLEMENT], &proof.com_ent, &r));
        assert!(distribution_station.verify_disclosure_proof(&pk, epoch, &registration_station.blocklist, &proof).unwrap());

        distribution_station.register_record(&proof, &phone.credential.attributes[ATTR_IDX_ENTITLEMENT], &r);
        let audit = distribution_station.create_audit_proof().unwrap();
        let is_valid = audit.verify(&registration_station.pedersen_params, &pk, &registration_station.blocklist, epoch).unwrap();
        assert!(is_valid);
    }


    #[test]
    fn non_revocation_should_fails_if_blocklists_mismatch() {
        let mut rng = ChaCha20Rng::seed_from_u64(42 as u64);

        let mut registration_station = RegistrationStation::new(&mut rng);
        let distribution_station = DistributionStation::new(&registration_station.pedersen_params);
        let pk = registration_station.register("foo", &Scalar::from(1234u64), &mut rng).unwrap();

        let builder = HouseholdPhoneBuilder::new(&pk, &mut rng);
        let (request, state) = builder.issue_request(&mut rng).unwrap();
        let signature = registration_station.sign_issue_request("foo", &request, &mut rng).unwrap();
        let phone = builder.unblind(&signature, &state, &registration_station.pedersen_params).unwrap();

        let blocklist_a: Vec<(G1Projective, G1Projective)> = vec![
            (G1Projective::random(&mut rng), G1Projective::random(&mut rng)),
            (G1Projective::random(&mut rng), G1Projective::random(&mut rng)),
            (G1Projective::random(&mut rng), G1Projective::random(&mut rng)),
        ];

        let blocklist_b: Vec<(G1Projective, G1Projective)> = vec![
            (G1Projective::random(&mut rng), G1Projective::random(&mut rng)),
            (G1Projective::random(&mut rng), G1Projective::random(&mut rng)),
        ];

        let rev = Scalar::random(&mut rng);

        let nrp = phone.create_non_revocation_proof(&rev, &blocklist_a, &mut rng).unwrap();
        let err = distribution_station.verify_non_revocation_proof(&blocklist_b, &nrp);

        assert!(err.is_err());

    }
}
