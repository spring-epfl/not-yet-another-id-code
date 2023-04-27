use blstrs::{Scalar, G1Projective};
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use group::Group;
use group::ff::Field;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use pribad_crypto::pedersen::PedersenParams;
use pribad_crypto::pointcheval_sanders::PrivateKey;
use pribad_crypto::smartphone::{RegistrationStation, HouseholdPhoneBuilder, DistributionStation};

pub fn bench_pedersen(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(42 as u64);
    c.bench_function("pedersen_1_generate_parameters", |b| b.iter(|| PedersenParams::new(black_box(&mut rng))));

    let params = PedersenParams::new(&mut rng);
    let message = Scalar::random(&mut rng);

    c.bench_function("pedersen_2_compute_commitment", |b| b.iter(|| params.commit(black_box(&message), black_box(&mut rng))));

    let (commitment, r) = params.commit(&message, &mut rng);

    c.bench_function("pedersen_3_validate_commitment", |b| b.iter(|| params.verify(black_box(&message), black_box(&commitment), black_box(&r))));
}

pub fn bench_pointcheval_sanders(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(42 as u64);

    c.bench_function("pointchevalsanders_1_generate_key_pair", |b| b.iter(||PrivateKey::<3>::new(black_box(&mut rng))));

    let sk: PrivateKey<3> = PrivateKey::new(&mut rng).unwrap();
    let pk = &sk.public_key;

    let user_params = [Some(Scalar::random(&mut rng)), Some(Scalar::random(&mut rng)), None];
    let issuer_params = [None, None, Some(Scalar::random(&mut rng))];
    let disclosed_attributes = [false, false, false];

    c.bench_function("pointchevalsanders_2_issue_request", |b| b.iter(|| pk.issue_request(black_box(&user_params), black_box(&mut rng))));

    let (req, blinding_param) = pk.issue_request(&user_params, &mut rng).unwrap();

    c.bench_function("pointchevalsanders_3_sign_request", |b| b.iter(|| sk.sign_issue_request(black_box(&req), black_box(&issuer_params), black_box(&mut rng))));

    let blinded = sk.sign_issue_request(&req, &issuer_params, &mut rng).unwrap();

    c.bench_function("pointchevalsanders_4_unblind_blinded_credential", |b| b.iter(|| blinded.unblind(black_box(&blinding_param))));

    let cred = blinded.unblind(&blinding_param).unwrap();

    c.bench_function("pointchevalsanders_5_create_disclosure_proof", |b| b.iter(|| pk.create_disclosure_proof(black_box(&cred), black_box(&disclosed_attributes), black_box(&mut rng))));

    let dp = pk.create_disclosure_proof(&cred, &disclosed_attributes, &mut rng).unwrap();

    c.bench_function("pointchevalsanders_6_verify_disclosure_proof", |b| b.iter(|| pk.verify_disclosure_proof(black_box(&dp))));
}

pub fn bench_smartphone(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(42 as u64);

    let mut registration_station = RegistrationStation::new(&mut rng);
    let distribution_station = DistributionStation::new(&registration_station.pedersen_params);
    let pk = registration_station.register("foo", &Scalar::from(1234u64), &mut rng).unwrap();

    let builder = HouseholdPhoneBuilder::new(&pk, &mut rng);
    let (request, state) = builder.issue_request(&mut rng).unwrap();
    let signature = registration_station.sign_issue_request("foo", &request, &mut rng).unwrap();
    let mut phone = builder.unblind(&signature, &state, &registration_station.pedersen_params).unwrap();

    let epoch = 1668172689u64;

    let blocklist: Vec<(G1Projective, G1Projective)> = Vec::new();

    c.bench_function("smartphone_1_create_disclosure_proof", |b| b.iter(||
        phone.create_disclosure_proof(black_box(epoch), black_box(&blocklist), black_box(&mut rng))
    ));

    let mut group = c.benchmark_group("smartphone_1b_create_non_revocation_proof");
    group.sample_size(10);

    for i in 1..16 {
        let n = 2u64 << i;
        let rev = Scalar::random(&mut rng);
        let bl: Vec<(G1Projective, G1Projective)> = (1..n).map(|_| (G1Projective::random(&mut rng), G1Projective::random(&mut rng))).collect();

        group.bench_with_input(
            BenchmarkId::new("blocklist_size", n),
            &(rev, bl),
            |b, (rev, bl)| b.iter(
                ||
                phone.create_non_revocation_proof(&rev, &bl, black_box(&mut rng))
            )
        );
    }
    group.finish();


    let (proof, r) = phone.create_disclosure_proof(epoch, &blocklist, &mut rng).unwrap();

    c.bench_function("smartphone_2_verify_entitlement", |b| b.iter(||
        distribution_station.verify_entitlement(black_box(&phone.credential.attributes[2]), black_box(&proof.com_ent), black_box(&r))
    ));


    distribution_station.verify_entitlement(&phone.credential.attributes[2], &proof.com_ent, &r);

    c.bench_function("smartphone_3_disclosure_proof", |b| b.iter(||
        distribution_station.verify_disclosure_proof(black_box(&pk), black_box(epoch), black_box(&blocklist), black_box(&proof))
    ));

    let mut group = c.benchmark_group("smartphone_3b_verify_non_revocation_proof");
    group.sample_size(10);

    for i in 1..16 {
        let n = 2u64 << i;
        let rev = Scalar::random(&mut rng);
        let bl: Vec<(G1Projective, G1Projective)> = (1..n).map(|_| (G1Projective::random(&mut rng), G1Projective::random(&mut rng))).collect();
        let nrp = phone.create_non_revocation_proof(&rev, &bl, black_box(&mut rng)).unwrap();

        group.bench_with_input(
            BenchmarkId::new("blocklist_size", n),
            &(nrp, bl),
            |b, (nrp, bl)| b.iter(
                ||
                distribution_station.verify_non_revocation_proof(&bl, &nrp)
            )
        );
    }
    group.finish();


}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets = bench_pedersen, bench_pointcheval_sanders, bench_smartphone
}

criterion_main!(benches);
