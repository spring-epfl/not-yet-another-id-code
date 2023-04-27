#![allow(non_snake_case)]
//Removes the unsafe FFI warnings
#![allow(improper_ctypes)]
#![allow(improper_ctypes_definitions)]
// This is the interface to the JVM that we'll call the majority of our
// methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native
// function. They carry extra lifetime information to prevent them escaping
// this context and getting used after being GC'd.
use jni::objects::{JClass, JString};

// This is just a pointer. We'll be returning it from our function. We
// can't return one of the objects with lifetime information because the
// lifetime checker won't let us.

use jni::sys::{jstring, jint, jbyteArray};
use mcl_rust::*;
use std::vec::Vec;
use sha2::{Sha256, Digest};
use std::time::{SystemTime};

use protobuf::Message;
mod protos;
use protos::generated_with_native::protocol::PublicKeyProto;
use protos::generated_with_native::protocol::PrivateKeyProto;
use protos::generated_with_native::protocol::KeyPairProto;
use protos::generated_with_native::protocol::CommitmentAndProofKnowledgeWithBlindingFactorProto;
use protos::generated_with_native::protocol::CommitmentAndProofKnowledgeWithoutBlindingFactorProto;
use protos::generated_with_native::protocol::AttributesProto;
use protos::generated_with_native::protocol::SignatureProto;
use protos::generated_with_native::protocol::CredentialProto;
use protos::generated_with_native::protocol::DisclosureProofRecipientProto;
use protos::generated_with_native::protocol::TokenProto;
use protos::generated_with_native::protocol::DisclosureProofVerifierProto;
use protos::generated_with_native::protocol::AlreadySeenCredentialsProto;
use protos::generated_with_native::protocol::RevocatedTokensProto;
use protos::generated_with_native::protocol::TokenAndRevocationValueProto;
use protos::generated_with_native::protocol::PowersForBlacklistProto;
use protos::generated_with_native::protocol::BlacBatchProtocolProverOutputProto;
use protos::generated_with_native::protocol::BlacResponsesProto;
use protos::generated_with_native::protocol::DisclosureProofResultProto;


#[repr(C)]
pub struct PublicKey {
    pub g: G1,
    pub g_powers: Vec<G1>,
    pub g_tilde: G2,
    pub x_tilde: G2,
    pub g_tilde_powers: Vec<G2>
}

#[repr(C)]
pub struct PrivateKey {
    pub x: Fr,
    pub g_power_x: G1,
    pub y_i: Vec<Fr>
}

#[repr(C)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: PrivateKey,
    pub is_valid: bool
}

#[repr(C)]
pub struct Commitment {
    pub C: G1,
    pub t: Fr,
    pub is_valid: bool
}

#[repr(C)]
pub struct NonInteractivePK {
    pub C: G1,
    pub challenge: Fr,
    pub responses: Vec<Fr>,
    pub R: G1,
    pub is_valid: bool
}

#[repr(C)]
pub struct Signature {
    pub sigma_one: G1,
    pub sigma_two: G1
}

#[repr(C)]
pub struct DisclosureProofRecipient {
    pub C: GT,
    pub challenge: Fr,
    pub R_commitment: GT,
    pub R_pseudonym: G1,
    pub R_revocation_value: G1,
    pub responses: Vec<Fr>,
    pub randomized_signature: Signature,
    pub s_hss: Fr,
    pub s_rev_value: Fr,
    pub token: Token,
    pub pseudonym: G1,
    pub base_revocation_value: G1
}

#[repr(C)]
pub struct DisclosureProofForVerifier {
    pub randomized_signature: Signature,
    pub C: GT,
    pub challenge: Fr,
    pub responses: Vec<Fr>,
    pub R_commitment: GT,
    pub R_pseudonym: G1,
    pub R_revocation_value: G1,
    pub nb_issuer_attributes: jint,
    pub nb_recipient_attributes: jint,
    pub pseudonym: G1,
    pub powered_rev_value: G1,
    pub epoch: G1,
    pub s_hss: Fr,
    pub s_rev_value: Fr,
    pub base_rev_value: G1,
}


#[repr(C)]
pub struct Token {
    pub h: G1,
    pub H: G1
}

#[repr(C)]
pub struct BlacResponses {
    u1: Fr,
    u2: Fr
}

#[repr(C)]
pub struct BlacBatchProtocolProverOutput {
    pub responses: BlacResponses,
    pub auxiliary_commitments: Vec<G1>,
    pub R: G1,
    pub token: Token,
    pub challenge: Fr
}

#[repr(C)]
pub struct DisclosureProofResult {
    pub already_seen_pseudonyms: Vec<G1>,
    pub is_valid_proof: bool
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_printCredentials(env: JNIEnv, _:JClass, credentials: jbyteArray) -> () {
    let credential_bytes = env.convert_byte_array(credentials).expect("Could not load credentials");
    let credential = CredentialProto::parse_from_bytes(&credential_bytes).unwrap();
    for i in 0..credential.attributes.len() {
        println!("{:?}", credential.attributes[i as usize]);
    }
}

//==============================ISSUANCE PROTOCOL====================================================
#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_keygenJava(env: JNIEnv, _: JClass, nb_attributes: jint) -> jbyteArray {
    let keys = Java_ch_epfl_rcadsprototype_Crypto_keygen(nb_attributes);
    let mut pk = PublicKeyProto::new();
    pk.g = keys.pk.g.serialize();
    pk.g_tilde = keys.pk.g_tilde.serialize();
    pk.x_tilde = keys.pk.x_tilde.serialize();
    for i in 0..nb_attributes {
        pk.g_powers.push(keys.pk.g_powers[i as usize].serialize());
        pk.g_tilde_powers.push(keys.pk.g_tilde_powers[i as usize].serialize());
    }

    let mut sk = PrivateKeyProto::new();
    sk.x = keys.sk.x.serialize();
    sk.g_power_x = keys.sk.g_power_x.serialize();
    for i in 0..nb_attributes {
        sk.y_i.push(keys.sk.y_i[i as usize].serialize());
    }

    let mut keyPair = KeyPairProto::new();
    keyPair.pk = env.convert_byte_array(convertVecToByteArray(env, pk.write_to_bytes().unwrap())).expect("Could not convert public key");
    keyPair.sk = env.convert_byte_array(convertVecToByteArray(env, sk.write_to_bytes().unwrap())).expect("Could not convert private key");

    return convertVecToByteArray(env, keyPair.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getAttributesJava(env: JNIEnv, _: JClass, nb_recipient_attributes: jint) -> jbyteArray {
    let mut attributes_proto = AttributesProto::new();
    for _ in 0..nb_recipient_attributes {
        let mut fr_elem = Fr::zero();
        fr_elem.set_by_csprng();
        attributes_proto.attributes.push(fr_elem.serialize());
    }

    return convertVecToByteArray(env, attributes_proto.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getUserCommitmentJava(env: JNIEnv, _: JClass, issuer_pk: jbyteArray, recipient_attributes: jbyteArray, nb_recipient_attributes: jint, nb_issuer_attributes: jint) -> jbyteArray {
    /*Translate bytes to rust structures*/
    let rust_issuer_pk_bytes = env.convert_byte_array(issuer_pk).expect("Could not load issuer's pk bytes");
    let rust_issuer_pk = PublicKeyProto::parse_from_bytes(&rust_issuer_pk_bytes).unwrap();
    let mut issuer_pk_g = unsafe{G1::uninit()};
    let mut issuer_pk_g_powers: Vec<G1> = Vec::new();
    let mut issuer_pk_x_tilde: G2 = unsafe{G2::uninit()};
    let mut issuer_pk_g_tilde: G2 = unsafe{G2::uninit()};
    let mut issuer_pk_g_tilde_powers: Vec<G2> = Vec::new();
    issuer_pk_g.deserialize(&rust_issuer_pk.g);
    issuer_pk_x_tilde.deserialize(&rust_issuer_pk.x_tilde);
    issuer_pk_g_tilde.deserialize(&rust_issuer_pk.g_tilde);
    let total_nb_attributes = nb_recipient_attributes + nb_issuer_attributes;
    for i in 0..total_nb_attributes {
        let mut g1_element = unsafe{G1::uninit()};
        g1_element.deserialize(&rust_issuer_pk.g_powers[i as usize]);
        issuer_pk_g_powers.push(g1_element);
        let mut g2_element = unsafe{G2::uninit()};
        g2_element.deserialize(&rust_issuer_pk.g_tilde_powers[i as usize]);
        issuer_pk_g_tilde_powers.push(g2_element);
    }
    let issuer_pk_for_method = PublicKey{g: issuer_pk_g, g_powers: issuer_pk_g_powers, g_tilde: issuer_pk_g_tilde, x_tilde: issuer_pk_x_tilde, g_tilde_powers: issuer_pk_g_tilde_powers};

    let rust_recipient_attributes_bytes = env.convert_byte_array(recipient_attributes).expect("Could not load recipient's attributes as bytes");
    let rust_recipient_attributes = AttributesProto::parse_from_bytes(&rust_recipient_attributes_bytes).unwrap();
    let mut recipient_attributes_for_method: Vec<Fr> = Vec::new();
    for i in 0..nb_recipient_attributes {
        let mut attribute = Fr::zero();
        attribute.deserialize(&rust_recipient_attributes.attributes[i as usize]);
        recipient_attributes_for_method.push(attribute);
    }

    /*Call rust method and obtain output*/
    let user_commitment: Commitment = Java_ch_epfl_rcadsprototype_Crypto_getUserCommitment(&issuer_pk_for_method, &recipient_attributes_for_method, nb_recipient_attributes, nb_issuer_attributes);
    let t_bytes = user_commitment.t.serialize();
    let non_interactive_pk: NonInteractivePK = Java_ch_epfl_rcadsprototype_Crypto_getNonInteractivePK(user_commitment, &issuer_pk_for_method, String::new(), &recipient_attributes_for_method, nb_recipient_attributes, nb_issuer_attributes);

    /*Translate it back to Java bytes*/
    let mut commitment_proto = CommitmentAndProofKnowledgeWithBlindingFactorProto::new();
    commitment_proto.C = non_interactive_pk.C.serialize();
    commitment_proto.R = non_interactive_pk.R.serialize();
    commitment_proto.challenge = non_interactive_pk.challenge.serialize();
    for i in 0..nb_recipient_attributes + 1 {
        commitment_proto.responses.push(non_interactive_pk.responses[i as usize].serialize());
    }
    commitment_proto.t = t_bytes;

    return convertVecToByteArray(env, commitment_proto.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_removeBlindingFactorJava(env: JNIEnv, _: JClass, proof_with_blinding: jbyteArray, nb_recipient_attributes: jint) -> jbyteArray {
    let rust_pk_with_blinding_bytes = env.convert_byte_array(proof_with_blinding).expect("Could not load proof of knowledge with blinding factor");
    let rust_pk_with_blinding = CommitmentAndProofKnowledgeWithBlindingFactorProto::parse_from_bytes(&rust_pk_with_blinding_bytes).unwrap();

    let mut proof_without_blinding_factor = CommitmentAndProofKnowledgeWithoutBlindingFactorProto::new();
    proof_without_blinding_factor.C = rust_pk_with_blinding.C;
    proof_without_blinding_factor.challenge = rust_pk_with_blinding.challenge;
    proof_without_blinding_factor.R = rust_pk_with_blinding.R;
    for i in 0..nb_recipient_attributes + 1 {
        let responses_bytes = rust_pk_with_blinding.responses[i as usize].clone();
        proof_without_blinding_factor.responses.push(responses_bytes);
    }
    return convertVecToByteArray(env, proof_without_blinding_factor.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_verifyUserCommitmentJava(env: JNIEnv, _: JClass, non_interactive_pk: jbyteArray, issuer_pk: jbyteArray, nb_recipient_attributes: jint, nb_issuer_attributes: jint) -> jstring {
    let rust_non_interactive_pk_bytes = env.convert_byte_array(non_interactive_pk).expect("Could not load pk bytes");
    let rust_non_interactive_pk = CommitmentAndProofKnowledgeWithoutBlindingFactorProto::parse_from_bytes(&rust_non_interactive_pk_bytes).unwrap();
    let mut non_interactive_pk_C = unsafe{G1::uninit()};
    let mut non_interactive_pk_R = unsafe{G1::uninit()};
    let mut non_interactive_pk_challenge = Fr::zero();
    let mut non_interactive_pk_responses: Vec<Fr> = Vec::new();
    non_interactive_pk_C.deserialize(&rust_non_interactive_pk.C);
    non_interactive_pk_R.deserialize(&rust_non_interactive_pk.R);
    non_interactive_pk_challenge.deserialize(&rust_non_interactive_pk.challenge);
    for i in 0..nb_recipient_attributes + 1 {
        let mut fr_elem = Fr::zero();
        fr_elem.deserialize(&rust_non_interactive_pk.responses[i as usize]);
        non_interactive_pk_responses.push(fr_elem);
    }
    let non_interactive_pk_for_method = NonInteractivePK{C: non_interactive_pk_C, challenge: non_interactive_pk_challenge, responses: non_interactive_pk_responses, R: non_interactive_pk_R, is_valid: true};

    let rust_issuer_pk_bytes = env.convert_byte_array(issuer_pk).expect("Could not load issuer's pk bytes");
    let rust_issuer_pk = PublicKeyProto::parse_from_bytes(&rust_issuer_pk_bytes).unwrap();
    let mut issuer_pk_g = unsafe{G1::uninit()};
    let mut issuer_pk_g_powers: Vec<G1> = Vec::new();
    let mut issuer_pk_x_tilde: G2 = unsafe{G2::uninit()};
    let mut issuer_pk_g_tilde: G2 = unsafe{G2::uninit()};
    let mut issuer_pk_g_tilde_powers: Vec<G2> = Vec::new();
    issuer_pk_g.deserialize(&rust_issuer_pk.g);
    issuer_pk_x_tilde.deserialize(&rust_issuer_pk.x_tilde);
    issuer_pk_g_tilde.deserialize(&rust_issuer_pk.g_tilde);
    let total_nb_attributes = nb_recipient_attributes + nb_issuer_attributes;
    for i in 0..total_nb_attributes {
        let mut g1_element = unsafe{G1::uninit()};
        g1_element.deserialize(&rust_issuer_pk.g_powers[i as usize]);
        issuer_pk_g_powers.push(g1_element);
        let mut g2_element = unsafe{G2::uninit()};
        g2_element.deserialize(&rust_issuer_pk.g_tilde_powers[i as usize]);
        issuer_pk_g_tilde_powers.push(g2_element);
    }
    let issuer_pk_for_method = PublicKey{g: issuer_pk_g, g_powers: issuer_pk_g_powers, g_tilde: issuer_pk_g_tilde, x_tilde: issuer_pk_x_tilde, g_tilde_powers: issuer_pk_g_tilde_powers};

    /*Call Rust method with translated args*/
    let validProof = Java_ch_epfl_rcadsprototype_Crypto_verifyPK(non_interactive_pk_for_method, &issuer_pk_for_method, nb_recipient_attributes, nb_issuer_attributes);

    if validProof {
        return env.new_string(format!("True"))
        .expect("Couldn't create java string!").into_inner();
    }
    else {
        return env.new_string(format!("False"))
        .expect("Couldn't create java string!").into_inner();
    }
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_issuerSigningJava(env: JNIEnv, _: JClass, issuer_pk: jbyteArray, issuer_sk: jbyteArray, proof_knowledge: jbyteArray, nb_issuer_attributes: jint, issuer_attributes: jbyteArray, nb_recipient_attributes: jint) -> jbyteArray {
    /*1. Map all byte arrays to their corresponding Rust structures*/
    //Public key
    let rust_issuer_pk_bytes = env.convert_byte_array(issuer_pk).expect("Could not load issuer public key");
    let rust_issuer_pk = PublicKeyProto::parse_from_bytes(&rust_issuer_pk_bytes).unwrap();
    let mut issuer_pk_g = unsafe{G1::uninit()};
    let mut issuer_pk_g_powers: Vec<G1> = Vec::new();
    let mut issuer_pk_x_tilde: G2 = unsafe{G2::uninit()};
    let mut issuer_pk_g_tilde: G2 = unsafe{G2::uninit()};
    let mut issuer_pk_g_tilde_powers: Vec<G2> = Vec::new();
    issuer_pk_g.deserialize(&rust_issuer_pk.g);
    issuer_pk_x_tilde.deserialize(&rust_issuer_pk.x_tilde);
    issuer_pk_g_tilde.deserialize(&rust_issuer_pk.g_tilde);
    let total_nb_attributes = nb_recipient_attributes + nb_issuer_attributes;
    for i in 0..total_nb_attributes {
        let mut g1_element = unsafe{G1::uninit()};
        g1_element.deserialize(&rust_issuer_pk.g_powers[i as usize]);
        issuer_pk_g_powers.push(g1_element);
        let mut g2_element = unsafe{G2::uninit()};
        g2_element.deserialize(&rust_issuer_pk.g_tilde_powers[i as usize]);
        issuer_pk_g_tilde_powers.push(g2_element);
    }
    let issuer_pk_for_method = PublicKey{g: issuer_pk_g, g_powers: issuer_pk_g_powers, g_tilde: issuer_pk_g_tilde, x_tilde: issuer_pk_x_tilde, g_tilde_powers: issuer_pk_g_tilde_powers};

    //Private key
    let rust_issuer_sk_bytes = env.convert_byte_array(issuer_sk).expect("Could not load issuer private key");
    let rust_issuer_sk = PrivateKeyProto::parse_from_bytes(&rust_issuer_sk_bytes).unwrap();
    let mut issuer_sk_x = Fr::zero();
    issuer_sk_x.deserialize(&rust_issuer_sk.x);
    let mut issuer_sk_g_power_x = unsafe{G1::uninit()};
    issuer_sk_g_power_x.deserialize(&rust_issuer_sk.g_power_x);
    let mut issuer_sk_y_i: Vec<Fr> = Vec::new();
    let total_nb_attributes = nb_recipient_attributes + nb_issuer_attributes;
    for i in 0..total_nb_attributes {
        let mut y_i = Fr::zero();
        y_i.deserialize(&rust_issuer_sk.y_i[i as usize]);
        issuer_sk_y_i.push(y_i);
    }
    let issuer_sk_for_method = PrivateKey{x: issuer_sk_x, g_power_x: issuer_sk_g_power_x, y_i: issuer_sk_y_i};


    //Proof of knowledge to extract C
    let rust_proof_knowledge_bytes = env.convert_byte_array(proof_knowledge).expect("Could not load recipient's proof of knowledge");
    let rust_proof_knowledge = CommitmentAndProofKnowledgeWithoutBlindingFactorProto::parse_from_bytes(&rust_proof_knowledge_bytes).unwrap();
    let mut non_interactive_pk_C = unsafe{G1::uninit()};
    non_interactive_pk_C.deserialize(&rust_proof_knowledge.C);

    //Issuer attributes
    let mut java_signature = SignatureProto::new();
    let rust_issuer_attributes_bytes = env.convert_byte_array(issuer_attributes).expect("Could not load issuer attributes");
    let rust_issuer_attributes = AttributesProto::parse_from_bytes(&rust_issuer_attributes_bytes).unwrap();
    let mut issuer_attributes_for_method: Vec<Fr> = Vec::new();
    for i in 0..nb_issuer_attributes {
        let mut fr_elem = Fr::zero();
        fr_elem.deserialize(&rust_issuer_attributes.attributes[i as usize]);
        java_signature.attributes.push(fr_elem.serialize());
        issuer_attributes_for_method.push(fr_elem);
    }

    /*2.Call Rust method*/
    let signature = Java_ch_epfl_rcadsprototype_Crypto_issuerSigning(&issuer_pk_for_method, issuer_sk_for_method, non_interactive_pk_C, nb_issuer_attributes, &issuer_attributes_for_method);

    /*3.Translate back to Java bytes */
    java_signature.sigma_one = signature.sigma_one.serialize();
    java_signature.sigma_two = signature.sigma_two.serialize();
    return convertVecToByteArray(env, java_signature.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_unblindSignatureJava(env: JNIEnv, _:JClass, issuer_signature: jbyteArray, commitment_with_blinding_factor: jbyteArray, recipient_attributes: jbyteArray, nb_issuer_attributes: jint, nb_recipient_attributes: jint) -> jbyteArray {
    let rust_signature_bytes = env.convert_byte_array(issuer_signature).expect("Could not load issuer's signature");
    let rust_signature = SignatureProto::parse_from_bytes(&rust_signature_bytes).unwrap();

    let mut sigma_one = unsafe{G1::uninit()};
    let mut sigma_two = unsafe{G1::uninit()};
    sigma_one.deserialize(&rust_signature.sigma_one);
    sigma_two.deserialize(&rust_signature.sigma_two);
    let signature_for_method = Signature{sigma_one: sigma_one, sigma_two: sigma_two};

    let rust_commitment_bytes = env.convert_byte_array(commitment_with_blinding_factor).expect("Could not load commitment from recipient");
    let rust_commitment = CommitmentAndProofKnowledgeWithBlindingFactorProto::parse_from_bytes(&rust_commitment_bytes).unwrap();

    let mut t = Fr::zero();
    t.deserialize(&rust_commitment.t);

    let unblinded_signature = Java_ch_epfl_rcadsprototype_Crypto_unblindSignature(signature_for_method, t);
    let mut return_credential = CredentialProto::new();
    return_credential.sigma_one = unblinded_signature.sigma_one.serialize();
    return_credential.sigma_two = unblinded_signature.sigma_two.serialize();

    for i in 0..nb_issuer_attributes {
        let attribute_bytes = rust_signature.attributes[i as usize].clone();
        return_credential.attributes.push(attribute_bytes);
    }

    let rust_recipient_attributes_bytes = env.convert_byte_array(recipient_attributes).expect("Could not load recipients attributes");
    let rust_recipient_attributes = AttributesProto::parse_from_bytes(&rust_recipient_attributes_bytes).unwrap();
    for i in 0..nb_recipient_attributes {
        let attribute_bytes = rust_recipient_attributes.attributes[i as usize].clone();
        return_credential.attributes.push(attribute_bytes);
    }
    return convertVecToByteArray(env, return_credential.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getPublicKeyJava(env: JNIEnv, _: JClass, keys: jbyteArray) -> jbyteArray {
    let keys = env.convert_byte_array(keys).expect("Could not load protobuf keys");
    let keyPair = KeyPairProto::parse_from_bytes(&keys).unwrap();
    let publicKey = PublicKeyProto::parse_from_bytes(&keyPair.pk).unwrap();
    return convertVecToByteArray(env, publicKey.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getPrivateKeyJava(env: JNIEnv, _: JClass, keys: jbyteArray) -> jbyteArray {
    let keys = env.convert_byte_array(keys).expect("Could not load protobuf keys");
    let keyPair = KeyPairProto::parse_from_bytes(&keys).unwrap();
    let privateKey = PrivateKeyProto::parse_from_bytes(&keyPair.sk).unwrap();
    return convertVecToByteArray(env, privateKey.write_to_bytes().unwrap());
}

#[no_mangle]
//pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_keygen(_env: JNIEnv, _: JClass, _input: JString, nb_attributes: jint) -> KeyPair {
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_keygen(nb_attributes: jint) -> KeyPair {
    let mut g1_generator = unsafe {G1::uninit()};
    G1::set_str(&mut g1_generator, 
        "1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10);
    let mut g = unsafe {G1::uninit()};
    let mut random_elem_fp = Fr::zero();
    random_elem_fp.set_by_csprng();
    G1::mul(&mut g, &g1_generator, &random_elem_fp);
    let mut g2_generator = unsafe{G2::uninit()};
    G2::set_str(&mut g2_generator, 
        "1 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582", 10);
    let mut g_tilde = unsafe{G2::uninit()};
    random_elem_fp.set_by_csprng();
    G2::mul(&mut g_tilde, &g2_generator, &random_elem_fp);

    let mut x = Fr::zero();
    x.set_by_csprng();

    let mut g_power_x = unsafe {G1::uninit()};
    G1::mul(&mut g_power_x, &g, &x);

    let mut y_i: Vec<Fr> = Vec::new(); 
    for _ in 0..nb_attributes {
        let mut elem = Fr::zero();
        elem.set_by_csprng();
        y_i.push(elem);
    }
    
    let mut g_powers: Vec<G1> = Vec::new();
    let mut g_tilde_powers: Vec<G2> = Vec::new();

    let mut x_tilde = unsafe{G2::uninit()};
    G2::mul(&mut x_tilde, &g2_generator, &x);

    for i in 0..nb_attributes {
        let mut g1_placeholder = unsafe{G1::uninit()};
        let mut g2_placeholder = unsafe{G2::uninit()};
        G1::mul(&mut g1_placeholder, &g, &y_i[i as usize]);
        g_powers.push(g1_placeholder);
        G2::mul(&mut g2_placeholder, &g_tilde, &y_i[i as usize]);
        g_tilde_powers.push(g2_placeholder);
    }

    let sk = PrivateKey{x: x, g_power_x: g_power_x, y_i: y_i};
    let pk = PublicKey{g: g, g_powers: g_powers, g_tilde: g_tilde, x_tilde: x_tilde, g_tilde_powers: g_tilde_powers};


    return KeyPair{pk: pk, sk: sk, is_valid: true};

}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getUserCommitment(issuer_pk: &PublicKey, recipient_attributes: &Vec<Fr>, nb_recipient_attributes: jint, nb_issuer_attributes: jint) -> Commitment {
    let mut t = Fr::zero();
    t.set_by_csprng();
    let mut C =  unsafe {G1::uninit()};
    G1::mul(&mut C, &issuer_pk.g, &t);

    /*We define our ABC such that the issuer's attributes are a_1..a_n and the 
    recipient attributes are a_n+1..a_m+n*/
    let mut tmp_C = unsafe{G1::uninit()};
    let neutral_elem = G1::zero();
    for i in 0..nb_recipient_attributes {
        let mut y_i_power_a_i = unsafe{G1::uninit()};
        G1::mul(&mut y_i_power_a_i, &issuer_pk.g_powers[(i + nb_issuer_attributes) as usize], &recipient_attributes[i as usize]);
        G1::add(&mut tmp_C, &C, &y_i_power_a_i);
        G1::add(&mut C, &tmp_C, &neutral_elem);
    }

    return Commitment { C: C, t: t, is_valid: true};
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getNonInteractivePK(user_commitment: Commitment, issuer_pk: &PublicKey, message: String, recipient_attributes: &Vec<Fr>, nb_recipient_attributes: jint, nb_issuer_attributes: jint) -> NonInteractivePK {
    let mut t_2 = Fr::zero();
    t_2.set_by_csprng();
    let mut R = unsafe{G1::uninit()};
    G1::mul(&mut R, &issuer_pk.g, &t_2);

    let mut exponents: Vec<Fr> = Vec::new();
    for _ in 0..nb_recipient_attributes {
        let mut random_elem = Fr::zero();
        random_elem.set_by_csprng();
        exponents.push(random_elem);
    }

    let mut hasher = Sha256::new();
    hasher.update(issuer_pk.g.serialize());

    /*Construct the provers commitment */
    let mut tmp_R = unsafe{G1::uninit()};
    let neutral_elem = G1::zero();
    for i in 0..nb_recipient_attributes {
        let mut y_i_power = unsafe{G1::uninit()};
        G1::mul(&mut y_i_power, &issuer_pk.g_powers[(i + nb_issuer_attributes) as usize], &exponents[i as usize]);
        G1::add(&mut tmp_R, &R, &y_i_power);
        G1::add(&mut R, &tmp_R, &neutral_elem);
        hasher.update(b"||");
        hasher.update(issuer_pk.g_powers[(i + nb_issuer_attributes) as usize].serialize());
    }

    /*Finish constructing the challenge */
    hasher.update(b"||");
    hasher.update(user_commitment.C.serialize());
    hasher.update(b"||");
    hasher.update(R.serialize());
    hasher.update(b"||");
    hasher.update(message);
    let hashed_public_values = hasher.finalize();
    let mut challenge = Fr::zero();
    Fr::set_hash_of(&mut challenge, &hashed_public_values);

    /*Construct responses array */
    let mut responses: Vec<Fr> = Vec::new();
    let mut result_subtraction = Fr::zero();
    let mut result_multiplication = Fr::zero();
    Fr::mul(&mut result_multiplication, &user_commitment.t, &challenge);
    Fr::sub(&mut result_subtraction, &t_2, &result_multiplication);
    responses.push(result_subtraction);
    for i in 0..nb_recipient_attributes {
        let mut result_challenge_times_attribute = Fr::zero();
        let mut result_response = Fr::zero();
        Fr::mul(&mut result_challenge_times_attribute, &recipient_attributes[i as usize], &challenge);
        Fr::sub(&mut result_response, &exponents[i as usize], &result_challenge_times_attribute);
        responses.push(result_response);
    }

    let mut copy_commitment = unsafe{G1::uninit()};
    G1::add(&mut copy_commitment, &user_commitment.C, &neutral_elem);
    return NonInteractivePK{C: copy_commitment, challenge: challenge, responses: responses, R: R, is_valid: true};
}


#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_verifyPK(non_interactive_pk: NonInteractivePK, issuer_pk: &PublicKey, nb_recipient_attributes: jint, nb_issuer_attributes: jint) -> bool {
    let mut second_term = unsafe{G1::uninit()};
    let mut tmp_second_term = unsafe{G1::uninit()};
    let mut g_power_response = unsafe{G1::uninit()};
    G1::mul(&mut g_power_response, &issuer_pk.g, &non_interactive_pk.responses[0]);
    G1::add(&mut second_term, &G1::zero(), &g_power_response);

    let neutral_elem = G1::zero();
    for i in 0..nb_recipient_attributes {
        let mut y_i_power_response = unsafe{G1::uninit()};
        G1::mul(&mut y_i_power_response, &issuer_pk.g_powers[(i + nb_issuer_attributes) as usize], &non_interactive_pk.responses[(i + 1) as usize]);
        G1::add(&mut tmp_second_term, &second_term, &y_i_power_response);
        G1::add(&mut second_term, &tmp_second_term, &neutral_elem);
    }

    let mut C_power_challenge = unsafe{G1::uninit()};
    G1::mul(&mut C_power_challenge, &non_interactive_pk.C, &non_interactive_pk.challenge);

    let mut check = unsafe{G1::uninit()};
    G1::add(&mut check, &second_term, &C_power_challenge);
    return check == non_interactive_pk.R;    
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_issuerSigning(issuer_pk: &PublicKey, issuer_sk: PrivateKey, C: G1, nb_issuer_attributes: jint, issuer_attributes: &Vec<Fr>) -> Signature {
    let mut u = Fr::zero();
    u.set_by_csprng();

    let mut sigma_prime_one = unsafe{G1::uninit()};
    G1::mul(&mut sigma_prime_one, &issuer_pk.g, &u);

    let mut sigma_prime_two = unsafe{G1::uninit()};
    G1::add(&mut sigma_prime_two, &C, &issuer_sk.g_power_x);

    let mut tmp_sigma_prime_two = unsafe{G1::uninit()};
    let neutral_element = G1::zero();
    for i in 0..nb_issuer_attributes {
        let mut y_i_power_ai = unsafe{G1::uninit()};
        G1::mul(&mut y_i_power_ai, &issuer_pk.g_powers[i as usize], &issuer_attributes[i as usize]);
        G1::add(&mut tmp_sigma_prime_two, &sigma_prime_two, &y_i_power_ai);
        G1::add(&mut sigma_prime_two, &tmp_sigma_prime_two, &neutral_element);
    }

    let mut sigma_prime_two_power_u = unsafe{G1::uninit()};
    G1::mul(&mut sigma_prime_two_power_u, &sigma_prime_two, &u);

    return Signature{sigma_one: sigma_prime_one, sigma_two: sigma_prime_two_power_u};
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_unblindSignature(issuer_signature: Signature, t: Fr) -> Signature {
    let mut sigma_prime_one_power_minus_t = unsafe{G1::uninit()};
    let mut minus_t = Fr::zero();
    Fr::neg(&mut minus_t, &t);
    G1::mul(&mut sigma_prime_one_power_minus_t, &issuer_signature.sigma_one, &minus_t);

    let mut second_signature_element = unsafe{G1::uninit()};
    G1::add(&mut second_signature_element, &issuer_signature.sigma_two, &sigma_prime_one_power_minus_t);

    return Signature{sigma_one: issuer_signature.sigma_one, sigma_two: second_signature_element};
}

//=======================DISTRIBUTION PROTOCOL=============================================

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getEpochJava(env: JNIEnv, _:JClass) -> jbyteArray {
    let mut random_elem = Fr::zero();
    random_elem.set_by_csprng();
    return convertVecToByteArray(env, random_elem.serialize());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getDisclosureProofJava(env: JNIEnv, _:JClass, issuer_pk: jbyteArray, nb_issuer_attributes: jint, nb_recipient_attributes: jint, credential: jbyteArray, epoch: jbyteArray) -> jbyteArray {
    /*To understand how this works, it is necessary that the revocation value is the last of the issuer's attributes, and the household secret is the last of the recipient attributes.*/
    let rust_issuer_public_key_bytes = env.convert_byte_array(issuer_pk).expect("Could not load the issuer's public key");
    let rust_issuer_pk = PublicKeyProto::parse_from_bytes(&rust_issuer_public_key_bytes).unwrap();
    let mut issuer_pk_g = unsafe{G1::uninit()};
    let mut issuer_pk_g_powers: Vec<G1> = Vec::new();
    let mut issuer_pk_x_tilde: G2 = unsafe{G2::uninit()};
    let mut issuer_pk_g_tilde: G2 = unsafe{G2::uninit()};
    let mut issuer_pk_g_tilde_powers: Vec<G2> = Vec::new();
    issuer_pk_g.deserialize(&rust_issuer_pk.g);
    issuer_pk_x_tilde.deserialize(&rust_issuer_pk.x_tilde);
    issuer_pk_g_tilde.deserialize(&rust_issuer_pk.g_tilde);
    let total_nb_attributes = nb_recipient_attributes + nb_issuer_attributes;
    for i in 0..total_nb_attributes {
        let mut g1_element = unsafe{G1::uninit()};
        g1_element.deserialize(&rust_issuer_pk.g_powers[i as usize]);
        issuer_pk_g_powers.push(g1_element);
        let mut g2_element = unsafe{G2::uninit()};
        g2_element.deserialize(&rust_issuer_pk.g_tilde_powers[i as usize]);
        issuer_pk_g_tilde_powers.push(g2_element);
    }
    let issuer_pk_for_method = PublicKey{g: issuer_pk_g, g_powers: issuer_pk_g_powers, g_tilde: issuer_pk_g_tilde, x_tilde: issuer_pk_x_tilde, g_tilde_powers: issuer_pk_g_tilde_powers};

    let rust_credentials_bytes = env.convert_byte_array(credential).expect("Could not load recipient's credentials");
    let rust_credentials = CredentialProto::parse_from_bytes(&rust_credentials_bytes).unwrap();
    let mut attributes_for_method: Vec<Fr> = Vec::new();
    for i in 0..total_nb_attributes {
        let mut fr_elem = Fr::zero();
        fr_elem.deserialize(&rust_credentials.attributes[i as usize]);
        attributes_for_method.push(fr_elem);
    }
    let mut sigma_one = unsafe{G1::uninit()};
    let mut sigma_two = unsafe{G1::uninit()};
    sigma_one.deserialize(&rust_credentials.sigma_one);
    sigma_two.deserialize(&rust_credentials.sigma_two);
    let signature_for_method = Signature{sigma_one: sigma_one, sigma_two: sigma_two};
    let mut revocation_value_for_method = Fr::zero();
    revocation_value_for_method.deserialize(&rust_credentials.attributes[(nb_issuer_attributes - 1) as usize]);
    let mut household_secret = Fr::zero();
    household_secret.deserialize(&rust_credentials.attributes[(nb_issuer_attributes + nb_recipient_attributes - 1) as usize]);

    let epoch_bytes = env.convert_byte_array(epoch).expect("Could not load the epoch");

    /*Call the native implementation */
    let disclosure_proof = Java_ch_epfl_rcadsprototype_Crypto_getDisclosureProof(&issuer_pk_for_method, &attributes_for_method, nb_issuer_attributes, nb_recipient_attributes, signature_for_method, &epoch_bytes, household_secret, revocation_value_for_method);

    /*Convert it back to bytes for transmission */
    let mut return_disclosure_proof = DisclosureProofRecipientProto::new();
    return_disclosure_proof.C = disclosure_proof.C.serialize();
    return_disclosure_proof.challenge = disclosure_proof.challenge.serialize();
    return_disclosure_proof.R_commitment = disclosure_proof.R_commitment.serialize();
    return_disclosure_proof.R_pseudonym = disclosure_proof.R_pseudonym.serialize();
    return_disclosure_proof.R_revocation_value = disclosure_proof.R_revocation_value.serialize();
    for i in 0..nb_recipient_attributes + 2 {
        return_disclosure_proof.responses.push(disclosure_proof.responses[i as usize].serialize());
    }
    let mut signature_for_disclosure = SignatureProto::new();
    signature_for_disclosure.sigma_one = disclosure_proof.randomized_signature.sigma_one.serialize();
    signature_for_disclosure.sigma_two = disclosure_proof.randomized_signature.sigma_two.serialize();
    return_disclosure_proof.randomized_signature = signature_for_disclosure.write_to_bytes().unwrap();
    return_disclosure_proof.s_hss = disclosure_proof.s_hss.serialize();
    return_disclosure_proof.s_rev_value = disclosure_proof.s_rev_value.serialize();
    let mut token = TokenProto::new();
    token.h = disclosure_proof.token.h.serialize();
    token.capital_h = disclosure_proof.token.H.serialize();
    return_disclosure_proof.token = token.write_to_bytes().unwrap();
    return_disclosure_proof.pseudonym = disclosure_proof.pseudonym.serialize();
    return_disclosure_proof.base_revocation_value = disclosure_proof.base_revocation_value.serialize();

    return convertVecToByteArray(env, return_disclosure_proof.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getProofOfDisclosureForVerifierJava(env: JNIEnv, _:JClass, proof_of_disclosure_for_recipient: jbyteArray, nb_recipient_attributes: jint, nb_issuer_attributes: jint, epoch: jbyteArray) -> jbyteArray {
    let rust_proof_bytes = env.convert_byte_array(proof_of_disclosure_for_recipient).expect("Could not load the recipients proof of disclosure");
    let rust_proof = DisclosureProofRecipientProto::parse_from_bytes(&rust_proof_bytes).unwrap();

    let mut return_verifier_proof = DisclosureProofVerifierProto::new();
    return_verifier_proof.randomized_signature = rust_proof.randomized_signature;
    return_verifier_proof.C = rust_proof.C;
    return_verifier_proof.challenge = rust_proof.challenge;
    for i in 0..nb_recipient_attributes + 2 {
        let copy_response = rust_proof.responses[i as usize].clone();
        return_verifier_proof.responses.push(copy_response);
    }
    return_verifier_proof.R_commitment = rust_proof.R_commitment;
    return_verifier_proof.R_pseudonym = rust_proof.R_pseudonym;
    return_verifier_proof.R_revocation_value = rust_proof.R_revocation_value;
    return_verifier_proof.nb_issuer_attributes = nb_issuer_attributes;
    return_verifier_proof.nb_recipient_attributes = nb_recipient_attributes;
    return_verifier_proof.pseudonym = rust_proof.pseudonym;
    let epoch_bytes = env.convert_byte_array(epoch).expect("Could not load the epoch bytes");
    return_verifier_proof.epoch = epoch_bytes;
    return_verifier_proof.s_hss = rust_proof.s_hss;
    return_verifier_proof.s_rev_value = rust_proof.s_rev_value;
    return_verifier_proof.base_revocation_value = rust_proof.base_revocation_value;
    let token = TokenProto::parse_from_bytes(&rust_proof.token).unwrap();
    return_verifier_proof.powered_rev_value = token.capital_h;
    return convertVecToByteArray(env, return_verifier_proof.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getDisclosureProof(issuer_pk: &PublicKey, attributes: &Vec<Fr>, nb_issuer_attributes: jint, nb_recipient_attributes: jint, signature: Signature, epoch: &[u8], household_secret: Fr, revocation_value: Fr) -> DisclosureProofRecipient {
    let mut r = Fr::zero();
    r.set_by_csprng();
    let mut t = Fr::zero();
    t.set_by_csprng();
    let mut t_prime = Fr::zero();
    t_prime.set_by_csprng();

    //Construct a randomized signature
    let mut first_term_power_r = unsafe{G1::uninit()};
    G1::mul(&mut first_term_power_r, &signature.sigma_one, &r);
    let mut sigma_one_power_t = unsafe{G1::uninit()};
    G1::mul(&mut sigma_one_power_t, &signature.sigma_one, &t);
    let mut signature_second_term = unsafe{G1::uninit()};
    G1::add(&mut signature_second_term, &signature.sigma_two, &sigma_one_power_t);
    let mut signature_second_term_power_r = unsafe{G1::uninit()};
    G1::mul(&mut signature_second_term_power_r, &signature_second_term, &r);

    let return_signature = Signature{sigma_one: first_term_power_r, sigma_two: signature_second_term_power_r};

    //Hash the epoch to a group element and construct pseudonym
    let mut hashed_epoch = unsafe{G1::uninit()};
    G1::set_hash_of(&mut hashed_epoch, epoch);
    let mut pseudonym = unsafe{G1::uninit()};
    G1::mul(&mut pseudonym, &hashed_epoch, &household_secret);
    let mut r_hss = Fr::zero();
    r_hss.set_by_csprng();
    let mut R_pseudonym = unsafe{G1::uninit()};
    G1::mul(&mut R_pseudonym, &hashed_epoch, &r_hss);

    //C = randomized_sign.sigma_one.pair(issuer_pk.generator_tilde) ** t
    let mut sigma_one_paired_g_tilde = unsafe{GT::uninit()};
    pairing(&mut sigma_one_paired_g_tilde, &return_signature.sigma_one, &issuer_pk.g_tilde);
    let mut C = unsafe{GT::uninit()};
    GT::pow(&mut C, &sigma_one_paired_g_tilde, &t);

    //R_commitment = randomized_sign.sigma_one.pair(issuer_pk.generator_tilde) ** t_prime
    let mut R_commitment = unsafe{GT::uninit()};
    GT::pow(&mut R_commitment, &sigma_one_paired_g_tilde, &t_prime);

    let mut a_i_prime: Vec<Fr> = Vec::new();
    let t_prime_copy = t_prime.clone();
    a_i_prime.push(t_prime);
    for _ in 0..nb_recipient_attributes-1 {
        let mut random_elem = Fr::zero();
        random_elem.set_by_csprng();
        a_i_prime.push(random_elem);
    }
    let r_hss_copy = r_hss.clone();
    a_i_prime.push(r_hss); //Under the condition that the household secret is the last attribute ABC.

    let mut tmp_C = unsafe{GT::uninit()};
    let mut tmp_R_commitment = unsafe{GT::uninit()};
    for i in 0..nb_recipient_attributes {
        let mut sigma_one_paired_g_tilde_powers = unsafe{GT::uninit()};
        pairing(&mut sigma_one_paired_g_tilde_powers, &return_signature.sigma_one, &issuer_pk.g_tilde_powers[(i + nb_issuer_attributes) as usize]);

        let mut sigma_paired_g_tilde_powers_power_attribute = unsafe{GT::uninit()};
        GT::pow(&mut sigma_paired_g_tilde_powers_power_attribute, &sigma_one_paired_g_tilde_powers, &attributes[(i + nb_issuer_attributes) as usize]);
        GT::mul(&mut tmp_C, &C, &sigma_paired_g_tilde_powers_power_attribute);
        C = tmp_C.clone();

        let mut sigma_paired_g_tilde_powers_power_random_elems = unsafe{GT::uninit()};
        GT::pow(&mut sigma_paired_g_tilde_powers_power_random_elems, &sigma_one_paired_g_tilde_powers, &a_i_prime[(i + 1) as usize]);
        GT::mul(&mut tmp_R_commitment, &R_commitment, &sigma_paired_g_tilde_powers_power_random_elems);
        R_commitment = tmp_R_commitment.clone();
    }

    let g1_generator = G1::from_str("1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10).unwrap();
    let mut random_elem_fp = Fr::zero();
    random_elem_fp.set_by_csprng();
    let mut base_rev_value = unsafe{G1::uninit()};
    G1::mul(&mut base_rev_value, &g1_generator, &random_elem_fp);
    let mut r_rev_value = Fr::zero();
    r_rev_value.set_by_csprng();
    let mut powered_rev_value = unsafe{G1::uninit()};
    G1::mul(&mut powered_rev_value, &base_rev_value, &revocation_value);
    let mut R_revocation_value = unsafe{G1::uninit()};
    G1::mul(&mut R_revocation_value, &base_rev_value, &r_rev_value);
    let mut sigma_one_paired_g_tilde_rev_value = unsafe{GT::uninit()};
    pairing(&mut sigma_one_paired_g_tilde_rev_value, &return_signature.sigma_one, &issuer_pk.g_tilde_powers[(nb_issuer_attributes - 1) as usize]);
    let mut prev_term_powered = unsafe{GT::uninit()};
    GT::pow(&mut prev_term_powered, &sigma_one_paired_g_tilde_rev_value, &revocation_value);
    GT::mul(&mut tmp_C, &C, &prev_term_powered);
    C = tmp_C.clone();
    GT::pow(&mut prev_term_powered, &sigma_one_paired_g_tilde_rev_value, &r_rev_value);
    GT::mul(&mut tmp_R_commitment, &R_commitment, &prev_term_powered);
    R_commitment = tmp_R_commitment.clone();

    let base_rev_value_copy = base_rev_value.clone();
    let token = Token { h: base_rev_value, H: powered_rev_value };

    let mut hasher = Sha256::new();
    hasher.update(sigma_one_paired_g_tilde.serialize());
    for i in 0..nb_recipient_attributes {
        let mut sigma_one_paired_g_tilde_powers = unsafe{GT::uninit()};
        pairing(&mut sigma_one_paired_g_tilde_powers, &return_signature.sigma_one, &issuer_pk.g_tilde_powers[(i + nb_issuer_attributes) as usize]);
        hasher.update(b"||");
        hasher.update(sigma_one_paired_g_tilde_powers.serialize());
    }
    hasher.update(b"||");
    hasher.update(C.serialize());
    hasher.update(b"||");
    hasher.update(R_commitment.serialize());
    let hashed_public_values = hasher.finalize();
    let mut challenge = Fr::zero();
    Fr::set_hash_of(&mut challenge, &hashed_public_values);

    let mut responses: Vec<Fr> = Vec::new();
    let mut t_response = Fr::zero();
    let mut product = Fr::zero();
    Fr::mul(&mut product, &challenge, &t);
    Fr::sub(&mut t_response, &t_prime_copy, &product);
    responses.push(t_response);

    for i in 0..nb_recipient_attributes - 1 {
        let mut product = Fr::zero();
        let mut difference = Fr::zero();
        Fr::mul(&mut product, &challenge, &attributes[(nb_issuer_attributes + i) as usize]);
        Fr::sub(&mut difference, &a_i_prime[(i + 1) as usize], &product);
        responses.push(difference);
    }
    let mut challenge_times_hh_secret = Fr::zero();
    Fr::mul(&mut challenge_times_hh_secret, &challenge, &household_secret);
    let mut s_hss = Fr::zero();
    Fr::sub(&mut s_hss, &r_hss_copy, &challenge_times_hh_secret);
    let s_hss_copy = s_hss.clone();
    responses.push(s_hss);

    let mut challenge_times_rev_value = Fr::zero();
    Fr::mul(&mut challenge_times_rev_value, &challenge, &revocation_value);
    let mut s_rev_value = Fr::zero();
    Fr::sub(&mut s_rev_value, &r_rev_value, &challenge_times_rev_value);
    let s_rev_value_copy = s_rev_value.clone();
    responses.push(s_rev_value);

    return DisclosureProofRecipient { C: C, challenge: challenge, R_commitment: R_commitment, R_pseudonym: R_pseudonym, R_revocation_value: R_revocation_value, responses: responses, randomized_signature: return_signature, s_hss: s_hss_copy, s_rev_value: s_rev_value_copy, token: token, pseudonym: pseudonym, base_revocation_value: base_rev_value_copy };

}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getAlreadySeenCredentialsJava(env: JNIEnv, _:JClass) -> jbyteArray {
    let mut already_seen = AlreadySeenCredentialsProto::new();
    let g = unsafe{G1::uninit()};
    for i in 1..5 {
            let mut elem = unsafe{G1::uninit()};
            G1::mul(&mut elem, &g, &Fr::from_int(i*2));
            already_seen.credentials.push(elem.serialize());
    }
    already_seen.number_credentials = 4;
    return convertVecToByteArray(env, already_seen.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getNewAlreadySeenCredentialsJava(env: JNIEnv, _:JClass, disclosureProofResult: jbyteArray) -> jbyteArray {
    let mut output = AlreadySeenCredentialsProto::new();
    let rust_result_bytes = env.convert_byte_array(disclosureProofResult).expect("Could not load the disclosure proof result");
    let result = DisclosureProofResultProto::parse_from_bytes(&rust_result_bytes).unwrap();
    let new_nbr_credentials = result.already_seen_pseudonyms.len();
    for i in 0..new_nbr_credentials {
       output.credentials.push(result.already_seen_pseudonyms[i as usize].clone());
    }
    output.number_credentials = new_nbr_credentials as i32;
    return convertVecToByteArray(env, output.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_isDisclosureProofValidJava(env: JNIEnv, _:JClass, disclosureProofResult: jbyteArray) -> jstring {
    let rust_result_bytes = env.convert_byte_array(disclosureProofResult).expect("Could not load the disclosure proof result");
    let result = DisclosureProofResultProto::parse_from_bytes(&rust_result_bytes).unwrap();
    if result.is_valid_proof {
        return env.new_string(format!("True"))
        .expect("Couldn't create java string!").into_inner();
    }
    else {
        return env.new_string(format!("False"))
        .expect("Couldn't create java string!").into_inner(); 
    }
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_verifyDisclosureProofJava(env: JNIEnv, _:JClass, verifier_disclosure_proof: jbyteArray, issuer_pk: jbyteArray, already_seen_credentials: jbyteArray) -> jbyteArray {
    let rust_issuer_public_key_bytes = env.convert_byte_array(issuer_pk).expect("Could not load the issuer's public key");
    let rust_issuer_pk = PublicKeyProto::parse_from_bytes(&rust_issuer_public_key_bytes).unwrap();
    let rust_proof_bytes = env.convert_byte_array(verifier_disclosure_proof).expect("Could not load the recipient's proof of disclosure");
    let rust_proof = DisclosureProofVerifierProto::parse_from_bytes(&rust_proof_bytes).unwrap();
    let mut issuer_pk_g = unsafe{G1::uninit()};
    let mut issuer_pk_g_powers: Vec<G1> = Vec::new();
    let mut issuer_pk_x_tilde: G2 = unsafe{G2::uninit()};
    let mut issuer_pk_g_tilde: G2 = unsafe{G2::uninit()};
    let mut issuer_pk_g_tilde_powers: Vec<G2> = Vec::new();
    issuer_pk_g.deserialize(&rust_issuer_pk.g);
    issuer_pk_x_tilde.deserialize(&rust_issuer_pk.x_tilde);
    issuer_pk_g_tilde.deserialize(&rust_issuer_pk.g_tilde);
    let total_nb_attributes = rust_proof.nb_recipient_attributes + rust_proof.nb_issuer_attributes;
    for i in 0..total_nb_attributes {
        let mut g1_element = unsafe{G1::uninit()};
        g1_element.deserialize(&rust_issuer_pk.g_powers[i as usize]);
        issuer_pk_g_powers.push(g1_element);
        let mut g2_element = unsafe{G2::uninit()};
        g2_element.deserialize(&rust_issuer_pk.g_tilde_powers[i as usize]);
        issuer_pk_g_tilde_powers.push(g2_element);
    }
    let issuer_pk_for_method = PublicKey{g: issuer_pk_g, g_powers: issuer_pk_g_powers, g_tilde: issuer_pk_g_tilde, x_tilde: issuer_pk_x_tilde, g_tilde_powers: issuer_pk_g_tilde_powers};

    let mut seen_credentials_for_method: Vec<G1> = Vec::new();
    let rust_credentials_bytes = env.convert_byte_array(already_seen_credentials).expect("Could not load previously seen credentials");
    let rust_credentials = AlreadySeenCredentialsProto::parse_from_bytes(&rust_credentials_bytes).unwrap();
    for i in 0..rust_credentials.number_credentials {
        let mut group_elem = unsafe{G1::uninit()};
        group_elem.deserialize(&rust_credentials.credentials[i as usize]);
        seen_credentials_for_method.push(group_elem);
    }

    let mut rust_proof_challenge = Fr::zero();
    rust_proof_challenge.deserialize(&rust_proof.challenge);
    let mut rust_proof_C = unsafe{GT::uninit()};
    rust_proof_C.deserialize(&rust_proof.C);
    let rust_proof_randomized_signature = SignatureProto::parse_from_bytes(&rust_proof.randomized_signature).unwrap();
    let mut sigma_one = unsafe{G1::uninit()};
    sigma_one.deserialize(&rust_proof_randomized_signature.sigma_one);
    let mut sigma_two = unsafe{G1::uninit()};
    sigma_two.deserialize(&rust_proof_randomized_signature.sigma_two);
    let random_sign_for_method = Signature{sigma_one: sigma_one, sigma_two: sigma_two};

    let mut responses_for_method: Vec<Fr> = Vec::new();
    let nb_recipient_attributes = rust_proof.nb_recipient_attributes;
    for i in 0..nb_recipient_attributes + 2 {
        let mut fr_elem = Fr::zero();
        fr_elem.deserialize(&rust_proof.responses[i as usize]);
        responses_for_method.push(fr_elem);
    }

    let mut rust_proof_R_commitment = unsafe{GT::uninit()};
    rust_proof_R_commitment.deserialize(&rust_proof.R_commitment);

    let mut rust_proof_R_pseudonym = unsafe{G1::uninit()};
    rust_proof_R_pseudonym.deserialize(&rust_proof.R_pseudonym);

    let mut rust_proof_R_revocation_value = unsafe{G1::uninit()};
    rust_proof_R_revocation_value.deserialize(&rust_proof.R_revocation_value);

    let mut rust_proof_pseudonym = unsafe{G1::uninit()};
    rust_proof_pseudonym.deserialize(&rust_proof.pseudonym);

    let mut rust_proof_epoch = unsafe{G1::uninit()};
    G1::set_hash_of(&mut rust_proof_epoch, &rust_proof.epoch);


    let mut rust_proof_s_hss = Fr::zero();
    rust_proof_s_hss.deserialize(&rust_proof.s_hss);
    let mut rust_proof_s_rev_value = Fr::zero();
    rust_proof_s_rev_value.deserialize(&rust_proof.s_rev_value);
    let mut rust_proof_base_revocation_value = unsafe{G1::uninit()};
    rust_proof_base_revocation_value.deserialize(&rust_proof.base_revocation_value);
    let mut rust_proof_powered_rev_value = unsafe{G1::uninit()};
    rust_proof_powered_rev_value.deserialize(&rust_proof.powered_rev_value);

    let proof_for_method = DisclosureProofForVerifier{ randomized_signature: random_sign_for_method, C: rust_proof_C, challenge: rust_proof_challenge, responses: responses_for_method, R_commitment: rust_proof_R_commitment, R_pseudonym: rust_proof_R_pseudonym, R_revocation_value: rust_proof_R_revocation_value, nb_issuer_attributes: rust_proof.nb_issuer_attributes, nb_recipient_attributes: nb_recipient_attributes, pseudonym: rust_proof_pseudonym, powered_rev_value: rust_proof_powered_rev_value, epoch: rust_proof_epoch, s_hss: rust_proof_s_hss, s_rev_value: rust_proof_s_rev_value, base_rev_value: rust_proof_base_revocation_value };

    let result = Java_ch_epfl_rcadsprototype_Crypto_verifyDisclosureProof(proof_for_method, &issuer_pk_for_method, seen_credentials_for_method);
    let mut output = DisclosureProofResultProto::new();
    output.is_valid_proof = result.is_valid_proof;
    if result.is_valid_proof {
        for i in 0..result.already_seen_pseudonyms.len() {
            output.already_seen_pseudonyms.push(result.already_seen_pseudonyms[i as usize].serialize());
        }
    }
    else {
    
    }
    return convertVecToByteArray(env, output.write_to_bytes().unwrap()); 
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_verifyDisclosureProof(disclosure_proof: DisclosureProofForVerifier, issuer_pk: &PublicKey, mut already_seen_credentials: Vec<G1>) -> DisclosureProofResult {
    if disclosure_proof.randomized_signature.sigma_one.is_zero() {
        println!("First element in the signature tuple is the neutral element!");
        return DisclosureProofResult{already_seen_pseudonyms: Vec::new(), is_valid_proof: false};
    }
    let mut check = unsafe{GT::uninit()};
    GT::pow(&mut check, &disclosure_proof.C, &disclosure_proof.challenge);
    let mut term_to_multiply_check_tmp = unsafe{GT::uninit()};
    let mut term_to_multiply_check = unsafe{GT::uninit()};
    pairing(&mut term_to_multiply_check_tmp, &disclosure_proof.randomized_signature.sigma_one, &issuer_pk.g_tilde);
    GT::pow(&mut term_to_multiply_check, &term_to_multiply_check_tmp, &disclosure_proof.responses[0]);

    let mut tmp_check = unsafe{GT::uninit()};
    GT::mul(&mut tmp_check, &check, &term_to_multiply_check);
    check = tmp_check.clone();

    let mut unpowered_terms = unsafe{GT::uninit()};
    let mut pair = unsafe{GT::uninit()};
    for i in 0..disclosure_proof.nb_recipient_attributes {
        pairing(&mut unpowered_terms, &disclosure_proof.randomized_signature.sigma_one, &issuer_pk.g_tilde_powers[(disclosure_proof.nb_issuer_attributes + i) as usize]);
        GT::pow(&mut pair, &unpowered_terms, &disclosure_proof.responses[(i + 1) as usize]);
        GT::mul(&mut tmp_check, &check, &pair);
        check = tmp_check.clone();
    }
    pairing(&mut unpowered_terms, &disclosure_proof.randomized_signature.sigma_one, &issuer_pk.g_tilde_powers[(disclosure_proof.nb_issuer_attributes - 1) as usize]);
    GT::pow(&mut pair, &unpowered_terms, &disclosure_proof.s_rev_value);
    GT::mul(&mut tmp_check, &check, &pair);
    check = tmp_check.clone();

    if check != disclosure_proof.R_commitment {
        println!("The value that was commited doesn't correspond to what is expected.");
        return DisclosureProofResult{already_seen_pseudonyms: Vec::new(), is_valid_proof: false};
    }

    let hashed_epoch = disclosure_proof.epoch;

    let mut pseudonym_power_challenge = unsafe{G1::uninit()};
    G1::mul(&mut pseudonym_power_challenge, &disclosure_proof.pseudonym, &disclosure_proof.challenge);
    let mut epoch_power_s_hss = unsafe{G1::uninit()};
    G1::mul(&mut epoch_power_s_hss, &hashed_epoch, &disclosure_proof.s_hss);
    let mut check_R_pseudonym = unsafe{G1::uninit()};
    G1::add(&mut check_R_pseudonym, &pseudonym_power_challenge, &epoch_power_s_hss);

    if check_R_pseudonym != disclosure_proof.R_pseudonym {
        println!("The exponentiation of the hashed epoch was not computed correctly.");
        return DisclosureProofResult{already_seen_pseudonyms: Vec::new(), is_valid_proof: false};
    }

    let mut powered_rev_value_power_challenge = unsafe{G1::uninit()};
    let mut base_rev_value_power_response = unsafe{G1::uninit()};
    G1::mul(&mut powered_rev_value_power_challenge, &disclosure_proof.powered_rev_value, &disclosure_proof.challenge);
    G1::mul(&mut base_rev_value_power_response, &disclosure_proof.base_rev_value, &disclosure_proof.s_rev_value);
    let mut check_R_revocated_value = unsafe{G1::uninit()};
    G1::add(&mut check_R_revocated_value, &powered_rev_value_power_challenge, &base_rev_value_power_response);

    if check_R_revocated_value != disclosure_proof.R_revocation_value {
        println!("The exponentiation to prove the revocation value is correct was not computed correctly.");
        return DisclosureProofResult{already_seen_pseudonyms: Vec::new(), is_valid_proof: false};
    }

    let nbr_already_seen_credentials = already_seen_credentials.len();
    for i in 0..nbr_already_seen_credentials {
        if disclosure_proof.pseudonym == already_seen_credentials[i] {
            println!("This recipient has already been seen in this epoch!");
            return DisclosureProofResult{already_seen_pseudonyms: Vec::new(), is_valid_proof: false};
        }
    }
    already_seen_credentials.push(disclosure_proof.pseudonym);
    return DisclosureProofResult{already_seen_pseudonyms: already_seen_credentials, is_valid_proof: true};
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getServiceProviderRevocatedValuesJava(env: JNIEnv, _:JClass, nbr_tokens: jint) -> jbyteArray {
    let tokens = Java_ch_epfl_rcadsprototype_Crypto_getServiceProviderRevocatedValues(nbr_tokens);

    let mut return_tokens = RevocatedTokensProto::new();

    for i in 0..nbr_tokens {
        let mut token_message = TokenProto::new();
        token_message.h = tokens[i as usize].h.serialize();
        token_message.capital_h = tokens[i as usize].H.serialize();
        return_tokens.tokens.push(token_message.write_to_bytes().unwrap());
    }
    return convertVecToByteArray(env, return_tokens.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getServiceProviderRevocatedValues(nbr_values: i32) -> Vec<Token> {
    //For now a placeholder implementation
    let mut revocated_tokens: Vec<Token> = Vec::new();
    let g1_generator = G1::from_str("1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10).unwrap();
    for _ in 0..nbr_values {
        let mut random_elem_fp = Fr::zero();
        random_elem_fp.set_by_csprng();
        let mut new_h = unsafe{G1::uninit()};
        G1::mul(&mut new_h, &g1_generator, &random_elem_fp);
        random_elem_fp.set_by_csprng();
        let mut new_H = unsafe{G1::uninit()};
        G1::mul(&mut new_H,&new_h, &random_elem_fp);
        let new_token = Token{h: new_h, H: new_H};
        revocated_tokens.push(new_token);
    }
    return revocated_tokens;
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getTokenAndRevocationValueJava(env: JNIEnv, _:JClass, disclosure_proof_recipient: jbyteArray, credential_attributes: jbyteArray, nb_issuer_attributes: jint) -> jbyteArray {
    let rust_proof_bytes = env.convert_byte_array(disclosure_proof_recipient).expect("Could not load the recipient's proof of disclosure");
    let rust_proof = DisclosureProofRecipientProto::parse_from_bytes(&rust_proof_bytes).unwrap();

    let rust_credential_bytes = env.convert_byte_array(credential_attributes).expect("Could not load the recipient's credential");
    let rust_credential = CredentialProto::parse_from_bytes(&rust_credential_bytes).unwrap();

    let mut token_and_rev_value = TokenAndRevocationValueProto::new();
    token_and_rev_value.token = rust_proof.token;
    token_and_rev_value.revocation_value = rust_credential.attributes[(nb_issuer_attributes - 1) as usize].clone();
    return convertVecToByteArray(env, token_and_rev_value.write_to_bytes().unwrap());
} 

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getBlacklistedPowersJava(env: JNIEnv, _:JClass, nbr_tokens: jint) -> jbyteArray {
    let mut powers = PowersForBlacklistProto::new();
    for _ in 0..nbr_tokens {
        let mut fr_elem = Fr::zero();
        fr_elem.set_by_csprng();
        powers.powers.push(fr_elem.serialize());
    }
    return convertVecToByteArray(env, powers.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getProverProtocolJava(env: JNIEnv, _:JClass, revocated_values: jbyteArray, powers_for_blacklisted_elements: jbyteArray, token_and_revocation_value: jbyteArray) -> jbyteArray {
    let rust_rev_values_bytes = env.convert_byte_array(revocated_values).expect("Error loading the blacklisted tokens");
    let rust_rev_values = RevocatedTokensProto::parse_from_bytes(&rust_rev_values_bytes).unwrap();
    let nb_tokens = rust_rev_values.tokens.len();
    let mut blacklist: Vec<Token> = Vec::new();
    for i in 0..nb_tokens {
        let new_token_message = TokenProto::parse_from_bytes(&rust_rev_values.tokens[i as usize]).unwrap();
        let mut h = unsafe{G1::uninit()};
        h.deserialize(&new_token_message.h);
        let mut H = unsafe{G1::uninit()};
        H.deserialize(&new_token_message.capital_h);
        let new_token = Token{h: h, H: H};
        blacklist.push(new_token);
    }

    let rust_powers_bytes = env.convert_byte_array(powers_for_blacklisted_elements).expect("Could not load the powers for blacklisted elements");
    let rust_powers = PowersForBlacklistProto::parse_from_bytes(&rust_powers_bytes).unwrap();
    let mut powers: Vec<Fr> = Vec::new();
    for i in 0..nb_tokens {
        let mut fr_elem = Fr::zero();
        fr_elem.deserialize(&rust_powers.powers[i as usize]);
        powers.push(fr_elem);
    }

    let rust_token_and_rev_bytes = env.convert_byte_array(token_and_revocation_value).expect("Could not load recipients token nor revocation value");
    let rust_token_and_rev = TokenAndRevocationValueProto::parse_from_bytes(&rust_token_and_rev_bytes).unwrap();
    let mut revocation_value = Fr::zero();
    revocation_value.deserialize(&rust_token_and_rev.revocation_value);

    let token_bytes = TokenProto::parse_from_bytes(&rust_token_and_rev.token).unwrap();
    let mut token_h = unsafe{G1::uninit()};
    token_h.deserialize(&token_bytes.h);
    let mut token_H = unsafe{G1::uninit()};
    token_H.deserialize(&token_bytes.capital_h);
    let token = Token{h: token_h, H: token_H};

    let blac_prover_output = Java_ch_epfl_rcadsprototype_Crypto_getProverProtocol(&blacklist, revocation_value, &powers, token);

    let mut output_message = BlacBatchProtocolProverOutputProto::new();
    output_message.challenge = blac_prover_output.challenge.serialize();
    output_message.R = blac_prover_output.R.serialize();
    let mut token_message = TokenProto::new();
    token_message.h = blac_prover_output.token.h.serialize();
    token_message.capital_h = blac_prover_output.token.H.serialize();
    output_message.token = token_message.write_to_bytes().unwrap();
    let mut blac_response_message = BlacResponsesProto::new();
    blac_response_message.u1 = blac_prover_output.responses.u1.serialize();
    blac_response_message.u2 = blac_prover_output.responses.u2.serialize();
    output_message.responses = blac_response_message.write_to_bytes().unwrap();
    let nb_commitments = blac_prover_output.auxiliary_commitments.len();
    for i in 0..nb_commitments {
        output_message.auxiliary_commitments.push(blac_prover_output.auxiliary_commitments[i as usize].serialize());
    }
     return convertVecToByteArray(env, output_message.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getProverProtocol(blacklist: &Vec<Token>, revocation_value: Fr, powers_for_blacklisted_elements: &Vec<Fr>, token: Token) -> BlacBatchProtocolProverOutput {
    let nbr_blacklisted_values = blacklist.len();
    let mut blinding_factor_r = Fr::zero();
    blinding_factor_r.set_by_csprng();
    
    let mut auxiliary_commitments: Vec<G1> = Vec::new();
    for i in 0..nbr_blacklisted_values {
        let mut h_power_revocation_value = unsafe{G1::uninit()};
        let mut H_power_minus_one = unsafe{G1::uninit()};
        let mut division = unsafe{G1::uninit()};
        let mut result = unsafe{G1::uninit()};

        G1::mul(&mut h_power_revocation_value, &blacklist[i].h, &revocation_value);
        G1::mul(&mut H_power_minus_one, &blacklist[i].H, &Fr::from_int(-1));
        G1::add(&mut division, &h_power_revocation_value, &H_power_minus_one);
        G1::mul(&mut result, &division, &blinding_factor_r);
        auxiliary_commitments.push(result);
    }

    let mut product_h_i_power_ai = G1::zero();
    let mut tmp_product_h_i_power_ai = unsafe{G1::uninit()};
    let mut product_H_i_power_ai = G1::zero();
    let mut tmp_product_H_i_power_ai = unsafe{G1::uninit()};
    let mut powered_elem = unsafe{G1::uninit()};
    for i in 0..nbr_blacklisted_values {
        G1::mul(&mut powered_elem, &blacklist[i].h, &powers_for_blacklisted_elements[i]);
        G1::add(&mut tmp_product_h_i_power_ai, &product_h_i_power_ai, &powered_elem);
        product_h_i_power_ai = tmp_product_h_i_power_ai.clone();

        G1::mul(&mut powered_elem, &blacklist[i].H, &powers_for_blacklisted_elements[i]);
        G1::add(&mut tmp_product_H_i_power_ai, &product_H_i_power_ai, &powered_elem);
        product_H_i_power_ai = tmp_product_H_i_power_ai.clone();
    }

    let mut h = unsafe{G1::uninit()};
    G1::add(&mut h, &token.h, &product_h_i_power_ai);
    let mut H = unsafe{G1::uninit()};
    G1::add(&mut H, &token.H, &product_H_i_power_ai);

    let mut alpha = Fr::zero();
    Fr::mul(&mut alpha, &revocation_value, &blinding_factor_r);

    let mut beta = Fr::zero();
    Fr::neg(&mut beta, &blinding_factor_r);

    let mut blinding_factor_s1 = Fr::zero();
    blinding_factor_s1.set_by_csprng();
    let mut blinding_factor_s2 = Fr::zero();
    blinding_factor_s2.set_by_csprng();

    let mut h_power_blinding_factor_s1 = unsafe{G1::uninit()};
    G1::mul(&mut h_power_blinding_factor_s1, &h, &blinding_factor_s1);
    let mut H_power_blinding_factor_s2 = unsafe{G1::uninit()};
    G1::mul(&mut H_power_blinding_factor_s2, &H, &blinding_factor_s2);
    let mut R = unsafe{G1::uninit()};
    G1::add(&mut R, &h_power_blinding_factor_s1, &H_power_blinding_factor_s2);

    //Construct challenge
    let mut hasher = Sha256::new();
    hasher.update(R.serialize());
    for i in 0..nbr_blacklisted_values {
        hasher.update(b"||");
        hasher.update(blacklist[i].h.serialize());
        hasher.update(blacklist[i].H.serialize());
        hasher.update(b"||");
        hasher.update(powers_for_blacklisted_elements[i].serialize());
    }
    let hashed_public_values = hasher.finalize();
    let mut challenge = Fr::zero();
    Fr::set_hash_of(&mut challenge, &hashed_public_values);

    let mut challenge_times_alpha = Fr::zero();
    Fr::mul(&mut challenge_times_alpha, &challenge, &alpha);
    let mut response_u1 = Fr::zero();
    Fr::sub(&mut response_u1, &blinding_factor_s1, &challenge_times_alpha);

    let mut challenge_times_beta = Fr::zero();
    Fr::mul(&mut challenge_times_beta, &challenge, &beta);
    let mut response_u2 = Fr::zero();
    Fr::sub(&mut response_u2, &blinding_factor_s2, &challenge_times_beta);
    let responses = BlacResponses{u1: response_u1, u2: response_u2};

    return BlacBatchProtocolProverOutput { responses: responses, auxiliary_commitments: auxiliary_commitments, R: R, token: token, challenge: challenge }
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getVerifierProtocolJava(env: JNIEnv, _:JClass, prover_protocol: jbyteArray, blacklist: jbyteArray, powers_for_blacklist: jbyteArray) -> jstring {
    let rust_rev_values_bytes = env.convert_byte_array(blacklist).expect("Error loading the blacklisted tokens");
    let rust_rev_values = RevocatedTokensProto::parse_from_bytes(&rust_rev_values_bytes).unwrap();
    let nb_tokens = rust_rev_values.tokens.len();
    let mut blacklist: Vec<Token> = Vec::new();
    for i in 0..nb_tokens {
        let new_token_message = TokenProto::parse_from_bytes(&rust_rev_values.tokens[i as usize]).unwrap();
        let mut h = unsafe{G1::uninit()};
        h.deserialize(&new_token_message.h);
        let mut H = unsafe{G1::uninit()};
        H.deserialize(&new_token_message.capital_h);
        let new_token = Token{h: h, H: H};
        blacklist.push(new_token);
    }

    let rust_powers_bytes = env.convert_byte_array(powers_for_blacklist).expect("Could not load the powers for blacklisted elements");
    let rust_powers = PowersForBlacklistProto::parse_from_bytes(&rust_powers_bytes).unwrap();
    let mut powers: Vec<Fr> = Vec::new();
    for i in 0..nb_tokens {
        let mut fr_elem = Fr::zero();
        fr_elem.deserialize(&rust_powers.powers[i as usize]);
        powers.push(fr_elem);
    }

    let prover_proto_bytes = env.convert_byte_array(prover_protocol).expect("Could not load the provers protocol for BLAC");
    let prover_proto = BlacBatchProtocolProverOutputProto::parse_from_bytes(&prover_proto_bytes).unwrap();

    let mut challenge = Fr::zero();
    challenge.deserialize(&prover_proto.challenge);
    let mut R = unsafe{G1::uninit()};
    R.deserialize(&prover_proto.R);

    let mut aux_commitments: Vec<G1> = Vec::new();
    for i in 0..nb_tokens {
        let mut group_elem = unsafe{G1::uninit()};
        group_elem.deserialize(&prover_proto.auxiliary_commitments[i as usize]);
        aux_commitments.push(group_elem);
    }

    let token_message = TokenProto::parse_from_bytes(&prover_proto.token).unwrap();
    let mut token_h = unsafe{G1::uninit()};
    token_h.deserialize(&token_message.h);
    let mut token_H = unsafe{G1::uninit()};
    token_H.deserialize(&token_message.capital_h);
    let token_for_method = Token{h: token_h, H: token_H};

    let responses_message = BlacResponsesProto::parse_from_bytes(&prover_proto.responses).unwrap();
    let mut response_u1 = Fr::zero();
    response_u1.deserialize(&responses_message.u1);
    let mut response_u2 = Fr::zero();
    response_u2.deserialize(&responses_message.u2);
    let response_for_method = BlacResponses{u1: response_u1, u2: response_u2};



    let rust_proto = BlacBatchProtocolProverOutput{ responses: response_for_method, auxiliary_commitments: aux_commitments, R: R, token: token_for_method, challenge: challenge};
    let is_valid_blac_proof = Java_ch_epfl_rcadsprototype_Crypto_getVerifierProtocol(rust_proto, &blacklist, &powers);

    if is_valid_blac_proof {
        return env.new_string(format!("True"))
        .expect("Couldn't create java string!").into_inner();
    }
    else {
        return env.new_string(format!("False"))
        .expect("Couldn't create java string!").into_inner();
    }
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getVerifierProtocol(prover_protocol: BlacBatchProtocolProverOutput, blacklist: &Vec<Token>,  powers_for_blacklisted_elements: &Vec<Fr>) -> bool {
    let nbr_blacklisted_values = blacklist.len();
    let mut product_h_i_power_ai = G1::zero();
    let mut tmp_product_h_i_power_ai = unsafe{G1::uninit()};
    let mut product_H_i_power_ai = G1::zero();
    let mut tmp_product_H_i_power_ai = unsafe{G1::uninit()};
    let mut powered_elem = unsafe{G1::uninit()};
    let mut commitment = G1::zero();
    let mut tmp_commitment = unsafe{G1::uninit()};
    for i in 0..nbr_blacklisted_values {
        G1::mul(&mut powered_elem, &blacklist[i].h, &powers_for_blacklisted_elements[i]);
        G1::add(&mut tmp_product_h_i_power_ai, &product_h_i_power_ai, &powered_elem);
        product_h_i_power_ai = tmp_product_h_i_power_ai.clone();

        G1::mul(&mut powered_elem, &blacklist[i].H, &powers_for_blacklisted_elements[i]);
        G1::add(&mut tmp_product_H_i_power_ai, &product_H_i_power_ai, &powered_elem);
        product_H_i_power_ai = tmp_product_H_i_power_ai.clone();

        G1::mul(&mut powered_elem, &prover_protocol.auxiliary_commitments[i], &powers_for_blacklisted_elements[i]);
        G1::add(&mut tmp_commitment, &commitment, &powered_elem);
        commitment = tmp_commitment.clone();
    }

    for i in 0..nbr_blacklisted_values {
        if prover_protocol.auxiliary_commitments[i].is_zero() {
            println!("One of the auxiliary commitments was a neutral element.");
            return false;
        }
    }

    let mut h = unsafe{G1::uninit()};
    G1::add(&mut h, &prover_protocol.token.h, &product_h_i_power_ai);
    let mut H = unsafe{G1::uninit()};
    G1::add(&mut H, &prover_protocol.token.H, &product_H_i_power_ai);
    
    let mut h_power_response_u1 = unsafe{G1::uninit()};
    G1::mul(&mut h_power_response_u1, &h, &prover_protocol.responses.u1);
    let mut H_power_response_u2 = unsafe{G1::uninit()};
    G1::mul(&mut H_power_response_u2, &H, &prover_protocol.responses.u2);

    let mut commitment_power_challenge = unsafe{G1::uninit()};
    G1::mul(&mut commitment_power_challenge, &commitment, &prover_protocol.challenge);

    let mut tmp_check = unsafe{G1::uninit()};
    let mut check = unsafe{G1::uninit()};
    G1::add(&mut tmp_check, &h_power_response_u1, &H_power_response_u2);
    G1::add(&mut check, &tmp_check, &commitment_power_challenge);
    
    return check == prover_protocol.R;
}



//=======================SANITY CHECK==================================================
#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_hello(env: JNIEnv,
                                                 _: JClass,
                                                 input: JString)
                                                 -> jstring {
    let input: String =
        env.get_string(input).expect("Couldn't get java string!").into();

    let output = env.new_string(format!("Hello, {}!", input))
        .expect("Couldn't create java string!");

    output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_testerExternalMain() -> () {
    println!("Succesful test");
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_initCurve() -> () {
    init(CurveType::BLS12_381);
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_convertSerializedToGroupElementAndCompare(env: JNIEnv, _:JClass, group_element: jbyteArray) -> jstring {

    let rust_group_element = env.convert_byte_array(group_element).expect("Could not load group element buffer");

    let mut return_elem = unsafe{G1::uninit()};
    return_elem.deserialize(&rust_group_element);
    let mut compare_generator = unsafe{G1::uninit()};
    G1::set_str(&mut compare_generator, "1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10);
    if return_elem == compare_generator{
        println!("Both elems are the same .. Rust");
        return env.new_string(format!("True"))
        .expect("Couldn't create java string!").into_inner();
    }
    else {
        return env.new_string(format!("False"))
        .expect("Couldn't create java string!").into_inner();
    }
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getGenerator(env: JNIEnv, _:JClass) -> jbyteArray {
    let mut generator = unsafe{G1::uninit()};
    G1::set_str(&mut generator, "1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10);
    let generator_bytes = generator.serialize();
    let result = convertVecToByteArray(env, generator_bytes);
    return result;
}

#[no_mangle]
pub fn convertVecToByteArray(env: JNIEnv, vec: Vec<u8>) -> jbyteArray {
    let result = env.byte_array_from_slice(&vec).expect("Unable to retrieve slice");
    return result;

}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_getPublicKey(env: JNIEnv, _:JClass) -> jbyteArray {
    let mut output_pk = PublicKeyProto::new();
    let mut generator = unsafe{G1::uninit()};
    G1::set_str(&mut generator, "1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10);
    output_pk.g = generator.serialize();
    output_pk.g_powers.push(generator.serialize());
    output_pk.g_powers.push(generator.serialize());

    let mut generator_2 = unsafe{G2::uninit()};
    G2::set_str(&mut generator_2, 
        "1 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582", 10);

    output_pk.g_tilde = generator_2.serialize();
    output_pk.x_tilde = generator_2.serialize();
    output_pk.g_tilde_powers.push(generator_2.serialize());
    output_pk.g_tilde_powers.push(generator_2.serialize());
    output_pk.g_tilde_powers.push(generator_2.serialize());

    return convertVecToByteArray(env, output_pk.write_to_bytes().unwrap());
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_basicBenchmark(env: JNIEnv, _:JClass) -> jstring {
    println!("In benchmark============");
    let mut result1 = 0;
    let mut result2 = 0;
    let mut result3 = 0;
    let mut result4 = 0;
    let mut g1 = unsafe{G1::uninit()};
    let mut g = unsafe{G1::uninit()};
    
    let mut rand_power = Fr::zero();
    rand_power.set_by_csprng();
    G1::mul(&mut g, &g1, &rand_power);

    let start = SystemTime::now();
    for _ in 0..1000 {
        rand_power.set_by_csprng();
        G1::mul(&mut g1, &g, &rand_power);
    }

    match start.elapsed() {
        Ok(elapsed) => {
            // it prints '2'
            println!("1000 exp in G1 takes {}ms", elapsed.as_millis());
            result1 = elapsed.as_millis();

        }
        Err(e) => {
            // an error occurred!
            println!("Error: {e:?}");
        }
    }

    let mut g2 = unsafe{G2::uninit()};
    let mut g = unsafe{G2::uninit()};
    let mut rand_power = Fr::zero();
    rand_power.set_by_csprng();
    G2::mul(&mut g, &g2, &rand_power);

    let start2 = SystemTime::now();
    for _ in 0..1000 {
        rand_power.set_by_csprng();
        G2::mul(&mut g2, &g, &rand_power);
    }

    match start2.elapsed() {
        Ok(elapsed) => {
            // it prints '2'
            println!("1000 exp in G2 takes {}ms", elapsed.as_millis());
            result2 = elapsed.as_millis();
        }
        Err(e) => {
            // an error occurred!
            println!("Error: {e:?}");
        }
    }

    let mut gt = unsafe{GT::uninit()};
    let mut g = unsafe{GT::uninit()};
    let mut rand_power = Fr::zero();
    rand_power.set_by_csprng();
    GT::pow(&mut g, &gt, &rand_power);

    let startT = SystemTime::now();
    for _ in 0..1000 {
        rand_power.set_by_csprng();
        GT::pow(&mut gt, &g, &rand_power);
    }

    match startT.elapsed() {
        Ok(elapsed) => {
            // it prints '2'
            println!("1000 exp in GT takes {}ms", elapsed.as_millis());
            result3 = elapsed.as_millis();
        }
        Err(e) => {
            // an error occurred!
            println!("Error: {e:?}");
        }
    }

    let g = unsafe{G1::uninit()};
    let mut g1 = unsafe{G1::uninit()};
    let g2_prime = unsafe{G2::uninit()};
    let mut g2 = unsafe{G2::uninit()};
    let mut gT = unsafe{GT::uninit()};
    let mut rand_power = Fr::zero();
    let startPairing = SystemTime::now();
    for _ in 0..1000 {
        rand_power.set_by_csprng();
        G1::mul(&mut g1, &g, &rand_power);
        rand_power.set_by_csprng();
        G2::mul(&mut g2, &g2_prime, &rand_power);
        pairing(&mut gT, &g1, &g2);
    }
    match startPairing.elapsed() {
        Ok(elapsed) => {
            // it prints '2'
            println!("1000 pairing in GT takes {}ms", elapsed.as_millis());
            result4 = elapsed.as_millis();
        }
        Err(e) => {
            // an error occurred!
            println!("Error: {e:?}");
        }
    }
    return env.new_string(format!("G1 exp take {}, G2 exp take {}, GT exp take {}, GT pairings take {}", result1, result2, result3, result4))
        .expect("Couldn't create java string!").into_inner();
}

#[no_mangle]
pub extern "system" fn Java_ch_epfl_rcadsprototype_Crypto_returnPublicKeyAndCompare(env: JNIEnv, _:JClass, pk: jbyteArray) -> jstring {
    let pk_rust_bytes = env.convert_byte_array(pk).expect("Could not load protobuf pk");
    let response_pk = PublicKeyProto::parse_from_bytes(&pk_rust_bytes).unwrap();

    let mut generator = unsafe{G1::uninit()};
    G1::set_str(&mut generator, "1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10);

    let mut pk_generator = unsafe{G1::uninit()};
    pk_generator.deserialize(&response_pk.g);

    let g_powers = response_pk.g_powers;
    let g_power_one = &g_powers[0];
    let mut test_g_power = unsafe{G1::uninit()};
    test_g_power.deserialize(g_power_one);
    assert!(test_g_power == generator);
    let g_power_two = &g_powers[1];
    let mut test_g_power_two = unsafe{G1::uninit()};
    test_g_power_two.deserialize(g_power_two);
    assert!(test_g_power_two == generator);
    if pk_generator == generator {
        return env.new_string(format!("True"))
        .expect("Couldn't create java string!").into_inner();
    }
    else {
        return env.new_string(format!("False"))
        .expect("Couldn't create java string!").into_inner();
    }
}

