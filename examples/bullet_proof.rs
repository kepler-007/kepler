use byteorder::{BigEndian, WriteBytesExt};
use secp256k1zkp::constants::MESSAGE_SIZE;
use secp256k1zkp::key::PublicKey;
use secp256k1zkp::{aggsig, ContextFlag, Error, Message, Secp256k1};

fn main() -> Result<(), Error> {
    // 1. Secp256k1
    let secp = Secp256k1::with_caps(ContextFlag::Commit);

    let value = 100;
    let (o_sk, _o_pk) = secp.generate_keypair(&mut rand::thread_rng())?;
    let output = secp.commit(value, o_sk)?;

    let (nonce_sk, _nonce_pk) = secp.generate_keypair(&mut rand::thread_rng())?;
    let proof = secp.bullet_proof(value, o_sk, nonce_sk, o_sk, None, None);

    let mut hex = String::new();
    hex.extend(proof.bytes().iter().map(|byte| format!("{:02x?}", byte)));
    println!("proof: len: {}, value: {}", proof.len(), hex);

    println!(
        "verify: {:?}",
        secp.verify_bullet_proof(output, proof, None)?
    );

    let q_generator = secp.generate_generator_with_hash("DEMO");
    let q_output = secp.commit_with_generator(value, o_sk, q_generator)?;
    let q_proof =
        secp.bullet_proof_with_generator(value, o_sk, nonce_sk, o_sk, None, None, q_generator);

    let mut hex = String::new();
    hex.extend(q_proof.bytes().iter().map(|byte| format!("{:02x?}", byte)));
    println!("proof: len: {}, value: {}", q_proof.len(), hex);

    println!(
        "verify: {:?}",
        secp.verify_bullet_proof_with_generator(q_output, q_proof, None, q_generator)?
    );

    Ok(())
}
