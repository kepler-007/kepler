use byteorder::{BigEndian, WriteBytesExt};
use secp256k1zkp::constants::MESSAGE_SIZE;
use secp256k1zkp::key::PublicKey;
use secp256k1zkp::{aggsig, ContextFlag, Error, Message, Secp256k1};
use sha2::{Digest, Sha256};

fn generate_message(fee: u64, lock_height: u64) -> Message {
    let mut message_bytes = [0u8; MESSAGE_SIZE];

    let mut fee_wtr = vec![];
    fee_wtr.write_u64::<BigEndian>(fee).unwrap();

    let mut height_wtr = vec![];
    height_wtr.write_u64::<BigEndian>(lock_height).unwrap();

    let mut hasher = Sha256::new();
    hasher.input(fee_wtr);
    hasher.input(height_wtr);

    if MESSAGE_SIZE >= 32 {
        message_bytes[..32].copy_from_slice(hasher.result().as_slice());
    } else {
        message_bytes.copy_from_slice(&hasher.result()[..MESSAGE_SIZE]);
    };

    Message::from(message_bytes)
}

fn main() -> Result<(), Error> {
    //////////////////
    // Input Output //
    //////////////////

    // 1. Secp256k1
    let secp = Secp256k1::with_caps(ContextFlag::Commit);

    // 2. new a curve generator Q by hash assert symbol
    let q_generator = secp.generate_generator_with_hash("DEMO");
    // println!("Q: {:?}", q_generator);

    // 3. random a secret key i (sender)
    let (i_sk, _i_pk) = secp.generate_keypair(&mut rand::thread_rng())?;

    // 4. commit aH + iG, a is amount, H is choose Point
    let i_input = secp.commit(100, i_sk.clone())?;

    // 5. random another secret key q
    let (q_sk, _q_pk) = secp.generate_keypair(&mut rand::thread_rng())?;

    // 6. commit aQ + qG use generator Q, as a amount in asset Q
    let q_input = secp.commit_with_generator(10, q_sk.clone(), q_generator)?;

    // 7. random a secret key o (receiver)
    // 8. get public key opk by secret key o
    let (o_sk, o_pk) = secp.generate_keypair(&mut rand::thread_rng())?;

    // 9. commit aH + oG, a is received amount, corresponding to i's a
    let o_output = secp.commit(100, o_sk.clone())?;

    // 10. random a secret key qo
    // 11. get public key qopk by secret key qokey
    let (qo_sk, qo_pk) = secp.generate_keypair(&mut rand::thread_rng())?;

    // 12. commit aG + qoG, a is corresponding to q's a
    let qo_output = secp.commit_with_generator(10, qo_sk.clone(), q_generator)?;

    // 13. commit_sum [output-aH, output-aQ], [input-aH, input-aQ]
    let kernel = secp.commit_sum(vec![o_output, qo_output], vec![i_input, q_input])?;

    // 14. get kernel_pk public key by commit_sum result as secret key
    let kernel_pk = kernel.to_pubkey(&secp)?;

    /////////////////////
    // Group Signature //
    /////////////////////
    let fee = 0;
    let height = 0;
    let message = generate_message(fee, height);

    // 1. generate signpsk and signpk by i, and generate helper random psk, pk for i
    let (i_nonce_sk, i_nonce_pk) = secp.generate_keypair(&mut rand::thread_rng())?;

    let mut i_sign_sk = i_sk.clone();
    i_sign_sk.neg_assign(&secp)?;
    let i_sign_pk = PublicKey::from_secret_key(&secp, &i_sign_sk)?;

    // 2. generate signpsk and signpk by q, and genreate helper random psk, pk for q
    let (q_nonce_sk, q_nonce_pk) = secp.generate_keypair(&mut rand::thread_rng())?;

    let mut q_sign_sk = q_sk.clone();
    q_sign_sk.neg_assign(&secp)?;
    let q_sign_pk = PublicKey::from_secret_key(&secp, &q_sign_sk)?;

    // 3. generate helper random psk, pk for o
    let (o_nonce_sk, o_nonce_pk) = secp.generate_keypair(&mut rand::thread_rng())?;

    // 4. generate helper random psk, pk for qo
    let (qo_nonce_sk, qo_nonce_pk) = secp.generate_keypair(&mut rand::thread_rng())?;

    // 5. combinate nonce_pk_sum, [nonce_i, nonce_o, nonce_q, nonce_qo]
    let nonce_pk_sum = PublicKey::from_combination(
        &secp,
        vec![&i_nonce_pk, &o_nonce_pk, &q_nonce_pk, &qo_nonce_pk],
    )?;

    // 6. combinate pk_sum [pk_o, pk_sign_i, pk_qo, pk_sign_qo]
    let pk_sum = PublicKey::from_combination(&secp, vec![&o_pk, &i_sign_pk, &qo_pk, &q_sign_pk])?;

    // 7. calculate_partial sign_partial_i: sign_i, nonce_i, pk_sum, nonce_pk_sum, fee, height
    let i_partial_sig = aggsig::sign_single(
        &secp,
        &message,
        &i_sign_sk,
        Some(&i_nonce_sk),
        None,
        Some(&nonce_pk_sum),
        Some(&pk_sum),
        Some(&nonce_pk_sum),
    )?;

    // 8. calculate_partial sign_partial_q: sign_q, nonce_q, pk_sum, nonce_pk_sum, fee, height
    let q_partial_sig = aggsig::sign_single(
        &secp,
        &message,
        &q_sign_sk,
        Some(&q_nonce_sk),
        None,
        Some(&nonce_pk_sum),
        Some(&pk_sum),
        Some(&nonce_pk_sum),
    )?;

    // 9. calculate_partial sign_partial_o: psk_o, nonce_o, ...
    let o_partial_sig = aggsig::sign_single(
        &secp,
        &message,
        &o_sk,
        Some(&o_nonce_sk),
        None,
        Some(&nonce_pk_sum),
        Some(&pk_sum),
        Some(&nonce_pk_sum),
    )?;

    // 10. calculate_partial sign_partial_qo: psk_qo, nonce_qo, ...
    let qo_partial_sig = aggsig::sign_single(
        &secp,
        &message,
        &qo_sk,
        Some(&qo_nonce_sk),
        None,
        Some(&nonce_pk_sum),
        Some(&pk_sum),
        Some(&nonce_pk_sum),
    )?;

    // 11. test verify_partial(sign_partial_i, pk_sign_i, ...)
    println!(
        "verify i_partial_sig: {}",
        aggsig::verify_single(
            &secp,
            &i_partial_sig,
            &message,
            Some(&nonce_pk_sum),
            &i_sign_pk,
            Some(&pk_sum),
            None,
            true
        )
    );

    // 12. test verify_partial(sign_partial_o, pk_sign_o, ...)
    println!(
        "verify o_partial_sig: {}",
        aggsig::verify_single(
            &secp,
            &o_partial_sig,
            &message,
            Some(&nonce_pk_sum),
            &o_pk,
            Some(&pk_sum),
            None,
            true
        )
    );

    // 13. add_partials: sign_partial_i, sign_partial_o, sign_partial_o, sign_partial_qo, nonce_pk_sum
    let signature = aggsig::add_signatures_single(
        &secp,
        vec![
            &i_partial_sig,
            &o_partial_sig,
            &q_partial_sig,
            &qo_partial_sig,
        ],
        &nonce_pk_sum,
    )?;

    // 14. verify signature, pk_sum, fee, height
    println!(
        "verify signature: {}",
        aggsig::verify_single(
            &secp,
            &signature,
            &message,
            Some(&nonce_pk_sum),
            &pk_sum,
            Some(&pk_sum),
            None,
            false
        )
    );

    println!(
        "verify signature: {}",
        aggsig::verify_single(
            &secp,
            &signature,
            &message,
            None,
            &pk_sum,
            Some(&pk_sum),
            None,
            false
        )
    );

    // 15. check equal kernel_pk == pk_sum
    println!(
        "signature publick key eq committment excess: {}",
        kernel_pk == pk_sum
    );

    return Ok(());
}
