use bls12_381::*;
use ff::Field;
use group::{Curve, Group};
use rand::thread_rng;


struct Generators {
    p1: G1Projective,
    p2: G2Projective,
    h0: G1Affine,
    revealed_msg_generators: Vec<G1Affine>,
    hidden_msg_generators: Vec<G1Affine>
}

struct Sdk {
    c: Scalar,
    e_hat: Scalar,
    r2_hat: Scalar,
    r3_hat: Scalar,
    s_hat: Scalar,
    hidden_msg_hat: Vec<Scalar>,
    c1: G1Affine,
    c2: G1Affine
}

fn spk_verify(
    w: G2Affine,
    a_prime: G1Affine,
    a_bar: G1Projective,
    d: G1Affine,
    sdk: Sdk,
    revealed_msgs: Vec<Scalar>,
    generators: Generators
) -> bool {
    let Sdk {c, e_hat, r2_hat, r3_hat, s_hat, hidden_msg_hat, c1, c2 } = sdk;
    let Generators { p1, p2, h0, revealed_msg_generators, hidden_msg_generators} = generators;

    let c1_v =  (((a_bar - d) * c) + a_prime * e_hat + h0 * r2_hat).to_affine();

    if revealed_msgs.len() != revealed_msg_generators.len() { return false }
    if hidden_msg_hat.len() != hidden_msg_generators.len() { return false }

    let mut t = p1;
    for i in 0..revealed_msgs.len() {
        t += revealed_msg_generators[i] * revealed_msgs[i];
    }

    let mut hidden_t = G1Projective::identity();
    for j in 0..hidden_msg_generators.len() {
        hidden_t += hidden_msg_generators[j] * hidden_msg_hat[j];
    }

    let c2_v = (t * c + d * (-r3_hat) + h0 * s_hat + hidden_t).to_affine();

    if c1 != c1_v {return false};
    if c2 != c2_v {return false};
    if pairing(&(a_bar.to_affine()), &(p2.to_affine())) != pairing(&a_prime, &w)
    {
        return false
    }
    true
}


fn main() {
    let mut rng = thread_rng();
    // base points
    let p1 = G1Projective::generator();
    let p2 = G2Projective::generator();
    // issuer keys
    let x = Scalar::random(&mut rng);
    let w = (p2 * x).to_affine();
    // message generators
    let h0 = G1Projective::random(&mut rng).to_affine();
    let h_1 = G1Projective::random(&mut rng).to_affine();
    let h_2 = G1Projective::random(&mut rng).to_affine();
    let h_3 = G1Projective::random(&mut rng).to_affine();
    // messages
    let m_1 = Scalar::random(&mut rng);
    let m_2 = Scalar::random(&mut rng);

    // signature
    let e = Scalar::random(&mut rng);
    let s = Scalar::random(&mut rng);
    let b = (p1 + h0 * s + h_1 * m_1 + h_2 * m_2).to_affine();
    let a = (b * (e + x).invert().unwrap()).to_affine();

    // Check regular signature
    assert_eq!(
        pairing(&b, &p2.to_affine()),
        pairing(&a, &(w + p2 * e).to_affine())
    );

    // proof
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);

    let r3 = r1.invert().unwrap();

    let e_tilde = Scalar::random(&mut rng);
    let s_tilde = Scalar::random(&mut rng);
    let r2_tilde = Scalar::random(&mut rng);
    let r3_tilde = Scalar::random(&mut rng);
    let m_2_tilde = Scalar::random(&mut rng);

    let a_prime = (a * r1).to_affine();
    let a_bar = a_prime * (-e) + b * r1;
    let d = (b * r1 + h0 * r2).to_affine();
    let s_prime = s + r2*r3;

    let c1_p = (a_prime * e_tilde + h0 * r2_tilde).to_affine();
    let c2_p = (d * (-r3_tilde) + h0 * s_tilde + h_2 * m_2_tilde).to_affine();

    let c = Scalar::random(&mut rng);

    let e_hat = e_tilde + c * e;
    let s_hat = s_tilde + c * s_prime;
    let r2_hat = r2_tilde + c * r2;
    let r3_hat = r3_tilde + c * r3;
    let m_2_hat = m_2_tilde +  c * m_2;

    let gens = Generators {p1, p2, h0, revealed_msg_generators: vec![h_1], hidden_msg_generators: vec![h_2]};
    let sdk = Sdk {c, e_hat, r2_hat, r3_hat, s_hat, hidden_msg_hat: vec![m_2_hat], c1: c1_p, c2: c2_p};

    // Check the proof
    let result = spk_verify(w, a_prime, a_bar, d, sdk, vec![m_1], gens);

    assert_eq!(result, true);


    // add an additional "un-disclosed" message to the proof
    let m_new = Scalar::random(&mut rng);
    let c2_p_new = (c2_p + h_3*m_new).to_affine();

    let gens_2 = Generators {p1, p2, h0, revealed_msg_generators: vec![h_1], hidden_msg_generators: vec![h_2, h_3]};
    let sdk_2 = Sdk {c, e_hat, r2_hat, r3_hat, s_hat, hidden_msg_hat: vec![m_2_hat, m_new], c1: c1_p, c2: c2_p_new};

    let result_2 =  spk_verify(w, a_prime, a_bar, d, sdk_2, vec![m_1], gens_2);

    assert_eq!(result_2, true);
}