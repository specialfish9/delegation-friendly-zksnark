use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_linear_sumcheck::rng::Blake2s512Rng;
use ark_linear_sumcheck::rng::FeedableRNG;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use rand::Rng;
use rand::RngCore;

use super::ass::AssShare;
use super::rss::SSRandom;
use ark_ff::Zero;
// use ark_ff::UniformRand;

#[derive(PartialEq, Eq)]
pub enum ShareType {
    Ass,
    Rss,
}

pub fn generate_poly_shares_rss<F: Field, R: Rng>(
    poly: &DenseMultilinearExtension<F>,
    rng: &mut R,
) -> (
    DenseMultilinearExtension<F>,
    DenseMultilinearExtension<F>,
    DenseMultilinearExtension<F>,
) {
    let num_vars = poly.num_vars;
    let p_share_0 = DenseMultilinearExtension::<F>::rand(num_vars, rng);
    let p_share_1 = DenseMultilinearExtension::<F>::rand(num_vars, rng);
    let p_share_2 = (poly - &p_share_0) - p_share_1.clone();

    (p_share_0, p_share_1, p_share_2)
}

pub fn generate_ass_share<E: Pairing, R: Rng>(
    element: E::ScalarField,
    rng: &mut R,
) -> (AssShare<E>, AssShare<E>) {
    use ark_ff::UniformRand;
    let share_0 = E::ScalarField::rand(rng);
    let share_1 = element - &share_0;

    (
        AssShare {
            party: 0,
            share_0: share_0,
        },
        AssShare {
            party: 1,
            share_0: share_1,
        },
    )
}

pub fn generate_poly_shares_ass<F: Field, R: Rng>(
    poly: &DenseMultilinearExtension<F>,
    rng: &mut R,
) -> (DenseMultilinearExtension<F>, DenseMultilinearExtension<F>) {
    let num_vars = poly.num_vars;
    let p_share_0 = DenseMultilinearExtension::<F>::rand(num_vars, rng);
    let p_share_1 = poly - &p_share_0;

    (p_share_0, p_share_1)
}

pub fn generate_rss_share_randomness<R: RngCore + FeedableRNG>() -> Vec<SSRandom<R>> {
    let mut seed_0 = R::setup();
    seed_0.feed(&"seed 0".as_bytes());
    let mut seed_1 = R::setup();
    seed_1.feed(&"seed 1".as_bytes());
    let mut random_0 = SSRandom::<R>::new(seed_0, seed_1);

    let mut seed_1 = R::setup();
    seed_1.feed(&"seed 1".as_bytes());
    let mut seed_2 = R::setup();
    seed_2.feed(&"seed 2".as_bytes());
    let mut random_1 = SSRandom::<R>::new(seed_1, seed_2);

    let mut seed_2 = R::setup();
    seed_2.feed(&"seed 2".as_bytes());
    let mut seed_0 = R::setup();
    seed_0.feed(&"seed 0".as_bytes());
    let mut random_2 = SSRandom::<R>::new(seed_2, seed_0);

    let mut vec_random = vec![random_0, random_1, random_2];
    vec_random
}

pub fn generate_ass_share_randomness<R: RngCore + FeedableRNG>() -> Vec<SSRandom<R>> {
    let mut seed_0 = R::setup();
    seed_0.feed(&"seed 0".as_bytes());
    let mut seed_1 = R::setup();
    seed_1.feed(&"seed 1".as_bytes());
    let mut random_0 = SSRandom::<R>::new(seed_0, seed_1);

    let mut seed_1 = R::setup();
    seed_1.feed(&"seed 1".as_bytes());
    let mut seed_0 = R::setup();
    seed_0.feed(&"seed 0".as_bytes());
    let mut random_1 = SSRandom::<R>::new(seed_1, seed_0);

    let mut vec_random = vec![random_0, random_1];
    vec_random
}

pub fn generate_beaver_triple<E: Pairing, R: Rng>(
    rng: &mut R,
) -> (
    (AssShare<E>, AssShare<E>, AssShare<E>),
    (AssShare<E>, AssShare<E>, AssShare<E>),
) {
    use ark_ff::UniformRand;
    let a = E::ScalarField::rand(rng);
    let b = E::ScalarField::rand(rng);
    let ab = a * b;
    let (a_0, a_1) = generate_ass_share(a, rng);
    let (b_0, b_1) = generate_ass_share(b, rng);
    let (ab_0, ab_1) = generate_ass_share(ab, rng);

    ((a_0, b_0, ab_0), (a_1, b_1, ab_1))
}

pub fn generate_beaver_triple_for_sumcheck<E: Pairing, R: Rng>(
    nvar: usize,
    deg: usize,
    rng: &mut R,
) -> (
    (
        Vec<Vec<Vec<AssShare<E>>>>,
        Vec<Vec<Vec<AssShare<E>>>>,
        Vec<Vec<Vec<AssShare<E>>>>,
    ),
    (
        Vec<Vec<Vec<AssShare<E>>>>,
        Vec<Vec<Vec<AssShare<E>>>>,
        Vec<Vec<Vec<AssShare<E>>>>,
    ),
) {
    use ark_ff::UniformRand;
    let mut bt_a_0 = Vec::new();
    let mut bt_b_0 = Vec::new();
    let mut bt_ab_0 = Vec::new();

    let mut bt_a_1 = Vec::new();
    let mut bt_b_1 = Vec::new();
    let mut bt_ab_1 = Vec::new();

    for i in 0..nvar {
        let mut bt_a_0_first = Vec::new();
        let mut bt_b_0_first = Vec::new();
        let mut bt_ab_0_first = Vec::new();

        let mut bt_a_1_first = Vec::new();
        let mut bt_b_1_first = Vec::new();
        let mut bt_ab_1_first = Vec::new();

        for b in 0..1 << (nvar - i) {
            let mut bt_a_0_second = Vec::new();
            let mut bt_b_0_second = Vec::new();
            let mut bt_ab_0_second = Vec::new();

            let mut bt_a_1_second = Vec::new();
            let mut bt_b_1_second = Vec::new();
            let mut bt_ab_1_second = Vec::new();

            for t in 0..deg + 1 {
                let a = E::ScalarField::zero(); //E::ScalarField::rand(rng);
                let b = E::ScalarField::zero(); //E::ScalarField::rand(rng);
                let ab = a * b;

                let (a_0, a_1) = generate_ass_share(a, rng);
                bt_a_0_second.push(a_0);
                bt_a_1_second.push(a_1);

                let (b_0, b_1) = generate_ass_share(b, rng);
                bt_b_0_second.push(b_0);
                bt_b_1_second.push(b_1);

                let (ab_0, ab_1) = generate_ass_share(ab, rng);
                bt_ab_0_second.push(ab_0);
                bt_ab_1_second.push(ab_1);
            }

            bt_a_0_first.push(bt_a_0_second);
            bt_b_0_first.push(bt_b_0_second);
            bt_ab_0_first.push(bt_ab_0_second);

            bt_a_1_first.push(bt_a_1_second);
            bt_b_1_first.push(bt_b_1_second);
            bt_ab_1_first.push(bt_ab_1_second);
        }
        bt_a_0.push(bt_a_0_first);
        bt_b_0.push(bt_b_0_first);
        bt_ab_0.push(bt_ab_0_first);

        bt_a_1.push(bt_a_1_first);
        bt_b_1.push(bt_b_1_first);
        bt_ab_1.push(bt_ab_1_first);
    }

    ((bt_a_0, bt_b_0, bt_ab_0), (bt_a_1, bt_b_1, bt_ab_1))
}
