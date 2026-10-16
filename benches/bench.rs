// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench --no-default-features --features "std parallel" -- --nocapture
// where N is the number of threads you want to use (N = 1 for single-thread).

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ff::PrimeField;
use ark_mnt4_298::{Fr as MNT4Fr, MNT4_298};
use ark_mnt4_753::{Fr as MNT4BigFr, MNT4_753};
use ark_mnt6_298::{Fr as MNT6Fr, MNT6_298};
use ark_mnt6_753::{Fr as MNT6BigFr, MNT6_753};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::sonic_pc::SonicKZG10;
use ark_std::{ops::Mul, UniformRand};
use blake2::Blake2s;
use dfs::snark::indexer::Indexer;
use dfs::snark::zk::SRS;
use dfs::snark::R1CSProof;
use dfs::utils::produce_test_r1cs;
use dfs::R1CSInstance;
use rand_chacha::ChaChaRng;

const NUM_PROVE_REPEATITIONS: usize = 1;
const NUM_VERIFY_REPEATITIONS: usize = 1;

#[derive(Copy)]
struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> Clone for DummyCircuit<F> {
    fn clone(&self) -> Self {
        DummyCircuit {
            a: self.a.clone(),
            b: self.b.clone(),
            num_variables: self.num_variables.clone(),
            num_constraints: self.num_constraints.clone(),
        }
    }
}

macro_rules! dfs_prove_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let rng = &mut ark_std::test_rng();

        for num_vars in 15..25 {
            let num_cons = 1 << num_vars;
            // let num_z = 1 << num_vars;
            // let num_wit = 1 << (num_vars - 1);
            let (r1cs, z, _, _, _) = produce_test_r1cs::<$bench_field>(num_vars, rng);
            // R1CSInstance::<$bench_field>::produce_synthetic_r1cs(num_cons, num_z, num_wit, rng);
            // let num_vars = 16 + 3;
            let srs = SRS::<$bench_pairing_engine, _>::generate_srs(num_vars, 4, rng);
            let (pk, vk) = Indexer::index_for_prover_and_verifier(&r1cs, &srs);

            let start = ark_std::time::Instant::now();

            for _ in 0..NUM_PROVE_REPEATITIONS {
                let _ = R1CSProof::new(&r1cs, &pk, &vk, &z, &Vec::new());
            }

            let final_time = start.elapsed();
            println!(
                "proving time for 2^{:?} num_cons: {:?}",
                num_vars,
                final_time / NUM_PROVE_REPEATITIONS as u32
            );
        }

        // println!(
        //     "per-constraint proving time for {}: {} ns/constraint",
        //     stringify!($bench_pairing_engine),
        //     start.elapsed().as_nanos() / NUM_PROVE_REPEATITIONS as u128 / 65536u128
        // );
    };
}

macro_rules! dfs_verify_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let rng = &mut ark_std::test_rng();
        for num_vars in 15..25 {
            let num_cons = 1 << num_vars;
            // let num_z = 1 << num_vars;
            // let num_wit = 1 << (num_vars - 1);
            let (r1cs, z, _, _, _) = produce_test_r1cs::<$bench_field>(num_vars, rng);
            // R1CSInstance::<$bench_field>::produce_synthetic_r1cs(num_cons, num_z, num_wit, rng);
            // let num_vars = 16 + 3;
            let srs = SRS::<$bench_pairing_engine, _>::generate_srs(num_vars, 4, rng);
            let (pk, vk) = Indexer::index_for_prover_and_verifier(&r1cs, &srs);
            let proof = R1CSProof::new(&r1cs, &pk, &vk, &z, &Vec::new());

            let start = ark_std::time::Instant::now();

            for _ in 0..NUM_VERIFY_REPEATITIONS {
                let _ = proof.verify(&vk, &Vec::new());
            }

            let final_time = start.elapsed();
            println!(
                "verification time for 2^{:?} num_cons: {:?}",
                num_vars,
                final_time / NUM_PROVE_REPEATITIONS as u32
            );

            // println!(
            //     "verifying time for {}: {} ms",
            //     stringify!($bench_pairing_engine),
            //     // start.elapsed().as_nanos() / NUM_VERIFY_REPEATITIONS as u128
            //     start.elapsed().as_micros()
            // );
        }
    };
}
fn bench_prove() {
    dfs_prove_bench!(bls, BlsFr, Bls12_381);
    // dfs_prove_bench!(mnt4, MNT4Fr, MNT4_298);
    // dfs_prove_bench!(mnt6, MNT6Fr, MNT6_298);
    // dfs_prove_bench!(mnt4big, MNT4BigFr, MNT4_753);
    // dfs_prove_bench!(mnt6big, MNT6BigFr, MNT6_753);
}
fn bench_verify() {
    dfs_verify_bench!(bls, BlsFr, Bls12_381);
    // dfs_verify_bench!(mnt4, MNT4Fr, MNT4_298);
    // dfs_verify_bench!(mnt6, MNT6Fr, MNT6_298);
    // dfs_verify_bench!(mnt4big, MNT4BigFr, MNT4_753);
    // dfs_verify_bench!(mnt6big, MNT6BigFr, MNT6_753);
}

fn main() {
    bench_prove();
    bench_verify();
}
