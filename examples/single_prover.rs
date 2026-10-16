#![allow(warnings)]
use ark_std::{cfg_chunks, cfg_chunks_mut, cfg_into_iter, cfg_iter};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, Subcommand};
use mpi::{
    datatype::{Partition, PartitionMut},
    topology::Process,
    Count,
};
use mpi::{request, traits::*};
// use mpi_snark::worker::WorkerState;

use std::{
    fs::File,
    io::{Read, Write},
    num::NonZeroUsize,
    path::PathBuf,
};

use mimalloc::MiMalloc;

use crossbeam::thread;
use itertools::{merge, Itertools};
use rayon::prelude::*;

use ark_bls12_381::Config;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

use core::num;
use std::mem;
use std::{collections::HashMap, rc::Rc};

use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, One, Zero};
use ark_linear_sumcheck::ml_sumcheck::protocol::verifier::SubClaim;
use ark_linear_sumcheck::ml_sumcheck::protocol::IPForMLSumcheck;
use ark_linear_sumcheck::ml_sumcheck::protocol::PolynomialInfo;
use ark_linear_sumcheck::ml_sumcheck::{protocol::ListOfProductsOfPolynomials, MLSumcheck};
use ark_linear_sumcheck::rng::{Blake2s512Rng, FeedableRNG};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_poly_commit::challenge::ChallengeGenerator;

use ark_poly_commit::multilinear_pc::{
    data_structures::Commitment, data_structures::CommitterKey, data_structures::VerifierKey,
    MultilinearPC,
};
use dfs::mpi_snark::worker::PublicProver;
use dfs::subprotocols::loglookup::sumcheck_polynomial_list;
use dfs::subprotocols::loglookup::LogLookupProof;
use dfs::utils::generate_dumb_sponge;
use dfs::{mpi_snark::coordinator::mpi_batch_open_poly_coordinator, utils::produce_test_r1cs};
use dfs::{mpi_utils::send_responses, utils::split_ipk};
use dfs::{snark::indexer::Indexer, R1CSInstance};
use dfs::{snark::zk::SRS, utils::split_r1cs};

use dfs::utils::{
    aggregate_comm, aggregate_eval, aggregate_poly, boost_degree, combine_comm, distributed_open,
    generate_eq, map_poly, merge_list_of_distributed_poly, merge_proof, normalized_multiplicities,
    partial_generate_eq, split_ck, split_poly, split_vec, two_pow_n,
};
use dfs::{end_timer_buf, start_timer_buf};
use dfs::{VerificationError, VerificationResult};
use rand::RngCore;

use dfs::mpi_snark::coordinator::{mpi_poly_commit_coordinator, mpi_sumcheck_coordinator};
use dfs::mpi_snark::worker::DistributedProverKey;
use dfs::mpi_snark::worker::{mpi_batch_open_poly_worker, mpi_sumcheck_worker};
use dfs::mpi_utils::{gather_responses, receive_requests, scatter_requests};
use dfs::snark::indexer::IndexProverKey;
use dfs::snark::indexer::IndexVerifierKey;
use dfs::snark::prover::ProverMessage;
use dfs::snark::verifier::DFSVerifier;
use dfs::snark::verifier::VerifierState;
use dfs::snark::R1CSProof;
use dfs::snark::{batch_open_poly, batch_verify_poly, BatchOracleEval, OracleEval};
use dfs::transcript::{get_scalar_challenge, get_vector_challenge};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DistributedRootKey<E: Pairing> {
    pub ipk: IndexProverKey<E>,
    pub ivk: IndexVerifierKey<E>,
}

// #[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
// pub struct Round1Msg<E: Pairing> {
//     pub comm_0: Commitment<E>,
//     pub comm_1: Commitment<E>,
// }

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Work {
        #[clap(long, value_name = "NUM")]
        log_instance_size: usize,

        #[clap(long, value_name = "NUM")]
        num_repeatition: usize,
    },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Command::Work {
            log_instance_size,
            num_repeatition,
        } => {
            work::<Bls12_381>(log_instance_size, num_repeatition);
        }
    }
}

fn work<E: Pairing>(log_instance_size: usize, num_repeatition: usize) {
    let rng = &mut ark_std::test_rng();
    for num_vars in 12..13 {
        let num_cons = 1 << num_vars;
        // let num_z = 1 << num_vars;
        // let num_wit = 1 << (num_vars - 1);
        let (r1cs, z, _, _, _) = produce_test_r1cs(num_vars, rng);
        // R1CSInstance::<$bench_field>::produce_synthetic_r1cs(num_cons, num_z, num_wit, rng);
        // let num_vars = 16 + 3;
        let srs = SRS::<E, _>::generate_srs(num_vars, 4, rng);
        let (pk, vk) = Indexer::index_for_prover_and_verifier(&r1cs, &srs);

        let start = ark_std::time::Instant::now();

        for _ in 0..num_repeatition {
            let _ = R1CSProof::new(&r1cs, &pk, &vk, &z, &Vec::new());
        }

        let prove_final_time = start.elapsed();

        let proof = R1CSProof::new(&r1cs, &pk, &vk, &z, &Vec::new());

        let start = ark_std::time::Instant::now();

        for _ in 0..num_repeatition {
            let _ = proof.verify(&vk, &Vec::new());
        }

        let verify_final_time = start.elapsed();

        println!(
            "proving time for 2^{:?} num_cons: {:?}",
            num_vars,
            prove_final_time / num_repeatition as u32
        );

        println!(
            "verification time for 2^{:?} num_cons: {:?}",
            num_vars,
            verify_final_time / num_repeatition as u32
        );
    }
}
