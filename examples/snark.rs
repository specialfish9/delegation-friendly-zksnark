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
use dfs::subprotocols::loglookup::sumcheck_polynomial_list;
use dfs::subprotocols::loglookup::LogLookupProof;
use dfs::utils::generate_dumb_sponge;
use dfs::{mpc_snark::coordinator, mpi_snark::worker::PublicProver};
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

use ark_std::fs;
use dfs::mpi_snark::coordinator::{mpi_poly_commit_coordinator, mpi_sumcheck_coordinator};
use dfs::mpi_snark::worker::DistributedProverKey;
use dfs::mpi_snark::worker::{mpi_batch_open_poly_worker, mpi_sumcheck_worker};
use dfs::mpi_utils::{gather_responses, receive_requests, scatter_requests};
use dfs::snark::indexer::IndexProverKey;
use dfs::snark::indexer::IndexVerifierKey;
use dfs::snark::prover::ProverMessage;
use dfs::snark::verifier::DFSVerifier;
use dfs::snark::verifier::VerifierState;
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
    Setup {
        #[clap(long, value_name = "NUM")]
        log_instance_size: usize,

        #[clap(long, value_name = "NUM")]
        log_num_parties: usize,

        #[clap(long, value_name = "DIR")]
        key_out: PathBuf,
    },

    Work {
        /// Path to the coordinator key package
        #[clap(long, value_name = "DIR")]
        key_file: PathBuf,

        #[clap(long, value_name = "NUM")]
        log_instance_size: usize,

        /// The number of workers who will do the committing and proving. Each worker has 1 core.
        #[clap(long, value_name = "NUM")]
        log_num_parties: usize,

        #[clap(long, value_name = "NUM")]
        worker_id: usize,

        #[clap(long, value_name = "NUM")]
        local: usize,
    },
}

fn main() {
    println!("Rayon num threads: {}", current_num_threads());

    let args = Args::parse();

    match args.command {
        Command::Setup {
            log_instance_size,
            log_num_parties,
            key_out,
        } => setup::<Bls12_381>(key_out, log_instance_size, log_num_parties),
        Command::Work {
            key_file,
            log_num_parties,
            log_instance_size,
            worker_id,
            local,
        } => {
            work::<Bls12_381>(
                log_num_parties,
                log_instance_size,
                key_file,
                worker_id,
                local,
            );
        }
    }
}

fn setup<E: Pairing>(
    origin_key_out_path: PathBuf,
    log_instance_size: usize,
    log_num_parties: usize,
) {
    let D: usize = log_instance_size;
    let P: usize = log_num_parties;

    let mut rng = StdRng::seed_from_u64(12);
    let (r1cs, z, za, zb, zc) = produce_test_r1cs(D, &mut rng);

    let srs = SRS::<E, _>::generate_srs(D + 2, 4, &mut rng);

    let (pk, vk) = Indexer::index_for_prover_and_verifier(&r1cs, &srs);

    let (ipk_vec, root_ipk) = split_ipk(&pk, P);
    // let r1cs_vec = split_r1cs(&r1cs, P);
    let z_vec = split_vec(&z, P);
    let za_vec = split_vec(&za, P);
    let zb_vec = split_vec(&zb, P);
    let zc_vec = split_vec(&zc, P);

    let mut key_out_path = origin_key_out_path.clone();

    fs::create_dir(
        "inst_folder/inst_".to_owned() + &log_instance_size.to_string() + "_" + &P.to_string(),
    );
    key_out_path
        .push("inst_".to_owned() + &log_instance_size.to_string() + "_" + &P.to_string() + "/test");

    for i in 0..1 << P {
        let mut buf = Vec::new();
        let pk = DistributedProverKey {
            ipk: ipk_vec[i].clone(),
            // r1cs: r1cs_vec[i].clone(),
            z: z_vec[i].clone(),
            za: za_vec[i].clone(),
            zb: zb_vec[i].clone(),
            zc: zc_vec[i].clone(),
            num_variables: r1cs.num_vars,
        };
        pk.serialize_uncompressed(&mut buf).unwrap();

        let mut file_name = key_out_path.clone();
        file_name.set_extension(i.to_string());

        let mut f =
            File::create(&file_name).expect(&format!("could not create file {:?}", key_out_path));
        f.write_all(&buf).unwrap();
    }

    {
        let mut buf = Vec::new();
        let pk = DistributedRootKey {
            ipk: root_ipk,
            ivk: vk,
        };
        pk.serialize_uncompressed(&mut buf).unwrap();
        let mut file_name = key_out_path.clone();
        file_name.set_extension("root");
        let mut f =
            File::create(&file_name).expect(&format!("could not create file {:?}", key_out_path));
        f.write_all(&buf).unwrap();
    }
}

fn work<E: Pairing>(
    log_num_parties: usize,
    log_instance_size: usize,
    key_file: PathBuf,
    mut worker_id: usize,
    local: usize,
) {
    let mut send_size = 0;
    let mut recv_size = 0;

    let (universe, _) = mpi::initialize_with_threading(mpi::Threading::Funneled).unwrap();
    let world = universe.world();
    let root_rank = 0;
    let root_process = world.process_at_rank(root_rank);
    let rank = world.rank();
    let size = world.size();

    let mut log = Vec::new();
    let very_start = start_timer_buf!(log, || format!("Node {rank}: Beginning work"));

    // if rank == root_rank {
    // Deserialize the proving keys
    println!("running mode: {}", local);

    if local == 0 {
        println!("worker id: {}", worker_id);
    } else {
        println!("worker id: {}", rank);
    }
    if (local == 0 && worker_id == 0) || (local == 1 && rank == root_rank) {
        let proving_keys = {
            let mut buf = Vec::new();

            let mut file_name = key_file.clone();
            file_name.set_extension("root");

            let mut f =
                File::open(&file_name).expect(&format!("couldn't open file {:?}", key_file));
            let _ = f.read_to_end(&mut buf);
            let buf_slice = buf.as_slice();

            let pk =
                DistributedRootKey::<E>::deserialize_uncompressed_unchecked(buf_slice).unwrap();
            pk
        };

        // Initial proof
        let start = start_timer_buf!(log, || format!("Coord: construct coordinator proof"));

        let default_response = "ready".to_string();
        let responses_chunked: Vec<_> = gather_responses(
            &mut log,
            &("mpi_snark_coordinator_".to_owned() + "_start"),
            size,
            &root_process,
            default_response,
        );

        use ark_std::time::Instant;
        let time = Instant::now();

        let (proof, coordinator_time) = dfs::mpi_snark::coordinator::PublicProver::new(
            &mut log,
            "mpi_snark_coordinator_",
            size,
            &root_process,
            log_num_parties,
            &proving_keys.ipk,
            &proving_keys.ivk,
        );

        let final_time = time.elapsed();
        println!("proving time: {:?}", final_time);
        println!("coordinator time: {:?}", coordinator_time);

        end_timer_buf!(log, start);

        /***************************************************************************/
        /***************************************************************************/

        {
            let time = Instant::now();
            assert!(proof.verify(&proving_keys.ivk, &Vec::new()).is_ok());
            let final_time = time.elapsed();
            println!("verification time: {:?}", final_time);
            let bytes = proof.serialized_size(ark_serialize::Compress::Yes);
            println!("proof size: {:?}", bytes);
        }
    } else {
        // Deserialize the proving keys
        // Worker code

        // let worker_id = (rank as usize) - 1;
        if local == 1 {
            worker_id = (rank as usize) - 1;
        } else {
            worker_id = worker_id - 1;
        }

        let proving_keys = {
            let mut buf = Vec::new();

            let mut file_name = key_file.clone();

            file_name.set_extension(worker_id.to_string());

            let mut f =
                File::open(&file_name).expect(&format!("couldn't open file {:?}", key_file));
            let _ = f.read_to_end(&mut buf);
            let buf_slice = buf.as_slice();

            let pk =
                DistributedProverKey::<E>::deserialize_uncompressed_unchecked(buf_slice).unwrap();

            pk
        };

        let current_num_threads = current_num_threads();
        println!(
            "Rayon num threads in worker {rank}: {}",
            current_num_threads
        );

        let log_chunk_size = proving_keys.num_variables - log_num_parties;
        let start_eq = (1 << log_chunk_size) * worker_id;

        let responses = "ready".to_string();
        send_responses(&mut log, rank, "worker ready", &root_process, &responses, 1);

        let (size1, size2) = PublicProver::prove(
            &proving_keys,
            &mut log,
            "mpi_worker_",
            size,
            rank,
            &root_process,
            log_num_parties,
            start_eq,
            log_chunk_size,
        );
        send_size = send_size + size1;
        recv_size = recv_size + size2;
        /***************************************************************************/
        /***************************************************************************/
    }

    end_timer_buf!(log, very_start);

    println!(
        "Rank {rank} log: {}\nsend_msg_size: {}\nrecv_msg_size: {}\n",
        log.join(";"),
        send_size,
        recv_size
    );
}

#[cfg(feature = "parallel")]
fn execute_in_pool<T: Send>(f: impl FnOnce() -> T + Send, num_threads: usize) -> T {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();
    pool.install(f)
}
#[cfg(not(feature = "parallel"))]
fn execute_in_pool<T: Send>(f: impl FnOnce() -> T + Send, num_threads: usize) -> T {
    f()
}
#[cfg(not(feature = "parallel"))]
fn execute_in_pool_with_all_threads<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    f()
}

#[cfg(feature = "parallel")]
use rayon::current_num_threads;

#[cfg(not(feature = "parallel"))]
fn current_num_threads() -> usize {
    1
}

fn pool_and_chunk_size(num_threads: usize, num_requests: usize) -> (usize, usize) {
    let pool_size = if num_threads > num_requests {
        num_threads / num_requests
    } else {
        1
    };
    let chunk_size = if num_requests >= num_threads {
        num_requests / num_threads
    } else {
        num_threads
    };
    dbg!((pool_size, chunk_size))
}

fn compute_responses<'a, R, W, U, F>(
    requests: &'a [R],
    worker_states: impl IntoIterator<Item = W>,
    stage_fn: F,
) -> Vec<U>
where
    R: 'a + Send + Sync,
    W: Send + Sync,
    U: Send + Sync,
    F: Send + Sync + Fn(&'a R, W) -> U,
{
    let (pool_size, chunk_size) = pool_and_chunk_size(current_num_threads(), requests.len());
    thread::scope(|s| {
        let mut thread_results = Vec::new();
        let worker_state_chunks: Vec<Vec<_>> = worker_states
            .into_iter()
            .chunks(chunk_size)
            .into_iter()
            .map(|c| c.into_iter().collect())
            .collect();
        for (reqs, states) in requests.chunks(chunk_size).zip(worker_state_chunks) {
            let result = s.spawn(|_| {
                execute_in_pool(
                    || {
                        reqs.into_iter()
                            .zip(states)
                            .map(|(req, state)| stage_fn(req, state))
                            .collect::<Vec<_>>()
                    },
                    pool_size,
                )
            });
            thread_results.push(result);
        }
        thread_results
            .into_iter()
            .map(|t| t.join().unwrap())
            .flatten()
            .collect::<Vec<_>>()
    })
    .unwrap()
}
