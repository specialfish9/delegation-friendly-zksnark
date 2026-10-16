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

use ark_poly_commit::multilinear_pc::{
    data_structures::Commitment, data_structures::CommitterKey, data_structures::VerifierKey,
    MultilinearPC,
};
use dfs::mpi_snark::coordinator::mpi_batch_open_poly_coordinator;
use dfs::mpi_utils::send_responses;
use dfs::subprotocols::loglookup::default_sumcheck_poly_list;
use dfs::subprotocols::loglookup::sumcheck_polynomial_list;
use dfs::subprotocols::loglookup::LogLookupProof;

use dfs::utils::{
    aggregate_comm, aggregate_eval, aggregate_poly, boost_degree, combine_comm, distributed_open,
    generate_eq, map_poly, merge_list_of_distributed_poly, merge_proof, normalized_multiplicities,
    partial_generate_eq, split_ck, split_poly, split_vec, two_pow_n,
};
use dfs::{end_timer_buf, start_timer_buf};
use dfs::{VerificationError, VerificationResult};
use rand::RngCore;

use dfs::mpi_snark::coordinator::{mpi_poly_commit_coordinator, mpi_sumcheck_coordinator};
use dfs::mpi_snark::worker::{mpi_batch_open_poly_worker, mpi_sumcheck_worker};
use dfs::mpi_utils::{gather_responses, receive_requests, scatter_requests};
use dfs::snark::{batch_open_poly, batch_verify_poly, BatchOracleEval, OracleEval};
use dfs::subprotocols::loglookup::poly_list_to_prover_state;
use dfs::transcript::{get_scalar_challenge, get_vector_challenge};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DistributedProverKey<E: Pairing> {
    pub ck: CommitterKey<E>,
    pub vk: VerifierKey<E>,
    pub table: DenseMultilinearExtension<E::ScalarField>,
    pub query: DenseMultilinearExtension<E::ScalarField>,
    pub freq: DenseMultilinearExtension<E::ScalarField>,
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
        log_table_size: usize,

        #[clap(long, value_name = "NUM")]
        log_query_size: usize,

        // /// Test circuit param: Number of portal wire ops per subcircuit. MUST be at least 1.
        #[clap(long, value_name = "NUM")]
        log_num_parties: usize,
        /// Path for the output coordinator key package
        #[clap(long, value_name = "DIR")]
        key_out: PathBuf,
    },

    Work {
        /// Path to the coordinator key package
        #[clap(long, value_name = "DIR")]
        key_file: PathBuf,

        #[clap(long, value_name = "NUM")]
        log_table_size: usize,

        #[clap(long, value_name = "NUM")]
        log_query_size: usize,

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
            log_table_size,
            log_query_size,
            log_num_parties,
            key_out,
        } => setup::<Bls12_381>(key_out, log_table_size, log_query_size, log_num_parties),
        Command::Work {
            key_file,
            log_num_parties,
            log_table_size,
            log_query_size,
            worker_id,
            local,
        } => {
            work::<Bls12_381>(
                log_num_parties,
                log_table_size,
                log_query_size,
                key_file,
                worker_id,
                local,
            );
        }
    }
}

fn setup<E: Pairing>(
    key_out_path: PathBuf,
    log_table_size: usize,
    log_query_size: usize,
    log_num_parties: usize,
) {
    let D: usize = log_table_size;
    let S: usize = log_query_size;
    let P: usize = log_num_parties;

    let mut rng = StdRng::seed_from_u64(12);

    let params = MultilinearPC::<Bls12_381>::setup(D, &mut rng);
    let (ck, vk) = MultilinearPC::trim(&params, D);
    let (ck_list, merge_ck) = split_ck(&ck, P);

    let table_evals = (0..1 << S).map(|_| Fr::rand(&mut rng)).collect();
    let table = DenseMultilinearExtension::from_evaluations_vec(S, table_evals);
    let table_list = split_poly(&table, P);

    let query_valid_evals = (0..(1 << D))
        .map(|_| *table.evaluations.choose(&mut rng).unwrap())
        .collect();

    let query_valid = DenseMultilinearExtension::from_evaluations_vec(D, query_valid_evals);
    let query_list = split_poly(&query_valid, P);

    let freq = normalized_multiplicities(&query_valid, &table);
    let freq_list = split_poly(&freq, P);

    for i in 0..1 << P {
        let mut buf = Vec::new();
        let pk = DistributedProverKey {
            ck: ck_list[i].clone(),
            vk: vk.clone(),
            table: table_list[i].clone(),
            query: query_list[i].clone(),
            freq: freq_list[i].clone(),
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
        let pk = DistributedProverKey {
            ck: merge_ck,
            vk: vk.clone(),
            table: DenseMultilinearExtension::from_evaluations_vec(0, vec![Fr::zero()]),
            query: DenseMultilinearExtension::from_evaluations_vec(0, vec![Fr::zero()]),
            freq: DenseMultilinearExtension::from_evaluations_vec(0, vec![Fr::zero()]),
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
    log_num_workers: usize,
    log_table_size: usize,
    log_query_size: usize,
    key_file: PathBuf,
    mut worker_id: usize,
    local: usize,
) {
    let (universe, _) = mpi::initialize_with_threading(mpi::Threading::Funneled).unwrap();
    let world = universe.world();
    let root_rank = 0;
    let root_process = world.process_at_rank(root_rank);
    let rank = world.rank();
    let size = world.size();

    // Deserialize the proving keys

    let proving_keys = {
        let mut buf = Vec::new();

        let mut file_name = key_file.clone();
        if rank == root_rank {
            file_name.set_extension("root");
        } else {
            file_name.set_extension((rank - 1).to_string());
        }

        let mut f = File::open(&file_name).expect(&format!("couldn't open file {:?}", key_file));
        let _ = f.read_to_end(&mut buf);
        let buf_slice = buf.as_slice();

        let pk = DistributedProverKey::<E>::deserialize_uncompressed_unchecked(buf_slice).unwrap();

        pk
    };

    let mut log = Vec::new();
    let very_start = start_timer_buf!(log, || format!("Node {rank}: Beginning work"));

    println!("running mode: {}", local);

    if local == 0 {
        println!("worker id: {}", worker_id);
    } else {
        println!("worker id: {}", rank);
    }
    if (local == 0 && worker_id == 0) || (local == 1 && rank == root_rank) {
        let mut prover_transcript = Blake2s512Rng::setup();

        // Initial broadcast
        let start = start_timer_buf!(log, || format!("Coord: construct coordinator state"));
        let x: E::ScalarField = get_scalar_challenge(&mut prover_transcript);
        end_timer_buf!(log, start);

        /***************************************************************************/
        /***************************************************************************/
        // Round 1
        let start = start_timer_buf!(log, || format!("Coord: Generating stage0 requests"));
        let requests_chunked = vec![x; 1 << log_num_workers];
        end_timer_buf!(log, start);

        // Round 1 scatter
        scatter_requests(&mut log, "stage0", &root_process, &requests_chunked);
        println!("Finished coordinator scatter 0");

        // Round 1 gather
        let (comms, _) = mpi_poly_commit_coordinator(
            &mut log,
            "stage0_poly_commit",
            size,
            &root_process,
            2,
            proving_keys.ck.g,
            log_num_workers,
        );
        println!("Finished coordinator gather 0");

        let comm_0: &Commitment<E> = &comms[0];
        let comm_1: &Commitment<E> = &comms[1];

        _ = prover_transcript.feed(comm_0);
        _ = prover_transcript.feed(comm_1);

        let z: Vec<E::ScalarField> = get_vector_challenge(&mut prover_transcript, log_query_size);
        let lambda: E::ScalarField = get_scalar_challenge(&mut prover_transcript);

        /***************************************************************************/
        /***************************************************************************/
        // Round 2
        let requests_chunked = vec![(z.clone(), lambda.clone()); 1 << log_num_workers];

        // Round 2 scatter
        scatter_requests(&mut log, "stage1", &root_process, &requests_chunked);
        println!("Finished coordinator scatter 1");

        // Round 2 sumcheck
        let poly_info = PolynomialInfo {
            max_multiplicands: 3,
            num_variables: log_table_size,
        };
        let mut q_polys = ListOfProductsOfPolynomials::new(1);
        default_sumcheck_poly_list(&lambda, log_query_size - log_table_size, &mut q_polys);

        let default_last_sumcheck_state = poly_list_to_prover_state(&q_polys);

        let (prover_msgs, final_point, _) = mpi_sumcheck_coordinator(
            &mut log,
            "stage1_sumcheck",
            size,
            &root_process,
            &poly_info,
            &mut prover_transcript,
            default_last_sumcheck_state,
            log_num_workers,
            1 << log_num_workers,
        );
        println!("Finished coordinator sumcheck 1");

        // Round 2 poly open
        let eta: E::ScalarField = get_scalar_challenge(&mut prover_transcript);
        let requests_chunked = vec![eta.clone(); 1 << log_num_workers];
        // println!("{:?}", eta);

        // Round 3 scatter
        scatter_requests(&mut log, "stage2", &root_process, &requests_chunked);
        println!("Finished coordinator scatter 2");

        let (batch_oracle, _) = mpi_batch_open_poly_coordinator(
            &mut log,
            "stage1_poly_open",
            size,
            &root_process,
            log_num_workers,
            poly_info.num_variables,
            5,
            &proving_keys.ck,
            &[comm_0.clone(), comm_1.clone()],
            &final_point,
            eta,
            proving_keys.ck.g,
            log_num_workers,
        );

        println!("Finished coordinator poly open 1");

        {
            let degree_diff = log_query_size - log_table_size;

            let mut verifier_transcript = Blake2s512Rng::setup();

            let (lookup_x, z, lambda) = LogLookupProof::<E>::verify_before_sumcheck(
                &poly_info,
                &batch_oracle,
                1,
                &mut verifier_transcript,
            );

            assert!(LogLookupProof::<E>::verify(
                &poly_info,
                &prover_msgs,
                &batch_oracle,
                degree_diff,
                &lookup_x,
                &z,
                &lambda,
                &proving_keys.vk,
                &mut verifier_transcript,
                E::ScalarField::zero(),
                E::ScalarField::zero(),
            )
            .is_ok())
        }
    } else {
        let current_num_threads = current_num_threads();
        println!(
            "Rayon num threads in worker {rank}: {}",
            current_num_threads
        );

        // Worker code

        if local == 1 {
            worker_id = (rank as usize) - 1;
        } else {
            worker_id = worker_id - 1;
        }
        // let worker_id = (rank as usize) - 1;

        /***************************************************************************/
        /***************************************************************************/
        // Round 1

        // Receive Round 1 request
        let (x, _): (E::ScalarField, usize) =
            receive_requests(&mut log, rank, "round 1", &root_process, 0);

        println!("Finished worker receive requests 0 for rank {rank}");

        // Round 1 compute
        let pf = LogLookupProof::<E>::prove(
            &proving_keys.query,
            &proving_keys.table,
            &proving_keys.freq,
            &proving_keys.ck,
            &x,
        );

        // Send Round 1 response
        let responses = pf.1.clone();
        send_responses(&mut log, rank, "round 1", &root_process, &responses, 0);

        println!("Finished worker gather 1 for rank {rank}");

        /***************************************************************************/
        /***************************************************************************/

        // Repeat this again and again.

        // Receive Round 2 request
        let ((z, lambda), _): ((Vec<E::ScalarField>, E::ScalarField), usize) =
            receive_requests(&mut log, rank, "round 2", &root_process, 0);

        println!("Finished worker receive requests 2 for rank {rank}");

        // Round 2 compute
        let log_chunk_size = z.len() - log_num_workers;
        let start = (1 << log_chunk_size) * worker_id;
        let mut q_polys = ListOfProductsOfPolynomials::new(log_query_size - log_num_workers);
        sumcheck_polynomial_list(
            (pf.0[0].clone(), pf.0[1].clone()),
            (pf.2[0].clone(), pf.2[1].clone()),
            proving_keys.freq.clone(),
            log_query_size - log_table_size,
            &mut q_polys,
            &z,
            &lambda,
            start,
            log_chunk_size,
        );

        println!("Finished worker compute 2 for rank {rank}");

        let (final_point, _, _) = mpi_sumcheck_worker(
            &mut log,
            "stage1_sumcheck",
            size,
            rank,
            &root_process,
            &q_polys,
            log_num_workers,
        );

        println!("Finished worker sumcheck for rank {rank}");

        // Receive Round 3 request
        let (eta, _): (E::ScalarField, usize) =
            receive_requests(&mut log, rank, "round 3", &root_process, 0);
        // println!("{:?}", eta);

        println!("open: {} {}", final_point.len(), log_table_size);
        mpi_batch_open_poly_worker(
            &mut log,
            "stage2_poly_open",
            size,
            rank,
            &root_process,
            log_num_workers,
            log_table_size,
            &proving_keys.ck,
            2,
            &[
                &pf.0[0],
                &pf.0[1],
                &proving_keys.freq,
                &proving_keys.query,
                &proving_keys.table,
            ],
            &final_point,
            eta,
        );
    }

    end_timer_buf!(log, very_start);

    println!("Rank {rank} log: {}", log.join(";"));
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
