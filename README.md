<h1 align="center">DFS</h1>
  
  
  
`dfs` is a Rust library that implements a
<p align="center">
<b>Delegation-friendly zkSNARK</b><br>
and<br>
<b>private delegation of provers</b>
</p>
  
This library was initially developed as part of the DFS paper, and is released under the MIT License and the Apache v2 License.  
  
**WARNING:** This is an academic prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.  

## Overview  
  
This artifact provides the implementation of DFS based on the Arkworks framework. Core components such as field arithmetic, the sumcheck protocol, and the polynomial commitment scheme (PCS) are supported by Arkworks.  
  
The implementation is organized as follows:
  
* [`src/`](src): Contains the full source code of our implementation.  
* [`src/subprotocols/`](src/subprotocols): Implements the LogUp-based lookup protocol.  
* [`src/snark/`](src/snark): Implements a single-prover version of DFS.  
* [`src/mpi_snark/`](src/mpi_snark): Provides a distributed DFS implementation for public delegation using the MPI interface.  
* [`src/mpc/`](src/mpc): Includes support for two secret-sharing schemes: additive secret sharing and replicated secret sharing.  
* [`src/mpc_snark/`](src/mpc_snark): Implements DFS for private delegation, combining distributed computation and MPC. Each party in this setup can consist of multiple nodes.  
* [`examples`](examples)/: Contains test and benchmarking code, along with SLURM scripts to facilitate execution in distributed environments.  
  
This comprehensive structure ensures that the artifact covers all aspects of DFS, from single-prover setups to distributed and MPC-based delegation, providing a robust and flexible implementation for evaluation and experimentation.  
  
## Build guide  
 
The library compiles on the `nightly` toolchain of the Rust compiler (v 1.75+). To install the latest version of Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager. Also, DFS is built on top of `rust-mpi`, and please follow the instructions [here](https://github.com/rsmpi/rsmpi) to install.

```bash
cargo build --release --examples
```

## Benchmarks
To fully run the experiments, a high-performance computing (HPC) cluster with SLURM and
MPI support is required. We provide the necessary scripts to facilitate execution,
ensuring seamless deployment and reproducibility of our experiments in a distributed 
computing environment.

The scripts can be found in [`rss_snark`](examples/rss_snark) and 
[`addss_snark`](examples/ass_snark). The `setup.slurm` is used to generate the 
experiment instance. The instance will be output in the `inst_folder` folder.
The `work-*.slurm` is used to run the experiments. `*` specifies how many machines 
are used. 

We also offer an option to run the experiments locally to test the functionality.
In the local mode, each core will represent a single node. Use the script `setup.sh`
to generate the instance and `work.sh` to run the experiment locally.



