#!/bin/bash

#SBATCH --job-name=single_prover_bench
#SBATCH --partition=cpu
#SBATCH --output=single-%j.out
#SBATCH --error=single-%j.err
#SBATCH -n 1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=40
#SBATCH --exclusive

ulimit -l unlimited
ulimit -s unlimited


#module load gcc
#module load openmpi
#module load llvm

#module load openmpi/4.1.5-gcc-8.5.0   
#module load openmpi/3.1.5-gcc-8.5.0
module load openmpi/4.1.1-gcc-8.5.0
module load llvm/12.0.1-gcc-8.5.0

RAYON_NUM_THREADS=8 cargo bench --no-default-features --features "std parallel" -- --nocapture
