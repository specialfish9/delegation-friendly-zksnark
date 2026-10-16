#!/bin/bash

#SBATCH --job-name=hello_world
#SBATCH --partition=debug
#SBATCH --output=%j.out
#SBATCH --error=%j.err
#SBATCH -n 8
#SBATCH --ntasks-per-node=8

ulimit -l unlimited
ulimit -s unlimited


module load openmpi/4.1.5-gcc-8.5.0   
module load llvm/12.0.1-gcc-8.5.0
cargo test -v
