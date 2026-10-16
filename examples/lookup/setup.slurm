#!/bin/bash

#SBATCH --job-name=lookup_setup
#SBATCH --partition=debug
#SBATCH --output=%j.out
#SBATCH --error=%j.err
#SBATCH -n 1
#SBATCH --ntasks-per-node=1

ulimit -l unlimited
ulimit -s unlimited

module load openmpi

#sleep 20
srun hpc_setup.sh 
