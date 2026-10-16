#!/bin/bash

#SBATCH --job-name=lookup_setup
#SBATCH --partition=cpu
#SBATCH --output=%j.out
#SBATCH --error=%j.err
#SBATCH -N 2
#SBATCH --ntasks-per-node=5
#SBATCH --cpus-per-task=4
#SBATCH --exclusive

ulimit -l unlimited
ulimit -s unlimited

#module load openmpi/3.1.5-gcc-8.5.0 
#module load openmpi/4.1.5-gcc-8.5.0 

module load openmpi/4.1.1-gcc-8.5.0
module load llvm/12.0.1-gcc-8.5.0
#module load openmpi


#sleep 20
#srun --mpi=pmi2 hpc_work.sh 

export OMP_NUM_THREADS=1
srun -n 9 --mpi=pmi2 hpc_work.sh

