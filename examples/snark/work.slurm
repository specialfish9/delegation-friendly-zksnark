#!/bin/bash

#SBATCH --job-name=lookup_setup
#SBATCH --partition=cpu
#SBATCH --output=result/%j.out
#SBATCH --error=result/%j.err
#SBATCH -N 9
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=16
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

#export OMP_NUM_THREADS=1


srun -n 9 --mpi=pmi2 hpc_work.sh
#srun -n 9 --mpi=pmi2 ../../target/debug/examples/lookup work  --log-table-size 8 --log-query-size 8 --log-num-parties 3 --key-file test --worker-id $SLURM_NODEID --local 1
