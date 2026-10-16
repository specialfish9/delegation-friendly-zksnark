#!/bin/bash

#SBATCH --job-name=lookup_setup
#SBATCH --partition=cpu
#SBATCH --output=result/work-5-%j.out
#SBATCH --error=result/work-5-%j.err
#SBATCH -N 5
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
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


# srun -n 9 --mpi=pmi2 hpc_work.sh
#srun -n 9 --mpi=pmi2 ../../target/debug/examples/lookup work  --log-table-size 8 --log-query-size 8 --log-num-parties 3 --key-file test --worker-id $SLURM_NODEID --local 1

for i in {15..27}
do
    LOG_INSTANCE_SIZE=$i
    LOG_NUM_PUBLIC_WORKERS=2
    KEY_FILE=inst_folder/inst_${LOG_INSTANCE_SIZE}_${LOG_NUM_PUBLIC_WORKERS}/test
    srun -n 5 --mpi=pmi2 hpc_work.sh $LOG_INSTANCE_SIZE $LOG_NUM_PUBLIC_WORKERS $KEY_FILE
done
