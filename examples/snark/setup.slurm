#!/bin/bash

#SBATCH --job-name=snark_setup
#SBATCH --partition=huge
#SBATCH --output=result/%j.out
#SBATCH --error=result/%j.err
#SBATCH -n 1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=40

ulimit -l unlimited
ulimit -s unlimited

module load openmpi/4.1.1-gcc-8.5.0
module load llvm/12.0.1-gcc-8.5.0

#sleep 20
for i in {25..27}
do
    #LOG_INSTANCE_SIZE=$i
    #LOG_NUM_PUBLIC_WORKERS=1
    #KEY_OUT=inst_folder
    #srun hpc_setup.sh $LOG_INSTANCE_SIZE $LOG_NUM_PUBLIC_WORKERS $KEY_OUT

    #LOG_INSTANCE_SIZE=$i
    #LOG_NUM_PUBLIC_WORKERS=2
    #KEY_OUT=inst_folder
    #srun hpc_setup.sh $LOG_INSTANCE_SIZE $LOG_NUM_PUBLIC_WORKERS $KEY_OUT

    LOG_INSTANCE_SIZE=$i
    LOG_NUM_PUBLIC_WORKERS=5
    KEY_OUT=inst_folder
    srun hpc_setup.sh $LOG_INSTANCE_SIZE $LOG_NUM_PUBLIC_WORKERS $KEY_OUT

    LOG_INSTANCE_SIZE=$i
    LOG_NUM_PUBLIC_WORKERS=6
    KEY_OUT=inst_folder
    srun hpc_setup.sh $LOG_INSTANCE_SIZE $LOG_NUM_PUBLIC_WORKERS $KEY_OUT
done
