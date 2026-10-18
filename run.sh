#!/usr/bin/env bash

# Non-SLURM launcher for the ass_snark example (OpenMPI, no shared filesystem).
#
# Assumes the Ansible playbook (../ma-girolimetto/ansible/dfs.yaml) has already:
#   - installed OpenMPI + nightly Rust and built target/release/examples/ass_snark on every node,
#   - set up passwordless root SSH between the nodes,
#   - created "{{ dfs_dir }}/hosts" and "{{ dfs_dir }}/examples/ass_snark/inst_folder/inst_<D>_<W>_<P>".
#
# The hostfile must be named "hosts" and live in the current working directory
# (the repo root), one host per line:
#
# node1 slots=1
# node2 slots=1
# node3 slots=1
#
# To generate the instance yourself (run from examples/ass_snark on one node):
#
# mkdir -p inst_folder
# ../../target/release/examples/ass_snark setup \
#   --log-instance-size 15 \
#   --log-num-workers-per-party 1 \
#   --log-num-public-workers 1 \
#   --key-out inst_folder
#
# NOTE: setup takes log_num_workers_per_party + 1 (its loop is `0..N`, so N=0
# produces no instance at all), while `work` takes the real value (0).

set -euo pipefail

# Three nodes = 1 coordinator + 2 workers = 2^PUB + 1 processes.
NODES="${NODES:-3}"
INSTANCE_SIZE="${INSTANCE_SIZE:-15}"
WORKERS_PER_PARTY="${WORKERS_PER_PARTY:-0}"
PUBLIC_WORKERS="${PUBLIC_WORKERS:-1}"

REPO_ROOT="$(pwd)"
HOSTFILE="${HOSTFILE:-$REPO_ROOT/hosts}"
KEY_FILE="${KEY_FILE:-$REPO_ROOT/examples/ass_snark/inst_folder/inst_${INSTANCE_SIZE}_${WORKERS_PER_PARTY}_${PUBLIC_WORKERS}/test}"

if [[ ! -f "$HOSTFILE" ]]; then
  echo "hostfile not found: $HOSTFILE" >&2
  exit 1
fi

# Threads per MPI process (each machine runs a single rank).
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-8}"

# Often required for large MPI buffers / deep stacks.
ulimit -l unlimited 2>/dev/null || true
ulimit -s unlimited 2>/dev/null || true

# OpenMPI refuses to run as root unless this is set (the playbook uses root).
ROOT_FLAG=()
if [[ "$(id -u)" -eq 0 ]]; then
  ROOT_FLAG=(--allow-run-as-root)
fi

mpirun \
  "${ROOT_FLAG[@]}" \
  --hostfile "$HOSTFILE" \
  -np "$NODES" \
  --map-by ppr:1:node \
  --bind-to none \
  -x RAYON_NUM_THREADS \
  bash -lc "set -e
    cd '$REPO_ROOT/examples/ass_snark'
    exec ../../target/release/examples/ass_snark work \
      --log-instance-size $INSTANCE_SIZE \
      --log-num-workers-per-party $WORKERS_PER_PARTY \
      --log-num-public-workers $PUBLIC_WORKERS \
      --key-file '$KEY_FILE' \
      --worker-id \"\${OMPI_COMM_WORLD_RANK}\" \
      --local 0"
