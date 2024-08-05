#!/bin/bash

set -e

stack_dir=$(readlink -f "$1")
[[ -d "$stack_dir" ]]

laconic_so="laconic-so --verbose --stack $stack_dir"

CONFIG_DIR=$(readlink -f "${CONFIG_DIR:-$(mktemp -d)}")
# By default assume we are running in the project root.
export CERC_REPO_BASE_DIR="${CERC_REPO_BASE_DIR:-$(git rev-parse --show-toplevel)/..}"

# Don't run geth/plugeth in the debugger, it will swallow error backtraces
echo CERC_REMOTE_DEBUG=false >> $CONFIG_DIR/stack.env
# Passing this lets us run eth_call forwarding tests without running ipld-eth-db
echo CERC_RUN_STATEDIFF=${CERC_RUN_STATEDIFF:-true} >> $CONFIG_DIR/stack.env

set -x

if [[ -z $SKIP_BUILD ]]; then
  # Prevent conflicting tty output
  export BUILDKIT_PROGRESS=plain

  $laconic_so setup-repositories
  $laconic_so build-containers
fi

if ! $laconic_so deploy \
  --env-file $CONFIG_DIR/stack.env \
  --cluster test up
then
  $laconic_so deploy --cluster test logs
  exit 1
fi

set +x

# Get IPv4 endpoint of geth bootnode file server
bootnode_endpoint=$(docker port test-fixturenet-eth-bootnode-geth-1 9898 | head -1)

# Extract the chain config and ID from genesis file
curl -s $bootnode_endpoint/geth.json | jq '.config' > $CONFIG_DIR/chain.json

# Output vars if we are running on Github
if [[ -n "$GITHUB_ENV" ]]; then
    echo ETH_CHAIN_ID="$(jq '.chainId' $CONFIG_DIR/chain.json)" >> "$GITHUB_ENV"
    echo ETH_CHAIN_CONFIG="$CONFIG_DIR/chain.json" >> "$GITHUB_ENV"
    echo ETH_HTTP_PATH=$(docker port test-fixturenet-eth-geth-1-1 8545 | head -1) >> "$GITHUB_ENV"
    # Read a private key so we can send from a funded account
    echo DEPLOYER_PRIVATE_KEY=$(curl -s $bootnode_endpoint/accounts.csv | head -1 | cut -d',' -f3) >> "$GITHUB_ENV"
fi
