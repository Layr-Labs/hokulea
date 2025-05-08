set positional-arguments

# default recipe to display help information
default:
  @just --list

############################### BUILD ###############################

# Build the workspace for all available targets
alias b := build-all
[group('build')]
build-all: build-native build-client-for-asterisc

# Build for the native target
[group('build')]
build-native *args='':
  cargo build --workspace $@

# Build `hokulea-client` for the `asterisc` target.
[group('build')]
build-client-for-asterisc:
  docker run \
    --rm \
    -v `pwd`/:/workdir \
    -w="/workdir" \
    ghcr.io/op-rs/kona/asterisc-builder:0.1.0 \
    cargo build -Zbuild-std=core,alloc -p hokulea-client-bin --bin hokulea-client-bin --profile release-client-lto

############################### LOCAL DEVNET ###############################

# Will download resources/g1.point if it doesn't exist.
[group('local-env')]
download-srs:
    #!/usr/bin/env bash
    if [ ! -f "resources/g1.point" ]; then
        echo "Downloading SRS G1 points to resources/g1.point ..."
        mkdir -p resources
        curl -o resources/g1.point -L https://github.com/Layr-Labs/eigenda-proxy/raw/refs/heads/main/resources/g1.point
    else
        echo "SRS file resources/g1.point already exists, skipping download"
    fi

# This target runs as a prerequisite to `run-client-native-against-devnet` target.
# The client assumes that rollup.json is present in the current working directory.
# This target downloads the rollup config from the op-node running in the kurtosis enclave.
[group('local-env')]
_download-rollup-config-from-kurtosis enclave='eigenda-devnet' chain_id='2151908':
  #!/usr/bin/env bash
  set -o pipefail -o errexit -o nounset
  export FOUNDRY_DISABLE_NIGHTLY_WARNING=true

  ROLLUP_NODE_RPC=$(kurtosis port print {{enclave}} op-cl-{{chain_id}}-1-op-node-op-geth-op-kurtosis http)
  echo "Downloading rollup config from kurtosis op-node at $ROLLUP_NODE_RPC"
  cast rpc "optimism_rollupConfig" --rpc-url $ROLLUP_NODE_RPC | jq > rollup.json

# `run-client-native-against-devnet` requires a finalized L2 block before it can run.
# In CI we thus run this command before running the client.
[group('local-env')]
_kurtosis_wait_for_first_l2_finalized_block chain_id='2151908':
  #!/usr/bin/env bash
  set -o pipefail -o errexit -o nounset
  export FOUNDRY_DISABLE_NIGHTLY_WARNING=true

  L2_RPC=$(kurtosis port print eigenda-devnet op-el-{{chain_id}}-1-op-geth-op-node-op-kurtosis rpc)
  while true; do
    BLOCK_NUMBER=$(cast block finalized --json --rpc-url $L2_RPC | jq -r .number | cast 2d)
    if [ $BLOCK_NUMBER -ne 0 ]; then
      echo "First finalized block found: $BLOCK_NUMBER"
      break
    fi
    echo "Waiting for first finalized block on L2 chain at $L2_RPC"
    sleep 5
  done

# Run the client program natively with the host program attached, against the op-devnet.
[group('local-env')]
run-client-against-devnet native_or_asterisc='native' bin_target='hokulea-host-bin' features='' mock_mode='' verbosity='' block_number='' rollup_config_path='rollup.json' enclave='eigenda-devnet' chain_id='2151908': (download-srs) (_download-rollup-config-from-kurtosis) (_kurtosis_wait_for_first_l2_finalized_block)
  #!/usr/bin/env bash
  set -o errexit -o nounset -o pipefail
  export FOUNDRY_DISABLE_NIGHTLY_WARNING=true

  L1_RPC="http://$(kurtosis port print {{enclave}} el-1-geth-teku rpc)"
  L1_BEACON_RPC="$(kurtosis port print {{enclave}} cl-1-teku-geth http)"
  L2_RPC="$(kurtosis port print {{enclave}} op-el-{{chain_id}}-1-op-geth-op-node-op-kurtosis rpc)"
  ROLLUP_NODE_RPC="$(kurtosis port print {{enclave}} op-cl-{{chain_id}}-1-op-node-op-geth-op-kurtosis http)"
  EIGENDA_PROXY_RPC="$(kurtosis port print {{enclave}} da-server-op-kurtosis http)"
  ROLLUP_CONFIG_PATH="$(realpath {{rollup_config_path}})"

  if [ -z "{{block_number}}" ]; then
    BLOCK_NUMBER=$(cast block finalized --json --rpc-url $L2_RPC | jq -r .number | cast 2d)
    if [ $BLOCK_NUMBER -eq 0 ]; then
      echo "No finalized blocks found on L2 chain. If devnet was just started, wait a bit and try again..."
      echo "You can run the following command to check the latest finalized block."
      echo "cast block finalized --json --rpc-url $L2_RPC | jq -r .number | cast 2d"
      exit 1
    fi
  else
    BLOCK_NUMBER={{block_number}}
  fi

  set -x
  just run-client $BLOCK_NUMBER \
    $L1_RPC $L1_BEACON_RPC $L2_RPC $ROLLUP_NODE_RPC $EIGENDA_PROXY_RPC \
    {{native_or_asterisc}} {{bin_target}} $ROLLUP_CONFIG_PATH {{features}} {{mock_mode}} {{verbosity}}

[group('local-env')]
run-kurtosis-devnet ENCLAVE_NAME="eigenda-devnet" ARGS_FILE="kurtosis_params.yaml":
  kurtosis run --enclave {{ENCLAVE_NAME}} github.com/ethpandaops/optimism-package --args-file {{ARGS_FILE}} --image-download always

# If you have run run-kurtosis-devnet recently, which always downloads all images,
# then it is safe to run this command, which skill use cached images instead, and is thus faster.
[group('local-env')]
run-kurtosis-devnet-with-cached-images ENCLAVE_NAME="eigenda-devnet" ARGS_FILE="kurtosis_params.yaml":
  kurtosis run --enclave {{ENCLAVE_NAME}} github.com/ethpandaops/optimism-package --args-file {{ARGS_FILE}}

# Deploy a mock contract that always return true. Designed to work with a devnet that uses eigenda-proxy memstore feature
# which does not return a legitimate DA cert
[group('local-env')]
deploy-mock-contract ENCLAVE_NAME="eigenda-devnet":
  #!/usr/bin/env bash
  set -o errexit -o nounset -o pipefail
  cd canoe/contracts/mock
  L1_RPC="http://$(kurtosis port print {{ENCLAVE_NAME}} el-1-geth-teku rpc)"
  DEVNET_PRIVATE_KEY=bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31
  forge script script/DeployEigenDACertMockVerifier.s.sol --rpc-url $L1_RPC --private-key $DEVNET_PRIVATE_KEY --broadcast

############################### STYLE ###############################

# unused-deps finds unused dependencies in the workspace.
# See https://rustprojectprimer.com/checks/unused.html
# machete runs very fast but is less accurate, on by default.
# udeps is slower (it compiles code) but more accurate, off by default.
[group('style')]
unused-deps slow="false":
  cargo machete
  # cargo +nightly udeps

# Lint the workspace for all available targets
alias la := lint
[group('style')]
lint: lint-native lint-docs

# Lint the workspace
alias l := lint-native
[group('style')]
lint-native: fmt-native-check lint-docs
  RISC0_SKIP_BUILD=1 cargo clippy --workspace --all --all-features --all-targets -- -D warnings

# Lint the Rust documentation
[group('style')]
lint-docs:
  RUSTDOCFLAGS="-D warnings" cargo doc --all --no-deps --document-private-items

# Runs `cargo hack check` against the workspace
alias h := hack
[group('style')]
hack:
  cargo hack check --feature-powerset --no-dev-deps

# Fixes the formatting of the workspace
alias f := fmt-native-fix
[group('style')]
fmt-native-fix:
  cargo fmt --all

# Check the formatting of the workspace
[group('style')]
fmt-native-check:
  cargo fmt --all -- --check

# Generate the hokulea/kona dependency graph shown in the README.
[group('style')]
generate-deps-graphviz:
  #!/usr/bin/env bash
  DEPS=$(cargo metadata --format-version=1 | jq -r '.packages[].dependencies[] | .name' | grep -E 'kona|hokulea' | tr '\n' ',')
  cargo depgraph --include "${DEPS%,}" | dot -Tpng > dependencies_graph.png

############################### UNIT TESTS ###############################

# Run all tests (excluding online tests)
alias t := tests
[group('test')]
tests: test test-docs

# Test for the native target with all features. By default, excludes online tests.
[group('test')]
test *args="-E '!test(test_online)'":
  cargo nextest run --workspace --all --all-features {{args}}

# Run all online tests
[group('test')]
test-online:
  just test "-E 'test(test_online)'"

# Test the Rust documentation
[group('test')]
test-docs:
  cargo test --doc --all --locked


############################## RUN CLIENT #################################
run-client block_number l1_rpc l1_beacon_rpc l2_rpc rollup_node_rpc eigenda_proxy_rpc native_or_asterisc='native' bin='hokulea-host-bin' rollup_config_path='' features='' mock_mode='true' verbosity='':
  #!/usr/bin/env bash
  set -o errexit -o nounset -o pipefail

  L1_NODE_ADDRESS="{{l1_rpc}}"
  L1_BEACON_ADDRESS="{{l1_beacon_rpc}}"
  L2_NODE_ADDRESS="{{l2_rpc}}"
  OP_NODE_ADDRESS="{{rollup_node_rpc}}"
  EIGENDA_PROXY_ADDRESS="{{eigenda_proxy_rpc}}"
  NATIVE_OR_ASTERISC="{{native_or_asterisc}}"

  L2_CHAIN_ID=$(cast chain-id --rpc-url $L2_NODE_ADDRESS)
  if [ -z "{{rollup_config_path}}" ]; then
    CHAIN_ID_OR_ROLLUP_CONFIG_ARG="--l2-chain-id $L2_CHAIN_ID"
  else
    CHAIN_ID_OR_ROLLUP_CONFIG_ARG="--rollup-config-path $(realpath {{rollup_config_path}})"
  fi

  CLAIMED_L2_BLOCK_NUMBER={{block_number}}
  echo "Fetching configuration for block #$CLAIMED_L2_BLOCK_NUMBER..."

  # Get output root for block
  CLAIMED_L2_OUTPUT_ROOT=$(cast rpc --rpc-url $OP_NODE_ADDRESS "optimism_outputAtBlock" $(cast 2h $CLAIMED_L2_BLOCK_NUMBER) | jq -r .outputRoot)

  # Get the info for the previous block
  AGREED_L2_OUTPUT_ROOT=$(cast rpc --rpc-url $OP_NODE_ADDRESS "optimism_outputAtBlock" $(cast 2h $((CLAIMED_L2_BLOCK_NUMBER - 1))) | jq -r .outputRoot)
  AGREED_L2_HEAD_HASH=$(cast block --rpc-url $L2_NODE_ADDRESS $((CLAIMED_L2_BLOCK_NUMBER - 1)) --json | jq -r .hash)
  L1_ORIGIN_NUM=$(cast rpc --rpc-url $OP_NODE_ADDRESS "optimism_outputAtBlock" $(cast 2h $((CLAIMED_L2_BLOCK_NUMBER - 1))) | jq -r .blockRef.l1origin.number)
  L1_HEAD=$(cast block --rpc-url $L1_NODE_ADDRESS $((L1_ORIGIN_NUM + 30)) --json | jq -r .hash)

  # Move to the workspace root
  cd $(git rev-parse --show-toplevel)

  rm -rf ./data
  mkdir ./data

  if [ "{{mock_mode}}" == 'true' ]; then
    set -a
      RISC0_DEV_MODE=true
    set +a
  fi

  FEATURES_FLAGS=""
  if [ "{{features}}" != '' ]; then
    FEATURES_FLAGS="--features {{features}}"
  fi

  if [ "$NATIVE_OR_ASTERISC" = "native" ]; then
    echo "Running host program with native client program..."
    cargo r --bin {{bin}} $FEATURES_FLAGS  -- \
      --l1-head $L1_HEAD \
      --agreed-l2-head-hash $AGREED_L2_HEAD_HASH \
      --claimed-l2-output-root $CLAIMED_L2_OUTPUT_ROOT \
      --agreed-l2-output-root $AGREED_L2_OUTPUT_ROOT \
      --claimed-l2-block-number $CLAIMED_L2_BLOCK_NUMBER \
      --l1-node-address $L1_NODE_ADDRESS \
      --l1-beacon-address $L1_BEACON_ADDRESS \
      --l2-node-address $L2_NODE_ADDRESS \
      --eigenda-proxy-address $EIGENDA_PROXY_ADDRESS \
      --native \
      --data-dir ./data \
      $CHAIN_ID_OR_ROLLUP_CONFIG_ARG \
      {{verbosity}}
  elif [ "$NATIVE_OR_ASTERISC" = "asterisc" ]; then
    HOST_BIN_PATH="./target/release/hokulea-host-bin"    
    CLIENT_BIN_PATH="./target/riscv64imac-unknown-none-elf/release-client-lto/hokulea-client-bin"
    STATE_PATH="./state.bin.gz"

    echo "Building hokulea host program for RISC-V target..."
    just build-client-for-asterisc
    echo "Loading host program into Asterisc state format..."
    asterisc load-elf --path=$CLIENT_BIN_PATH
    echo "Building host program for native target..."
    cargo build --bin hokulea-host-bin --release

    echo "Running asterisc"
    asterisc run \
      --info-at '%10000000' \
      --proof-at never \
      --input $STATE_PATH \
      -- \
      $HOST_BIN_PATH \
      --l1-head $L1_HEAD \
      --agreed-l2-head-hash $AGREED_L2_HEAD_HASH \
      --claimed-l2-output-root $CLAIMED_L2_OUTPUT_ROOT \
      --agreed-l2-output-root $AGREED_L2_OUTPUT_ROOT \
      --claimed-l2-block-number $CLAIMED_L2_BLOCK_NUMBER \
      --l2-chain-id $L2_CHAIN_ID \
      --l1-node-address $L1_NODE_ADDRESS \
      --l1-beacon-address $L1_BEACON_ADDRESS \
      --l2-node-address $L2_NODE_ADDRESS \
      --eigenda-proxy-address $EIGENDA_PROXY_ADDRESS \
      --server \
      --data-dir ./data \
      {{verbosity}}
  else
    echo "Unknown value for NATIVE_OR_ASTERISC: $NATIVE_OR_ASTERISC"
    exit 1
  fi

# Run the client program natively with the host program attached, in offline mode.
run-client-native-offline block_number l2_claim l2_output_root l2_head l1_head l2_chain_id verbosity='':
  #!/usr/bin/env bash

  CLAIMED_L2_BLOCK_NUMBER={{block_number}}
  CLAIMED_L2_OUTPUT_ROOT={{l2_claim}}
  AGREED_L2_OUTPUT_ROOT={{l2_output_root}}
  AGREED_L2_HEAD_HASH={{l2_head}}
  L1_HEAD={{l1_head}}
  L2_CHAIN_ID={{l2_chain_id}}

  # Move to the workspace root
  cd $(git rev-parse --show-toplevel)

  echo "Running host program with native client program..."
  cargo r --bin hokulea-host-bin --release -- \
    --l1-head $L1_HEAD \
    --agreed-l2-head-hash $AGREED_L2_HEAD_HASH \
    --claimed-l2-output-root $CLAIMED_L2_OUTPUT_ROOT \
    --agreed-l2-output-root $AGREED_L2_OUTPUT_ROOT \
    --claimed-l2-block-number $CLAIMED_L2_BLOCK_NUMBER \
    --l2-chain-id $L2_CHAIN_ID \
    --native \
    --data-dir ./data \
    {{verbosity}}

# Run the client program on asterisc with the host program detached, in offline mode.
run-client-asterisc-offline block_number l2_claim l2_output_root l2_head l1_head l2_chain_id verbosity='':
  #!/usr/bin/env bash

  HOST_BIN_PATH="./target/release/kona-host"
  CLIENT_BIN_PATH="./target/riscv64gc-unknown-none-elf/release-client-lto/hokulea-client-bin"
  STATE_PATH="./state.bin.gz"

  CLAIMED_L2_BLOCK_NUMBER={{block_number}}
  CLAIMED_L2_OUTPUT_ROOT={{l2_claim}}
  AGREED_L2_OUTPUT_ROOT={{l2_output_root}}
  AGREED_L2_HEAD_HASH={{l2_head}}
  L1_HEAD={{l1_head}}
  L2_CHAIN_ID={{l2_chain_id}}

  # Move to the workspace root
  cd $(git rev-parse --show-toplevel)

  echo "Building client program for RISC-V target..."
  just build-asterisc --bin hokulea-client-bin --profile release-client-lto

  echo "Loading client program into Asterisc state format..."
  asterisc load-elf --path=$CLIENT_BIN_PATH

  echo "Building host program for native target..."
  cargo build --bin hokulea-host-bin --release

  echo "Running asterisc"
  asterisc run \
    --info-at '%10000000' \
    --proof-at never \
    --input $STATE_PATH