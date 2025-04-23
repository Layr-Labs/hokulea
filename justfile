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
    cargo build -Zbuild-std=core,alloc -p hokulea-client-bin --bin hokulea-client-bin --profile release-client-lto --no-default-features

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
run-client-against-devnet native_or_asterisc='native' verbosity='' block_number='' rollup_config_path='rollup.json' enclave='eigenda-devnet' chain_id='2151908': (download-srs) (_download-rollup-config-from-kurtosis) (_kurtosis_wait_for_first_l2_finalized_block)
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
  just --justfile bin/client/justfile run-client $BLOCK_NUMBER \
    $L1_RPC $L1_BEACON_RPC $L2_RPC $ROLLUP_NODE_RPC $EIGENDA_PROXY_RPC \
    {{native_or_asterisc}} $ROLLUP_CONFIG_PATH {{verbosity}}

[group('local-env')]
run-kurtosis-devnet ENCLAVE_NAME="eigenda-devnet" ARGS_FILE="kurtosis_params.yaml":
  kurtosis run --enclave {{ENCLAVE_NAME}} github.com/ethpandaops/optimism-package --args-file {{ARGS_FILE}} --image-download always

# If you have run run-kurtosis-devnet recently, which always downloads all images,
# then it is safe to run this command, which skill use cached images instead, and is thus faster.
[group('local-env')]
run-kurtosis-devnet-with-cached-images ENCLAVE_NAME="eigenda-devnet" ARGS_FILE="kurtosis_params.yaml":
  kurtosis run --enclave {{ENCLAVE_NAME}} github.com/ethpandaops/optimism-package --args-file {{ARGS_FILE}}

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
  cargo clippy --workspace --all --all-features --all-targets -- -D warnings

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
