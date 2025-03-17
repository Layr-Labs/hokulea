set positional-arguments

# default recipe to display help information
default:
  @just --list

############################### STYLE ###############################

# unused-deps finds unused dependencies in the workspace.
# See https://rustprojectprimer.com/checks/unused.html
# machete runs very fast but is less accurate, on by default.
# udeps is slower (it compiles code) but more accurate, off by default.
unused-deps slow="false":
  cargo machete
  # cargo +nightly udeps

# Lint the workspace for all available targets
alias la := lint
lint: lint-native lint-docs

# Lint the workspace
alias l := lint-native
lint-native: fmt-native-check lint-docs
  cargo +nightly clippy --workspace --all --all-features --all-targets -- -D warnings

# Lint the Rust documentation
lint-docs:
  RUSTDOCFLAGS="-D warnings" cargo doc --all --no-deps --document-private-items

# Runs `cargo hack check` against the workspace
alias h := hack
hack:
  cargo hack check --feature-powerset --no-dev-deps

# Fixes the formatting of the workspace
alias f := fmt-native-fix
fmt-native-fix:
  cargo +nightly fmt --all

# Check the formatting of the workspace
fmt-native-check:
  cargo +nightly fmt --all -- --check

# Generate the hokulea/kona dependency graph shown in the README.
generate-deps-graphviz:
  #!/usr/bin/env bash
  DEPS=$(cargo metadata --format-version=1 | jq -r '.packages[].dependencies[] | .name' | grep -E 'kona|hokulea' | tr '\n' ',')
  cargo depgraph --include "${DEPS%,}" | dot -Tpng > dependencies_graph.png

############################### BUILD ###############################

# Build the workspace for all available targets
alias b := build
build: build-native

# Build for the native target
build-native *args='':
  cargo build --workspace $@

############################### UNIT TESTS ###############################

# Run all tests (excluding online tests)
alias t := tests
tests: test test-docs

# Test for the native target with all features. By default, excludes online tests.
test *args="-E '!test(test_online)'":
  cargo nextest run --workspace --all --all-features {{args}}

# Run all online tests
# TODO: understand when this is needed
test-online:
  just test "-E 'test(test_online)'"

# Test the Rust documentation
test-docs:
  cargo test --doc --all --locked

############################### E2E TESTS ###############################

# TODO: Use the below stuff to add an e2e test for the client program using hokulea

# Clones and checks out the monorepo at the commit present in `.monorepo`
monorepo:
  ([ ! -d monorepo ] && git clone https://github.com/ethereum-optimism/monorepo) || exit 0
  cd monorepo && git checkout $(cat ../.monorepo)

# Updates the pinned version of the monorepo
update-monorepo:
  [ ! -d monorepo ] && git clone https://github.com/ethereum-optimism/monorepo
  cd monorepo && git rev-parse HEAD > ../.monorepo

# Run action tests for the client program on the native target
action-tests test_name='Test_ProgramAction' *args='':
  #!/bin/bash

  just monorepo

  if [ ! -d "monorepo/.devnet" ]; then
    echo "Building devnet allocs for the monorepo"
    (cd monorepo && make devnet-allocs)
  fi

  echo "Building host program for the native target"
  just build-native --bin kona-host --release

  echo "Running action tests for the client program on the native target"
  export KONA_HOST_PATH="{{justfile_directory()}}/target/release/kona-host"
  export KONA_CLIENT_PATH="{{justfile_directory()}}/target/release-client-lto/kona"

  cd monorepo/op-e2e/actions/proofs && \
    gotestsum --format=short-verbose -- -run "{{test_name}}" {{args}} -count=1 ./...

# Clean the action tests directory
clean-actions:
  rm -rf monorepo/
