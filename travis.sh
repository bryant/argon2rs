#!/bin/sh
set -e
cargo build
cargo test

# test single-threaded
cargo test --no-default-features

# benches use `extern crate test` which requires nightly.
if [ "$TRAVIS_RUST_VERSION" = "nightly" ]
then
    if [ ! -z "`grep '\<avx\>' /proc/cpuinfo`" ]
    then
        echo "=== benching with '-C target-feature=+avx' ==="
        export RUSTFLAGS='-C target-feature=+avx'
        cargo clean && cargo bench --features "simd bench_ref"
    fi

    unset RUSTFLAGS
    echo "=== benching without avx ==="
    cargo clean && cargo bench --features "simd bench_ref"
fi
