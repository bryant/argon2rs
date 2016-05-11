cargo build
cargo test
# benches use `extern crate test` which requires nightly.
if [ "$TRAVIS_RUST_VERSION" = "nightly" ]
then
    cargo bench
fi
