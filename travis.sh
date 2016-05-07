cargo build
# tests use `extern crate test` which requires nightly.
if [ "$TRAVIS_RUST_VERSION" = "nightly" ]
then
    cargo test
fi
