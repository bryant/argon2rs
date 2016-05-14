argon2rs
========

[![Build
Status](https://travis-ci.org/bryant/argon2rs.svg?branch=master)](https://travis-ci.org/bryant/argon2rs)

This is a purely Rust-based library that provides both variants of the
state-of-the-art Argon2 hashing algorithm, suitable for password hashing and
password-based key derivation.

[Documentation](http://bryant.github.io/argon2rs/)

## Installation

Via cargo:

```bash
$ cd $PROJECT_ROOT
$ cargo install --features "simd"
```

From git:

```bash
$ git clone https://github.com/bryant/argon2rs $ARGON_DIR && cd $ARGON_DIR
$ cargo build --features "simd"
```

## Usage

From `examples/helloworld.rs`:

```rust
extern crate argon2rs;

pub fn main() {
    let (password, salt) = ("argon2i!", "delicious salt");
    println!("argon2i(\"argon2i\", \"delicious\"):");
    for byte in argon2rs::simple2i(&password, &salt).iter() {
        print!("{:02x}", byte);
    }
    println!("");
}
```

outputs:

```
argon2i("argon2i", "delicious"):
e254b28d820f26706a19309f1888cefd5d48d91384f35dc2e3fe75c3a8f665a6
```

There are two variants of Argon2 that differ in the manner by which reference
indices are computed during block-filling rounds. Argon2d does this in a faster
but data-dependent fashion that could be vulnerable to side-channel [attacks][1],
whereas Argon2i ("i" denoting independence from plaintext input) works slower
but is immune to such attacks and is therefore the preferred choice for password
hashing.

## TODO

- [x] Parallelize.
- [x] Incorporate SIMD into compression function.
- [x] Zero-on-drop trait for sensitive(s): `Matrix`
- [x] Constant-time verification API.
- [x] Benchmarks.
- [ ] Support NEON and SIMD on other arches.
- [ ] Fuzz.

## LICENSE

MIT.

## Benchmarks

Our primary benchmark is a single-threaded run of Argon2i with default
parameters against the [reference implementation](
https://github.com/p-h-c/phc-winner-argon2). In order to compile and run this,
first pull in the C sources:

```bash
$ git submodule init
$ git submodule update benches/cargon/phc-winner-argon2
```

and then benchmark with Cargo as usual:

```
$ cargo bench --features=simd

# output trimmed for brevity

     Running target/release/versus_cargon-b5955411e1594c85

running 2 tests
test bench_argon2rs_i ... bench:  14,320,903 ns/iter (+/- 3,025,492)
test bench_cargon_i   ... bench:  11,999,153 ns/iter (+/- 112,568)

test result: ok. 0 passed; 0 failed; 0 ignored; 2 measured
```

## References

["Argon2: The Memory-Hard Function for Password Hashing and Other
Applications"](https://github.com/P-H-C/phc-winner-argon2/raw/master/argon2-specs.pdf)
