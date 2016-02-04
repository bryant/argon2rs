argon2rs
========

This is a purely Rust-based library that provides both variants of the
state-of-the-art Argon2 hashing algorithm, suitable for password hashing and
password-based key derivation.

## Installation

Via cargo:

```bash
$ cd $PROJECT_ROOT
$ cargo install --features "simd threaded"
```

From git:

```bash
$ git clone https://github.com/bryant/argon2rs $ARGON_DIR && cd $ARGON_DIR
$ cargo build --features "simd threaded"
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
8026dbe9eb1a2318722ec948a828710b1dbb32a3091b2d7e8e1d3b900e4e96212c0f594e12be7b3
474d97568b3d6f015c1f1f7ae6fa69261c53993f0a8dd94e9
```

There are two variants of Argon2 that differ in the manner by which reference
indices are computed during block-filling rounds. Argon2d does this in a faster
but data-dependent fashion that could be vulnerable to side-channel attacks [1],
whereas Argon2i ("i" denoting independence from plaintext input) works slower
but is immune to such attacks and is therefore the preferred choice for password
hashing.

## TODO

- [x] Parallelize.
- [x] Incorporate SIMD into compression function.

## LICENSE

MIT.

## Random Benchmark

Compared with the [reference impl][https://github.com/p-h-c/phc-winner-argon2]
written in heavily hand-optimized C:

```bash
~/phc-winner-argon2$ echo -n "asic-resistant but" | time -v ./argon2 'still fast' -t 80 -m 16 -p 9 2>&1 > /dev/null | grep 'wall clock'
        Elapsed (wall clock) time (h:mm:ss or m:ss): 0:02.46

~/argon2rs$ echo -n "asic-resistant but" | time -v ./target/release/examples/cli 80 9 16 'still fast' 2>&1 > /dev/null | grep 'wall clock'
        Elapsed (wall clock) time (h:mm:ss or m:ss): 0:02.88
```

## References

[1] https://github.com/P-H-C/phc-winner-argon2/raw/master/argon2-specs.pdf "Argon2: The Memory-Hard Function for Password Hashing and Other Applications"
