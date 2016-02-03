argon2rs
========

The pure Rust password hashing library that runs on Argon2.

## Usage

From `examples/helloworld`:

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

## References

[1] https://github.com/P-H-C/phc-winner-argon2/raw/master/argon2-specs.pdf "Argon2: The Memory-Hard Function for Password Hashing and Other Applications"
