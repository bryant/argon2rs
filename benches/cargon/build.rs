extern crate gcc;

fn main() {
    let cargon_root = std::path::Path::new("phc-winner-argon2");
    let mut cfg = gcc::Config::new();

    for src in &["argon2.c",
                 "core.c",
                 "blake2/blake2b.c",
                 "thread.c",
                 "encoding.c",
                 "opt.c"] {
        let mut srcpath = cargon_root.join("src");
        srcpath.push(src);
        cfg.file(srcpath);
    }

    cfg.include(cargon_root.join("include")).compile("libargon2.a");
}
