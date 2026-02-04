use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let c_src = PathBuf::from(&manifest_dir).join("src").join("c");

    println!("cargo:rerun-if-changed={}/vault_engine.c", c_src.display());
    println!("cargo:rerun-if-changed={}/vault_engine.h", c_src.display());

    cc::Build::new()
        .file(c_src.join("vault_engine.c"))
        .include(&c_src)
        .opt_level(3)
        .flag("-Wall")
        .flag("-Wextra")
        .compile("vault_engine");

    println!("cargo:rustc-link-lib=sodium");

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-search=/opt/homebrew/lib");
        println!("cargo:rustc-link-search=/usr/local/lib");
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-search=/usr/lib");
        println!("cargo:rustc-link-search=/usr/local/lib");
    }
}
