fn main() {
    cc::Build::new()
        .file("c_src/crypto_core.c")
        .compile("crypto_core");

    println!("cargo:rerun-if-changed=c_src/crypto_core.c");
}
