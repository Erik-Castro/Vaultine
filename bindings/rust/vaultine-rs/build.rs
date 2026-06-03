fn main() {
    // Auto-discover local build directory for development workflow
    let build_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    ).join("../../../build/src");

    if build_dir.exists() {
        println!("cargo:rustc-link-search={}", build_dir.display());
    }

    println!("cargo:rustc-link-lib=ssm");
    println!("cargo:rerun-if-changed=build.rs");
}
