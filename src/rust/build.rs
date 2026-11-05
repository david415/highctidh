//! Builds CTIDH-1024 from this repository's `src/ctidh1024`, with the flags
//! its cgo binding uses, in its portable C form.

fn main() {
    let dir = std::path::Path::new("../ctidh1024");
    let mut build = cc::Build::new();
    for entry in std::fs::read_dir(dir).expect("highctidh sources") {
        let path = entry.expect("highctidh source").path();
        if path.extension().is_some_and(|e| e == "c") {
            build.file(&path);
        }
    }
    build
        .include(dir)
        .define("BITS", "1024")
        .define("CGONUTS", None)
        .define("HIGHCTIDH_PORTABLE", "1")
        .define("GETRANDOM", None)
        .opt_level(2)
        .warnings(false)
        .compile("highctidh1024");
    println!("cargo:rerun-if-changed=../ctidh1024");
}
