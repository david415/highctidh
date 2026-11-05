//! Builds each field size from `src` as the C Makefile does, with the
//! assembly field arithmetic on x86_64 and aarch64 (for 1024 and 2048 bits
//! only when the target enables SVE2) and the portable fiat C elsewhere or
//! with the `portable` feature. Every symbol gets a per-size
//! prefix, as with the cgo bindings, so all four sizes link into one binary.
//! The cgo build's `CGONUTS` would do that too but also turns off the AVX2
//! sort, so the size-independent symbols it renames are renamed here.

use std::path::Path;

const COMMON: &[&str] = &[
    "crypto_classify.c",
    "crypto_declassify.c",
    "csidh.c",
    "elligator.c",
    "int32_sort.c",
    "mont.c",
    "poly.c",
    "random.c",
    "randombytes.c",
    "skgen.c",
    "steps.c",
    "steps_untuned.c",
    "validate.c",
];

const GENERIC: &[&str] = &[
    "crypto_classify",
    "crypto_declassify",
    "crypto_sort_int32",
    "ctidh_fillrandom_default",
    "random_boundedl1",
    "random_bytes",
    "random_coin",
    "randombytes",
    "steps",
    "steps_guess",
    "steps_override",
];

fn main() {
    let src = Path::new("src");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let portable = std::env::var_os("CARGO_FEATURE_PORTABLE").is_some();
    let features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let has = |feature: &str| features.split(',').any(|f| f == feature);
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    for bits in ["511", "512", "1024", "2048"] {
        // The aarch64 fp1024 and fp2048 assembly uses SVE instructions.
        let sve = arch == "aarch64" && matches!(bits, "1024" | "2048");
        let asm = match arch.as_str() {
            "x86_64" | "aarch64" if !portable && (!sve || has("sve2")) => Some(arch.as_str()),
            _ => None,
        };
        let namespace = format!("highctidh_{bits}_##x");
        let mut build = cc::Build::new();
        build
            .include(src)
            .define("BITS", bits)
            .define("NAMESPACEBITS(x)", namespace.as_str())
            .define("NAMESPACEGENERIC(x)", namespace.as_str())
            .define("GETRANDOM", None)
            .flag("-fwrapv")
            .opt_level(2)
            .warnings(false);
        for symbol in GENERIC {
            build.define(symbol, format!("highctidh_{bits}_{symbol}").as_str());
        }
        if has("avx2") {
            build.flag("-mavx2");
        }
        if os == "macos" {
            build.define("__Darwin__", None);
        }
        let mut files: Vec<String> = COMMON.iter().map(|f| f.to_string()).collect();
        files.extend([
            format!("fp_inv{bits}.c"),
            format!("fp_sqrt{bits}.c"),
            format!("primes{bits}.c"),
        ]);
        if let Some(asm) = asm {
            build.define("HIGHCTIDH_PORTABLE", "0");
            if sve {
                build.flag("-march=armv8-a+sve2");
            }
            files.extend([
                format!("fp{bits}_{asm}.S"),
                format!("uintbig{bits}_{asm}.S"),
            ]);
        } else {
            build.define("HIGHCTIDH_PORTABLE", "1");
            files.extend([format!("fiat_p{bits}.c"), "fp2fiat.c".to_string()]);
        }
        for file in files {
            build.file(src.join(file));
        }
        build.compile(&format!("highctidh{bits}"));
    }
    println!("cargo:rerun-if-changed=src");
}
