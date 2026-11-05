# highctidh Rust bindings

A Rust crate for CTIDH-511, CTIDH-512, CTIDH-1024 and CTIDH-2048, with one
module per size (`ctidh511`, `ctidh512`, `ctidh1024`, `ctidh2048`) whose API
and encodings mirror the Go packages of the same names. The crate's
`Cargo.toml` is at the repository root; `build.rs` compiles the C in `src`
with `cc`, so no installed library is needed.

The field arithmetic is the assembly on x86_64 and aarch64 and the portable
fiat C elsewhere. On aarch64 the 1024 and 2048 bit assembly needs SVE2, so
those two sizes use the fiat C unless the target enables `sve2`. The
`portable` feature selects the fiat C everywhere. On x86_64, a target with
`avx2` enabled also gets the AVX2 sort.

`generate_key_pair` and the group action itself (`derive_secret`,
`group_action`, `blind`) draw randomness from highctidh's `randombytes`,
which is getrandom(2) on Linux and CommonCrypto on macOS.
`generate_private_key` reads only from the RNG it is given.

The tests match the vectors in `src/ctidh*/vectors*_test.go` and, for
CTIDH-1024, the [hpqc](https://github.com/katzenpost/hpqc) vectors in
`tests/ctidh1024.json`, byte for byte.

```
cargo test
```
