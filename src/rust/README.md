# highctidh Rust bindings

A Rust crate for CTIDH-1024. `build.rs` compiles `../ctidh1024` with `cc`, in
its portable C form, so no installed library is needed.

The crate exposes key generation, the Go bindings' key encodings, validation,
the shared secret and the group action on a public key (blinding).
`tests/ctidh1024.json` holds Go CTIDH-1024 test vectors from
[hpqc](https://github.com/katzenpost/hpqc), which the crate matches byte for
byte.

```
cargo test --manifest-path src/rust/Cargo.toml
```
