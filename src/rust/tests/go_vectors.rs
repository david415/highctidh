use blake2::Blake2b512;
use hkdf::SimpleHkdf;
use rand_core::TryRng;

/// The deterministic HKDF-BLAKE2b-512 stream hpqc's Go vector generator
/// draws keys from.
struct HkdfRng {
    stream: Vec<u8>,
    pos: usize,
}

impl HkdfRng {
    fn new(label: &str, case: &str) -> Self {
        let secret = format!("hpqc-vector-seed-{label}");
        let mut stream = vec![0; 255 * 64];
        SimpleHkdf::<Blake2b512>::new(None, secret.as_bytes())
            .expand(case.as_bytes(), &mut stream)
            .unwrap();
        Self { stream, pos: 0 }
    }
}

impl TryRng for HkdfRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.copy_from_slice(&self.stream[self.pos..self.pos + dst.len()]);
        self.pos += dst.len();
        Ok(())
    }
}

impl rand_core::TryCryptoRng for HkdfRng {}

fn hex(c: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(c[field].as_str().unwrap()).unwrap()
}

/// hpqc's CTIDH-1024 vectors: deterministic key generation and blinding.
#[test]
fn matches_hpqc() {
    use highctidh::ctidh1024::*;

    let v: serde_json::Value = serde_json::from_str(include_str!("ctidh1024.json")).unwrap();
    let cases = v["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        for (label, field) in [
            ("nike_alice", "alice_private_key_hex"),
            ("nike_bob", "bob_private_key_hex"),
            ("nike_blinding_factor", "blinding_factor_hex"),
        ] {
            let key = generate_private_key(&mut HkdfRng::new(label, name));
            assert_eq!(*key.bytes(), hex(c, field), "{name} {label}");
        }

        let mut alice = PrivateKey::new_empty();
        alice.from_bytes(&hex(c, "alice_private_key_hex")).unwrap();
        let mut bob = PrivateKey::new_empty();
        bob.from_bytes(&hex(c, "bob_private_key_hex")).unwrap();
        let mut factor = PrivateKey::new_empty();
        factor.from_bytes(&hex(c, "blinding_factor_hex")).unwrap();

        let alice_pk = alice.public();
        assert_eq!(alice_pk.bytes(), hex(c, "alice_public_key_hex"), "{name}");
        let bob_pk = PublicKey::new(&hex(c, "bob_public_key_hex"));
        assert_eq!(bob_pk, bob.public(), "{name}");
        let ss = derive_secret(&alice, &bob_pk);
        assert_eq!(*ss, hex(c, "shared_secret_hex"), "{name}");
        assert_eq!(bob.derive_secret(&alice_pk), ss, "{name}");

        let mut blinded = alice_pk;
        blinded.blind(&factor).unwrap();
        assert_eq!(
            blinded.bytes(),
            hex(c, "blinded_alice_public_key_hex"),
            "{name}"
        );
    }
}

/// The alice, bob and shared secret hex strings of each test in a Go
/// `vectors*_test.go` file, in file order.
fn go_vectors(go: &str) -> Vec<[Vec<u8>; 5]> {
    let names = [
        "alicePrivateKeyHex",
        "alicePublicKeyHex",
        "bobPrivateKeyHex",
        "bobPublicKeyHex",
        "sharedSecretHex",
    ];
    let values: Vec<Vec<u8>> = go
        .lines()
        .filter_map(|line| {
            let (name, value) = line.trim().split_once(" := \"")?;
            names
                .contains(&name)
                .then(|| hex::decode(value.trim_end_matches('"')).unwrap())
        })
        .collect();
    assert_eq!(values.len(), 10);
    values
        .chunks(5)
        .map(|c| c.to_vec().try_into().unwrap())
        .collect()
}

macro_rules! go_package_vectors {
    ($test:ident, $module:ident, $file:literal) => {
        #[test]
        fn $test() {
            use highctidh::$module::*;

            for [alice_sk, alice_pk, bob_sk, bob_pk, ss] in go_vectors(include_str!($file)) {
                let mut alice = PrivateKey::new_empty();
                alice.from_bytes(&alice_sk).unwrap();
                let mut bob = PrivateKey::new_empty();
                bob.from_bytes(&bob_sk).unwrap();
                assert_eq!(*alice.bytes(), alice_sk);
                assert_eq!(alice.public().bytes(), alice_pk);
                assert_eq!(bob.public().bytes(), bob_pk);
                let alice_pk = PublicKey::new(&alice_pk);
                let bob_pk = PublicKey::new(&bob_pk);
                assert_eq!(*derive_secret(&alice, &bob_pk), ss);
                assert_eq!(*derive_secret(&bob, &alice_pk), ss);
            }
        }
    };
}

go_package_vectors!(
    matches_go_511,
    ctidh511,
    "../../ctidh511/vectors511_test.go"
);
go_package_vectors!(
    matches_go_512,
    ctidh512,
    "../../ctidh512/vectors512_test.go"
);
go_package_vectors!(
    matches_go_1024,
    ctidh1024,
    "../../ctidh1024/vectors1024_test.go"
);
go_package_vectors!(
    matches_go_2048,
    ctidh2048,
    "../../ctidh2048/vectors2048_test.go"
);
