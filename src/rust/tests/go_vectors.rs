use blake2::Blake2b512;
use highctidh::{PrivateKey, PublicKey};
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

#[test]
fn matches_go() {
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
            let key = PrivateKey::generate(&mut HkdfRng::new(label, name));
            assert_eq!(*key.to_bytes(), hex(c, field), "{name} {label}");
        }

        let alice = PrivateKey::from_bytes(&hex(c, "alice_private_key_hex")).unwrap();
        let bob = PrivateKey::from_bytes(&hex(c, "bob_private_key_hex")).unwrap();
        let factor = PrivateKey::from_bytes(&hex(c, "blinding_factor_hex")).unwrap();
        assert_eq!(*alice.to_bytes(), hex(c, "alice_private_key_hex"), "{name}");

        let alice_pk = alice.public_key();
        assert_eq!(
            alice_pk.to_bytes(),
            hex(c, "alice_public_key_hex"),
            "{name}"
        );
        assert_eq!(
            bob.public_key().to_bytes(),
            hex(c, "bob_public_key_hex"),
            "{name}"
        );

        let bob_pk = PublicKey::from_bytes(&hex(c, "bob_public_key_hex")).unwrap();
        assert_eq!(bob_pk, bob.public_key(), "{name}");
        let ss = alice.shared_secret(&bob_pk).unwrap();
        assert_eq!(*ss, hex(c, "shared_secret_hex"), "{name}");
        assert_eq!(*bob.shared_secret(&alice_pk).unwrap(), *ss, "{name}");

        assert_eq!(
            alice_pk.blind(&factor).unwrap().to_bytes(),
            hex(c, "blinded_alice_public_key_hex"),
            "{name}"
        );
    }
}

/// Test1024BitVectors and TestPython1024BitVectors from
/// `src/ctidh1024/vectors1024_test.go`: alice and bob's keys and the secret.
#[test]
fn matches_go_package_vectors() {
    for [alice_sk, alice_pk, bob_sk, bob_pk, ss] in [
        [
            "fe0001010000fe0100fe00ff00fc0300ffffff0000ff0100000000ff01010200000201fe01000100ff0000fdff010001ffffff03fd0000000000feff000101ff000401000100000100040000010001ff00000001000100000101ffffff010001ff00ff00ffff0000fe000100000100ff0000000002ff0000fe0000010000ff000000",
            "b962dadf244d6239ab74d808b0a88b2078b549bb03fab005ef6a97c1ee448bdc5a37892aaddf762e0157de5670320e8007398fb3eeab00a09fcbfe3caffb1fcebd03c38144e76b5d1dcd623871dbc6fe13470a23901dbadac77626fd05f891f18416a94123f9333ef1bdfb7570fa248f2567e33a8661c1411c42963b93e7a506",
            "ffff01fe0000ff000102010103000000ff02000102fe0000000100fffefeff00000000fd01fe00fefd0001000000fc00fe0000fe000102000100000002feff0001ff0001010100ff01ffff0000010102000000020100010003fffd0000fe000000ff00ff01000001fd0001ff0000000001010000ff0100ffff010100ff000000ff00",
            "e859133b1bb959a4f17135cd337477141f81684317b30a7f14bad81a867df388477c2bf7a7af738618b568f323b91762f2282706875341b9343a3cd0450073783a91fc71edca8c8b30f9ec6379137c91ce33dcae9dc3c7fd1a951925e299bafdbff6a29dcdb9ae1207f7fb986b6b1087bf05b79c542dca25993c5a43ef7dc105",
            "411abafeca991f77b6f9263721ca3e2898031871e18d91b61c33c8664a9fc3fccf331729a9dd60465687e53c3d7649abfd4a3e32f4ea86e351535c9b281a76a74fa6b057d94403e55941de7e91432e2e85cc8f5b13fa28314a8dc8f09360e44c802bfc8b036451b26bc54200e133dde3976aa1f4885277a7692da9d38c09e301",
        ],
        [
            "000200fffd0000ff03fffe0200010000fd00ff0000fffd010001fe01000001ff00ff020100fe00fffd010100000101feff0100010101fd000000000000fefffffe02000101020000ff0101020000ffffff00000002000001020101ff00ff0200ffff0000000100000000000001ffff00000100fd000000010000fe00ffff00000000",
            "f364c4b220d57528d6b64432e93fb40495177faf9a224955f34b5700cf1cf35be7c476e43681a375602fc57eba16aa0c5c4ae02f3031d55d84c2cb679969074216ca0f114d7c798dc12c65b9820d2dce650070c79f992f34c6653963d62fba82a9f48293940ec6001093a06023ee0b80022d19e33d3a669934cbd289c87ddb01",
            "00fe00fe0101000200fe0002000100fe01000001020200000100ff040000ff000003010002000001010000fc0100010200fe00010000fe000000fe00000201ff000202ffff000000ff00ff0002ff0101fe010000000101ff0001fe00000001000000ff00ff020100000000ff00ffff0000ff00000000ffff0003ff000100ff000000",
            "90d51cc0f48b0ce2712bc8305e7415300bde7feef634e17211ae493ea57b56d1ad81914e85e3b8b43275e7a31c9d440f3f88ef476a31c7e504520f7b538bcbe80fd3bbbc76726c4c37c6c8f9f857618602fcbbc6899e8ac420de32e1ebb1f1178dd13f600afba82276b5f5e6b40dc421b5c3b1f342a9152009b1fae95d372303",
            "b5ab3b4d9cac68c451a43d1b499e190d462788362089ca5f3e4462c1502bb06cc820fe2e46c0f9ddaf8de6fcf8c0b4238e677497ebc6f5bb622a894c3c485c9e16142579392b6af434db46b146416aab5d5bd43c3d0f1bc55755f1af93d137d20540e65fc54e7b2b564dceec6484dc2b8bdd30db2b4ea7ba86adecfcb3e7ba08",
        ],
    ] {
        let alice = PrivateKey::from_bytes(&hex::decode(alice_sk).unwrap()).unwrap();
        let bob = PrivateKey::from_bytes(&hex::decode(bob_sk).unwrap()).unwrap();
        let alice_pk = PublicKey::from_bytes(&hex::decode(alice_pk).unwrap()).unwrap();
        let bob_pk = PublicKey::from_bytes(&hex::decode(bob_pk).unwrap()).unwrap();
        assert_eq!(alice.public_key(), alice_pk);
        assert_eq!(bob.public_key(), bob_pk);
        assert_eq!(*alice.to_bytes(), hex::decode(alice_sk).unwrap());
        assert_eq!(
            *alice.shared_secret(&bob_pk).unwrap(),
            hex::decode(ss).unwrap()
        );
        assert_eq!(
            *bob.shared_secret(&alice_pk).unwrap(),
            hex::decode(ss).unwrap()
        );
    }
}
