// cargo new bc-rust_test --bin
// cd bc-rust_test
//
// cargo clean
// cargo update
// cargo run

use bouncycastle_core::traits::Hash;
use bouncycastle_sha2 as sha2;
use bouncycastle_sha3 as sha3;
use bouncycastle_core::traits::RNG;
use bouncycastle_rng as rng;
use bouncycastle_hmac::HMAC_SHA256;
use bouncycastle_core::traits::MAC;
use bouncycastle_core::key_material::{KeyMaterial256, KeyType};

fn main() {
    let data: &[u8] = b"Let nothing be done through strife or vainglory; but in lowliness of mind let each esteem other better than themselves.";

    let output: Vec<u8> = sha2::SHA256::new().hash(data);
    println!("SHA256: {}", hex::encode(output));

    let output: Vec<u8> = sha3::SHA3_256::new().hash(data);
    println!("SHA3_256: {}", hex::encode(output));

    let random_bytes = rng::DefaultRNG::default().next_bytes(32);
    println!("Random bytes: {:x?}", random_bytes);

    let key = KeyMaterial256::from_bytes_as_type(
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            KeyType::MACKey).unwrap();

    let hmac = HMAC_SHA256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
    let output: Vec<u8> = hmac.mac(data);
    println!("HMAC_SHA256: {}", hex::encode(output));
}