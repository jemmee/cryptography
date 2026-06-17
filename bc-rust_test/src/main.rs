// cargo new bc-rust_test --bin
// cd bc-rust_test
//
// cargo clean
// cargo update
// cargo run

use bouncycastle_hex as hex;
use bouncycastle_core::traits::Hash;
use bouncycastle_sha2 as sha2;
use bouncycastle_sha3 as sha3;
use bouncycastle_core::traits::RNG;
use bouncycastle_rng as rng;
use bouncycastle_hmac::HMAC_SHA256;
use bouncycastle_core::traits::MAC;
use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
use bouncycastle_base64 as base64;
use bouncycastle_core::traits::KDF;
use bouncycastle_hkdf::HKDF_SHA256;

fn main() {
    let data: &[u8] = b"Let nothing be done through strife or vainglory; but in lowliness of mind let each esteem other better than themselves.";
    println!("Data: {}", String::from_utf8_lossy(data));

    let output = hex::encode(data);
    println!("Data in hex: {}", output);

    let output = base64::encode(data);
    println!("Data in base64: {}", output);

    let output: Vec<u8> = sha2::SHA224::new().hash(data);
    println!("SHA224 of data in hex: {}", hex::encode(output));

    let output: Vec<u8> = sha2::SHA256::new().hash(data);
    println!("SHA256 of data in hex: {}", hex::encode(output));

    let output: Vec<u8> = sha2::SHA384::new().hash(data);
    println!("SHA384 of data in hex: {}", hex::encode(output));

    let output: Vec<u8> = sha2::SHA512::new().hash(data);
    println!("SHA512 of data in hex: {}", hex::encode(output));

    let output: Vec<u8> = sha3::SHA3_224::new().hash(data);
    println!("SHA3_224 of data in hex: {}", hex::encode(output));
    
    let output: Vec<u8> = sha3::SHA3_256::new().hash(data);
    println!("SHA3_256 of data in hex: {}", hex::encode(output));

    let output: Vec<u8> = sha3::SHA3_384::new().hash(data);
    println!("SHA3_384 of data in hex: {}", hex::encode(output));

    let output: Vec<u8> = sha3::SHA3_512::new().hash(data);
    println!("SHA3_512 of data in hex: {}", hex::encode(output));

    let random_bytes: [u8; 16] = rng::DefaultRNG::default().next_bytes(16).unwrap().try_into().expect("RNG returned wrong number of bytes");
    // println!("Random bytes: {:?}", random_bytes);
    println!("Random bytes in hex: {}", hex::encode(&random_bytes));

    let key = KeyMaterial256::from_bytes_as_type(
                &random_bytes,
                KeyType::Seed).unwrap();
    let hkdf = HKDF_SHA256::new();
    let derived_key = hkdf.derive_key(&key, b"extra input").unwrap();
    // println!("Drived key: {:?}", derived_key.ref_to_bytes());
    println!("Derived key in hex: {}", hex::encode(derived_key.ref_to_bytes()));

    let key = KeyMaterial256::from_bytes_as_type(
                &random_bytes,
                KeyType::MACKey).unwrap();
    let hmac = HMAC_SHA256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
    let output: Vec<u8> = hmac.mac(data);
    println!("HMAC_SHA256 of key in hex: {}", hex::encode(output));
}