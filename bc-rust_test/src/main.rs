// cargo new bc-rust_test --bin
// cd bc-rust_test
//
// cargo clean
// cargo update
// cargo run

use bouncycastle_hex as hex;
use bouncycastle_base64 as base64;
use bouncycastle_core::traits::Hash;
use bouncycastle_sha2 as sha2;
use bouncycastle_sha3 as sha3;
use bouncycastle_core::traits::XOF;
use bouncycastle_core::traits::RNG;
use bouncycastle_rng as rng;
use bouncycastle_hmac::{HMAC_SHA224, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512, HMAC_SHA3_224, HMAC_SHA3_256, HMAC_SHA3_384, HMAC_SHA3_512};
use bouncycastle_core::traits::MAC;
use bouncycastle_core::key_material::{KeyMaterial256, KeyMaterial512, KeyType};
use bouncycastle_core::traits::KDF;
use bouncycastle_hkdf::HKDF_SHA256;
use bouncycastle_mlkem::{MLKEM512, MLKEM768, MLKEM1024,MLKEMTrait};
use bouncycastle_core::traits::KEM;
use bouncycastle_core::errors::KEMError;
use bouncycastle_mldsa::{MLDSA44, MLDSA65, MLDSA87, MLDSATrait};
use bouncycastle_core::traits::Signature;
use bouncycastle_core::errors::SignatureError;

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

    let mut shake = sha3::SHAKE128::new();
    shake.absorb(data);
    let output: Vec<u8> = shake.squeeze(16);
    println!("SHAKE128 of data in hex: {}", hex::encode(output));

    let mut shake = sha3::SHAKE256::new();
    shake.absorb(data);
    let output: Vec<u8> = shake.squeeze(16);
    println!("SHAKE256 of data in hex: {}", hex::encode(output));

    // let random_bytes: [u8; 16] = rng::DefaultRNG::default().next_bytes(16).unwrap().try_into().expect("RNG returned wrong number of bytes");
    let random_bytes: [u8; 32] = rng::DefaultRNG::default().next_bytes(32).unwrap().try_into().expect("RNG returned wrong number of bytes");
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
    let hmac = HMAC_SHA224::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
    let output: Vec<u8> = hmac.mac(data);
    println!("HMAC_SHA224 of key in hex: {}", hex::encode(output));

    let key = KeyMaterial256::from_bytes_as_type(
                &random_bytes,
                KeyType::MACKey).unwrap();
    let hmac = HMAC_SHA256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
    let output: Vec<u8> = hmac.mac(data);
    println!("HMAC_SHA256 of key in hex: {}", hex::encode(output));

    let key = KeyMaterial512::from_bytes_as_type(
                &random_bytes,
                KeyType::MACKey).unwrap();
    let hmac = HMAC_SHA384::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
    let output: Vec<u8> = hmac.mac(data);
    println!("HMAC_SHA384 of key in hex: {}", hex::encode(output));

    let key = KeyMaterial512::from_bytes_as_type(
                &random_bytes,
                KeyType::MACKey).unwrap();
    let hmac = HMAC_SHA512::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
    let output: Vec<u8> = hmac.mac(data);
    println!("HMAC_SHA512 of key in hex: {}", hex::encode(output));

    let key = KeyMaterial256::from_bytes_as_type(
                &random_bytes,
                KeyType::MACKey).unwrap();
    let hmac = HMAC_SHA3_224::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
    let output: Vec<u8> = hmac.mac(data);
    println!("HMAC_SHA3_224 of key in hex: {}", hex::encode(output));

    let key = KeyMaterial256::from_bytes_as_type(
                &random_bytes,
                KeyType::MACKey).unwrap();
    let hmac = HMAC_SHA3_256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
    let output: Vec<u8> = hmac.mac(data);
    println!("HMAC_SHA3_256 of key in hex: {}", hex::encode(output));

    let key = KeyMaterial512::from_bytes_as_type(
                &random_bytes,
                KeyType::MACKey).unwrap();
    let hmac = HMAC_SHA3_384::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
    let output: Vec<u8> = hmac.mac(data);
    println!("HMAC_SHA3_384 of key in hex: {}", hex::encode(output));

    let key = KeyMaterial512::from_bytes_as_type(
                &random_bytes,
                KeyType::MACKey).unwrap();
    let hmac = HMAC_SHA3_512::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
    let output: Vec<u8> = hmac.mac(data);
    println!("HMAC_SHA3_512 of key in hex: {}", hex::encode(output));


    let (pk, sk) = MLKEM512::keygen().unwrap();
    // Create the shared secret and ciphertext using the public key
    let (ss, ct) = MLKEM512::encaps(&pk).unwrap();
    // Recover the shared secret using the private key
    let ss1 = match MLKEM512::decaps(&sk, &ct) {
        Err(KEMError) => panic!("Error decapsulating"),
        Ok(ss) => ss,
    };
    //assert_eq!(ss, ss1);
    if ss == ss1 {
        println!("MLKEM512 ciphertext in hex: {}", hex::encode(ct));
    } else {
        println!("MLKEM512 decapsulation failed");
    }
    
    let (pk, sk) = MLKEM768::keygen().unwrap();
    // Create the shared secret and ciphertext using the public key
    let (ss, ct) = MLKEM768::encaps(&pk).unwrap();
    // Recover the shared secret using the private key
    let ss1 = match MLKEM768::decaps(&sk, &ct) {
        Err(KEMError) => panic!("Error decapsulating"),
        Ok(ss) => ss,
    };
    //assert_eq!(ss, ss1);
    if ss == ss1 {
        println!("MLKEM768 ciphertext in hex: {}", hex::encode(ct));
    } else {
        println!("MLKEM768 decapsulation failed");
    }
    
    let (pk, sk) = MLKEM1024::keygen().unwrap();
    // Create the shared secret and ciphertext using the public key
    let (ss, ct) = MLKEM1024::encaps(&pk).unwrap();
    // Recover the shared secret using the private key
    let ss1 = match MLKEM1024::decaps(&sk, &ct) {
        Err(KEMError) => panic!("Error decapsulating"),
        Ok(ss) => ss,
    };
    //assert_eq!(ss, ss1);
    if ss == ss1 {
        println!("MLKEM1024 ciphertext in hex: {}", hex::encode(ct));
    } else {
        println!("MLKEM1024 decapsulation failed");
    }
    
    let (pk, sk) = MLDSA44::keygen().unwrap();
    let sig = MLDSA44::sign(&sk, data, None).unwrap();
    // This is the signature value that you can save to a file or whatever you need.
    match MLDSA44::verify(&pk, data, None, &sig) {
        Ok(()) => println!("MLDSA44 signature in hex: {}", hex::encode(sig)),
        Err(SignatureError::SignatureVerificationFailed) => println!("MLDSA44 signature is invalid!"),
        Err(e) => panic!("Something else went wrong: {:?}", e),
    }
    
    let (pk, sk) = MLDSA65::keygen().unwrap();
    let sig = MLDSA65::sign(&sk, data, None).unwrap();
    // This is the signature value that you can save to a file or whatever you need.
    match MLDSA65::verify(&pk, data, None, &sig) {
        Ok(()) => println!("MLDSA65 signature in hex: {}", hex::encode(sig)),
        Err(SignatureError::SignatureVerificationFailed) => println!("MLDSA65 signature is invalid!"),
        Err(e) => panic!("Something else went wrong: {:?}", e),
    }

    let (pk, sk) = MLDSA87::keygen().unwrap();
    let sig = MLDSA87::sign(&sk, data, None).unwrap();
    // This is the signature value that you can save to a file or whatever you need.
    match MLDSA87::verify(&pk, data, None, &sig) {
        Ok(()) => println!("MLDSA87 signature in hex: {}", hex::encode(sig)),
        Err(SignatureError::SignatureVerificationFailed) => println!("MLDSA87 signature is invalid!"),
        Err(e) => panic!("Something else went wrong: {:?}", e),
    }
}
