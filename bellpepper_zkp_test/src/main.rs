// cargo new bellpepper_zkp_test
//
// cd bellpepper_zkp_test
//
// cargo run
//
// 1. Running Trusted Setup...
// 2. Prover: Generating proof for x=3...
// 3. Verifier: Checking proof against output 35...
// ✅ SUCCESS: The proof is mathematically sound!

use bellman::{
    gadgets::num::AllocatedNum,
    groth16, Circuit, ConstraintSystem, SynthesisError,
};
use blstrs::{Scalar as Fr, Bls12};
use ff::Field;
use rand::thread_rng;

// We wrap the synthesis in a struct to implement the Circuit trait
struct SimpleCircuit {
    x: Option<Fr>,
}

impl Circuit<Fr> for SimpleCircuit {
    fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // 1. Allocate Private Input (Witness)
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. Intermediate calculation: x^2
        let x_sq = x.square(cs.namespace(|| "x_sq"))?;

        // 3. Intermediate calculation: x^3
        let x_cu = x_sq.mul(cs.namespace(|| "x_cu"), &x)?;

        // 4. Calculate Public Output Value
        let out_val = self.x.map(|v| {
            let mut tmp = v.square();
            tmp *= v;
            tmp += v;
            tmp += Fr::from(5);
            tmp
        });

        let out = AllocatedNum::alloc(cs.namespace(|| "out"), || {
            out_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 5. Enforce: x^3 + x + 5 = out
        cs.enforce(
            || "x^3 + x + 5 == out",
            |lc| lc + x_cu.get_variable() + x.get_variable() + (Fr::from(5), CS::one()),
            |lc| lc + CS::one(),
            |lc| lc + out.get_variable(),
        );

        // 6. Define the public output
        out.inputize(cs.namespace(|| "out_is_public"))?;

        Ok(())
    }
}

fn main() {
    let mut rng = thread_rng();
    println!("--- Stable Bellman ZKP Demo ---");
    
    // 1. Setup
    println!("1. Running Trusted Setup...");
    let params = groth16::generate_random_parameters::<Bls12, _, _>(
        SimpleCircuit { x: None },
        &mut rng,
    ).expect("Setup failed");

    // 2. Prover
    println!("2. Prover: Generating proof for x=3...");
    let secret_x = Fr::from(3);
    let proof = groth16::create_random_proof(
        SimpleCircuit { x: Some(secret_x) },
        &params,
        &mut rng,
    ).expect("Proving failed");

    // 3. Verifier
    println!("3. Verifier: Checking proof against output 35...");
    let pvk = groth16::prepare_verifying_key(&params.vk);
    let public_inputs = [Fr::from(35)];
    
    let is_valid = groth16::verify_proof(&pvk, &proof, &public_inputs).is_ok();

    if is_valid {
        println!("✅ SUCCESS: The proof is mathematically sound!");
    } else {
        println!("❌ FAILURE: Invalid proof.");
    }
}