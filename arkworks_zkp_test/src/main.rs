// cargo new arkworks_zkp_test
//
// cargo run
//
// 1. Generating parameters (Trusted Setup)...
// 2. Creating proof...
// 3. Verifying proof...
// ✅ Success! Proof is valid.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Field;
use ark_groth16::Groth16;
// Note: We import the macro differently or just use it if provided by the crate
use ark_relations::lc; 
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_snark::SNARK;
use ark_std::rand::{SeedableRng, rngs::StdRng};

struct SimpleCircuit {
    pub x: Option<Fr>,   
    pub out: Option<Fr>, 
}

impl ConstraintSynthesizer<Fr> for SimpleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x_val = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let out_val = cs.new_input_variable(|| self.out.ok_or(SynthesisError::AssignmentMissing))?;
        
        let x_sq_val = cs.new_witness_variable(|| {
            let x = self.x.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(x.square())
        })?;
        // Use lc!() instead of lc()
        cs.enforce_constraint(lc!() + x_val, lc!() + x_val, lc!() + x_sq_val)?;
        
        let x_cu_val = cs.new_witness_variable(|| {
            let x = self.x.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(x.square() * x)
        })?;
        cs.enforce_constraint(lc!() + x_sq_val, lc!() + x_val, lc!() + x_cu_val)?;

        // Final Constraint: (x^3 + x + 5) * 1 = out
        cs.enforce_constraint(
            lc!() + x_cu_val + x_val + (Fr::from(5u32), Variable::One),
            lc!() + Variable::One,
            lc!() + out_val,
        )?;
        Ok(())
    }
}

fn main() {
    let mut rng = StdRng::seed_from_u64(42u64); 

    println!("1. Generating parameters (Trusted Setup)...");
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        SimpleCircuit { x: None, out: None }, 
        &mut rng
    ).unwrap();

    println!("2. Creating proof...");
    let secret_x = Fr::from(3u32); // Witness
    let public_out = Fr::from(35u32); // Public Input
    
    let proof = Groth16::<Bls12_381>::prove(
        &pk, 
        SimpleCircuit { x: Some(secret_x), out: Some(public_out) }, 
        &mut rng
    ).unwrap();

    println!("3. Verifying proof...");
    let is_valid = Groth16::<Bls12_381>::verify(&vk, &[public_out], &proof).unwrap();

    if is_valid {
        println!("✅ Success! Proof is valid.");
    } else {
        println!("❌ Failure! Proof is invalid.");
    }
}