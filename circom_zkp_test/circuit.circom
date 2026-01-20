// git clone https://github.com/iden3/circom.git
// cd circom
// cargo build --release
// cargo install --path circom
//
// npm install -g snarkjs
//
// circom circuit.circom --r1cs --wasm --sym
//
// cd circuit_js
// node generate_witness.js circuit.wasm ../input.json ../witness.wtns
// cd ..
//
// # Start ceremony
// snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
// # Contribute randomness
// snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v
// # Prepare Phase 2
// snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v
// # Setup Groth16
// snarkjs groth16 setup circuit.r1cs pot12_final.ptau circuit_0000.zkey
// snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey --name="1st Contributor Name" -v
// # Export verification key
// snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
//
// # Create the proof
// snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json
//
// # Verify the proof
// snarkjs groth16 verify verification_key.json public.json proof.json

pragma circom 2.0.0;

// This circuit proves: x^3 + x + 5 = out
template SimpleEquation() {
    // Signals
    signal input x;      // Private by default
    signal output out;   // Public

    // Intermediate signals (needed because Circom only allows quadratic constraints)
    signal x_sq;
    signal x_cu;

    // Constraints (Rank-1 Constraint System)
    x_sq <== x * x;      // x * x = x_sq
    x_cu <== x_sq * x;   // x_sq * x = x_cu

    // x^3 + x + 5 = out
    out <== x_cu + x + 5;
}

component main = SimpleEquation();