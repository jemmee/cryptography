// npm install circomlib
//
// circom merkle.circom --r1cs --wasm --sym


pragma circom 2.1.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/switcher.circom";

// Verifies that a leaf exists in a Merkle Tree of a given depth
template MerkleTreeChecker(depth) {
    signal input leaf;
    signal input path_elements[depth];
    signal input path_indices[depth]; // 0 if left, 1 if right
    signal input root;

    signal level_hashes[depth + 1];
    level_hashes[0] <== leaf;

    component hashers[depth];
    component switchers[depth];

    for (var i = 0; i < depth; i++) {
        switchers[i] = Switcher();
        switchers[i].L <== level_hashes[i];
        switchers[i].R <== path_elements[i];
        switchers[i].sel <== path_indices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        level_hashes[i + 1] <== hashers[i].out;
    }

    // The final calculated hash must match the public root
    root === level_hashes[depth];
}

component main {public [root]} = MerkleTreeChecker(3);