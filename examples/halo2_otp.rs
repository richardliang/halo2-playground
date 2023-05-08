use clap::Parser;
use halo2_base::{gates::GateChip, gates::GateInstructions, utils::ScalarField, AssignedValue, Context};
use halo2_playground::scaffold::{cmd::Cli, run};
use poseidon::PoseidonChip;
use serde::{Deserialize, Serialize};

// Poseidon constants
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

// Valid for 100 years; TOTP interval 30 seconds
// 100 * 365 * 24 * 60 * 2 = 105120000
// log2 (105120000) = 27
const LEVELS: usize = 27;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub otp: String, // field element, but easier to deserialize as a string
    pub time: String,
    pub path_elements: [String; LEVELS],
    pub path_index: [String; LEVELS]
}

fn otp_merkle_proof<F: ScalarField>(
    ctx: &mut Context<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    let otp = F::from_str_vartime(&input.otp).expect("deserialize field element should not fail");
    let time = F::from_str_vartime(&input.time).expect("deserialize field element should not fail");
    let path_elements = input.path_elements.map(|x: String| ctx.load_witness(F::from_str_vartime(&x).unwrap()));
    let path_index = input.path_index.map(|x: String| ctx.load_witness(F::from_str_vartime(&x).unwrap()));

    let otp = ctx.load_witness(otp);
    let time = ctx.load_witness(time);
    make_public.push(time);

    // create a Gate chip that contains methods for basic arithmetic operations
    let gate = GateChip::<F>::default();
    let mut poseidon = PoseidonChip::<F, T, RATE>::new(ctx, R_F, R_P).unwrap();
    poseidon.update(&[time, otp]);
    let leaf = poseidon.squeeze(ctx, &gate).unwrap();

    // // Loop through the path elements
    let mut level_hashes = vec![];
    level_hashes.push(leaf.clone());

    for i in 0..LEVELS {
        // Should be 0 or 1
        gate.assert_bit(ctx, path_index[i].clone());

        // Instantiate inner poseidon instances
        let mut inner_poseidon = PoseidonChip::<F, T, RATE>::new(ctx, R_F, R_P).unwrap();

        if *path_index[i].value() == F::zero() {
            inner_poseidon.update(&[level_hashes[i], path_elements[i]]);
        } else {
            inner_poseidon.update(&[path_elements[i], level_hashes[i]]);
        }
        level_hashes.push(inner_poseidon.squeeze(ctx, &gate).unwrap());
    }

    let root = level_hashes[LEVELS];
    make_public.push(root);
    println!("otp: {:?}, time: {:?}, root: {:?}", otp.value(), time.value(), root.value());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    run(otp_merkle_proof, args);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CircuitInput;
    use halo2_base::gates::builder::{GateThreadBuilder, GateCircuitBuilder};
    use halo2_base::halo2_proofs::dev::MockProver;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

    #[test]
    fn test_otp_merkle_proof() {
        let params = CircuitInput {
            otp: "12345".to_string(),
            time: "3155000".to_string(),
            path_elements: ["1234","11234","12222","118865","435676","494999","4837377","1234","11234","12222","118865","435676","494999","4837377","1234","11234","12222","118865","435676","494999","4837377","1234","11234","12222","118865","435676","494999"].map(|x| x.to_string()),
            path_index: ["1","1","0","1","0","1","0","1","1","0","1","0","1","0","1","1","0","1","0","1","0","1","1","0","1","0","1"].map(|x| x.to_string())
        };

        let k = 10u32;

        // Instantiate Vec of AssignedValue<F> to store public inputs
        let mut make_public = vec![];

        let mut builder = GateThreadBuilder::<Fr>::mock();
        otp_merkle_proof(builder.main(0), params, &mut make_public);

        builder.config(k as usize, Some(12));

        let circuit = GateCircuitBuilder::mock(builder);
        MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();

        println!("Public inputs: {:?}", make_public);
    }
}