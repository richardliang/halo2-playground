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

    // first we load a private input `x` (let's not worry about public inputs for now)
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
    poseidon.update(&[otp, time]);
    let leaf = poseidon.squeeze(ctx, &gate).unwrap();

    // // Loop through the path elements
    let mut level_hashes = vec![];
    level_hashes.push(leaf.clone());

    for i in 0..LEVELS {
        // Should be 0 or 1
        gate.assert_bit(ctx, path_index[i].clone());

        if *path_index[i].value() == F::zero() {
            poseidon.update(&[path_elements[i], level_hashes[i]]);
        } else {
            poseidon.update(&[level_hashes[i], path_elements[i]]);
        }
        level_hashes.push(poseidon.squeeze(ctx, &gate).unwrap());
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
