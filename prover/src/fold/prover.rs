use crate::{
    common, config::INNER_DEGREE, utils::chunk_trace_to_witness_block,
    zkevm::circuit::TargetCircuit,
};
use eth_types::{l2_types::BlockTrace, ToBigEndian};
use halo2_proofs::halo2curves::{bn256, grumpkin, CurveAffine};
use sirius::{
    commitment::CommitmentKey,
    ff::{Field, PrimeField},
    group::{prime::PrimeCurve, Group},
    ivc::{step_circuit::trivial, CircuitPublicParamsInput, PublicParams, IVC},
    poseidon::random_oracle::ROPair,
};
use std::{io, marker::PhantomData, num::NonZeroUsize, path::Path};
use zkevm_circuits::super_circuit::params::ARITY;

pub const T: usize = 8;
pub const RATE: usize = T - 1;

const CIRCUIT_TABLE_SIZE1: usize = 17;
const CIRCUIT_TABLE_SIZE2: usize = 17;

const COMMITMENT_KEY_SIZE: usize = 23;

const LIMBS_COUNT_LIMIT: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(10) };
const LIMB_WIDTH: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(32) };

type C1 = bn256::G1;
type C2 = grumpkin::G1;

pub type C1Scalar = <C1 as Group>::Scalar;

type C1Affine = <C1 as PrimeCurve>::Affine;
type C2Affine = <C2 as PrimeCurve>::Affine;
type C2Scalar = <C2 as Group>::Scalar;

type RandomOracle = sirius::poseidon::PoseidonRO<T, RATE>;
type RandomOracleConstant<F> = <RandomOracle as ROPair<F>>::Args;

fn get_or_create_commitment_key<C: CurveAffine>(
    k: usize,
    label: &'static str,
) -> io::Result<CommitmentKey<C>> {
    const FOLDER: &str = ".cache/examples";

    unsafe { CommitmentKey::load_or_setup_cache(Path::new(FOLDER), label, k) }
}

#[derive(Debug)]
pub struct Prover<C: TargetCircuit> {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub prover_impl: common::Prover,
    phantom: PhantomData<C>,
}

impl<C: TargetCircuit> Default for Prover<C> {
    fn default() -> Self {
        Prover {
            prover_impl: common::Prover::default(),
            phantom: PhantomData,
        }
    }
}

impl<C: TargetCircuit> From<common::Prover> for Prover<C> {
    fn from(prover_impl: common::Prover) -> Self {
        Self {
            prover_impl,
            phantom: PhantomData,
        }
    }
}

impl<C: TargetCircuit> Prover<C> {
    // this version is not needed unless we use this kzg key
    pub fn from_params_dir(params_dir: &str) -> Self {
        common::Prover::from_params_dir(params_dir, &[*INNER_DEGREE]).into()
    }

    pub fn fold(&mut self, _id: &str, block_traces: Vec<BlockTrace>) -> Result<(), anyhow::Error> {
        assert!(!block_traces.is_empty());

        let first_block = chunk_trace_to_witness_block(vec![block_traces[0].clone()])?;
        let sc1 = C::from_witness_block(&first_block)?;
        let sc2 = trivial::Circuit::<ARITY, _>::default();

        let primary_spec = RandomOracleConstant::<C1Scalar>::new(10, 10);
        let secondary_spec = RandomOracleConstant::<C2Scalar>::new(10, 10);

        let z_in = first_block
            .prev_state_root
            .to_be_bytes()
            .map(|byte| <C1Scalar as PrimeField>::from_u128(byte.into()));

        let primary_commitment_key =
            get_or_create_commitment_key::<bn256::G1Affine>(COMMITMENT_KEY_SIZE, "bn256")
                .expect("Failed to get secondary key");
        let secondary_commitment_key =
            get_or_create_commitment_key::<grumpkin::G1Affine>(COMMITMENT_KEY_SIZE, "grumpkin")
                .expect("Failed to get primary key");

        let pp = PublicParams::<
            '_,
            ARITY,
            ARITY,
            T,
            C1Affine,
            C2Affine,
            C::Inner,
            trivial::Circuit<ARITY, _>,
            RandomOracle,
            RandomOracle,
        >::new(
            CircuitPublicParamsInput::new(
                CIRCUIT_TABLE_SIZE1 as u32,
                &primary_commitment_key,
                primary_spec.clone(),
                &sc1,
            ),
            CircuitPublicParamsInput::new(
                CIRCUIT_TABLE_SIZE2 as u32,
                &secondary_commitment_key,
                secondary_spec.clone(),
                &sc2,
            ),
            LIMB_WIDTH,
            LIMBS_COUNT_LIMIT,
        )
        .unwrap();

        let mut ivc = IVC::new(&pp, &sc1, z_in, &sc2, [C2Scalar::ZERO; ARITY], false).unwrap();

        block_traces.into_iter().skip(1).for_each(|block_trace| {
            let block = chunk_trace_to_witness_block(vec![block_trace]).unwrap();
            let sc1 = C::from_witness_block(&block).unwrap();
            ivc.fold_step(&pp, &sc1, &sc2).unwrap();
        });

        // uncomment after implement on-circuit part of protogalaxy protocol
        // ivc.verify(&pp).unwrap();

        Ok(())
    }
}
