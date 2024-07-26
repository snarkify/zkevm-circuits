use crate::{
    common, config::INNER_DEGREE, utils::chunk_trace_to_witness_block,
    zkevm::circuit::TargetCircuit,
};
use eth_types::l2_types::BlockTrace;
use sirius::ivc::step_circuit;
use std::marker::PhantomData;

const ARITY: usize = 1;

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
    pub fn from_params_dir(params_dir: &str) -> Self {
        common::Prover::from_params_dir(params_dir, &[*INNER_DEGREE]).into()
    }

    pub fn fold(&mut self, _id: &str, block_traces: Vec<BlockTrace>) -> Result<(), anyhow::Error> {
        let witness_block = chunk_trace_to_witness_block(block_traces)?;
        let primary_circuit = C::from_witness_block(&witness_block)?;
        // let secondary_circuit = step_circuit::trivial::Circuit::<ARITY, _>::default();
        Ok(())
    }
}
