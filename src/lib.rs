pub mod bom;

use crate::bom::bitcode::bitcode_entrypoint;
use crate::bom::extract::extract_bitcode_entrypoint;
use crate::bom::normalize::normalize_entrypoint;
use crate::bom::trace::trace_entrypoint;
use crate::bom::options::{Options,Subcommand};

pub fn run_bom(opt : Options) -> anyhow::Result<i32> {
    match opt.subcommand {
        Subcommand::Trace(trace_opts) => { trace_entrypoint(&trace_opts)?; Ok(0) }
        Subcommand::Normalize(normalize_opts) => { normalize_entrypoint(&normalize_opts)?; Ok(0) }
        Subcommand::GenerateBitcode(bitcode_opts) => { bitcode_entrypoint(&bitcode_opts) }
        Subcommand::ExtractBitcode(extract_opts) => { extract_bitcode_entrypoint(&extract_opts)?; Ok(0) }
    }
}
