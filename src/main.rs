mod bom;

use structopt::StructOpt;

use crate::bom::bitcode::bitcode_entrypoint;
use crate::bom::extract::extract_bitcode_entrypoint;
use crate::bom::normalize::normalize_entrypoint;
use crate::bom::trace::trace_entrypoint;
use crate::bom::options::{Options,Subcommand};


fn main() -> anyhow::Result<()> {
    let opt = Options::from_args();

    match opt.subcommand {
        Subcommand::Trace(trace_opts) => { trace_entrypoint(&trace_opts) }
        Subcommand::Normalize(normalize_opts) => { normalize_entrypoint(&normalize_opts) }
        Subcommand::GenerateBitcode(bitcode_opts) => { bitcode_entrypoint(&bitcode_opts) }
        Subcommand::ExtractBitcode(extract_opts) => { extract_bitcode_entrypoint(&extract_opts) }
    }
}



