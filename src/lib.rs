pub mod bom;

use env_logger::{Env};

use crate::bom::bitcode::bitcode_entrypoint;
use crate::bom::extract::extract_bitcode_entrypoint;
use crate::bom::normalize::normalize_entrypoint;
use crate::bom::trace::trace_entrypoint;
use crate::bom::options::{Options,BbCommand};

pub fn run_bom(opt : Options) -> anyhow::Result<i32> {
    let cmdline_log_filter = match opt.subcommand {
        BbCommand::GenerateBitcode(ref bitcode_opts) =>
            verbosity_to_log(&bitcode_opts.verbose),
        BbCommand::ExtractBitcode(ref extract_opts) =>
            verbosity_to_log(&extract_opts.verbose),
        _ => "warn",
    };
    let env = Env::new().default_filter_or(cmdline_log_filter);
    env_logger::init_from_env(env);
    run_bom_command(opt)
}

pub fn run_bom_command(opt : Options) -> anyhow::Result<i32> {
    match opt.subcommand {
        BbCommand::Trace(trace_opts) => { trace_entrypoint(&trace_opts)?; Ok(0) }
        BbCommand::Normalize(normalize_opts) => { normalize_entrypoint(&normalize_opts)?; Ok(0) }
        BbCommand::GenerateBitcode(bitcode_opts) => { bitcode_entrypoint(&bitcode_opts) }
        BbCommand::ExtractBitcode(extract_opts) => { extract_bitcode_entrypoint(&extract_opts) }
    }
}

fn verbosity_to_log(v_flags: &u8) -> &str {
    match v_flags {
        0 => "warn",
        1 => "info",
        _ => "debug",
    }

}
