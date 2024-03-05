use bom;
use bom::bom::options::{BitcodeOptions, ExtractOptions, Options, Subcommand};
use std::path::{PathBuf};

pub static SOURCE_DIR: &'static str = "tests/sources";


// Get the clang command provided by the user (via the CLANG environment variable), if any
//
// If the user did not provide one, just return None, which is interpreted by build-bom as 'clang'
pub fn user_clang_cmd() -> Option<PathBuf> {
    std::env::var("CLANG").map(|s| { let mut p = std::path::PathBuf::new(); p.push(s); p }).ok()
}

// Get the user-provided llvm-link command (via the LLVM_LINK environment variable), if any
//
// If the user did not provide one, return None, which build-bom interprets as 'llvm-link'
pub fn user_llvm_link_cmd() -> Option<String> {
    std::env::var("LLVM_LINK").ok()
}

// Get the user-provided llvm-dis command (via the LLVM_DIS environment variable), if any
//
// If the user did not provide one, return None, which build-bom interprets as 'llvm-dis'
#[allow(dead_code)]
pub fn user_llvm_dis_cmd() -> Option<String> {
    std::env::var("LLVM_DIS").ok()
}

pub fn gen_bitcode(gen_opts : BitcodeOptions) -> anyhow::Result<()> {
    let gen_cmd = Subcommand::GenerateBitcode(gen_opts);
    let gen_opt = Options { subcommand: gen_cmd };
    let rc = bom::run_bom_command(gen_opt)?;
    assert_eq!(rc, 0);
    Ok(())
}

pub fn extract_bitcode(extract_opts : ExtractOptions) -> anyhow::Result<()> {
    let extract_cmd = Subcommand::ExtractBitcode(extract_opts);
    let extract_opt = Options { subcommand: extract_cmd };
    let rc = bom::run_bom_command(extract_opt)?;
    assert_eq!(rc, 0);
    Ok(())
}
