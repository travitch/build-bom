use fs_extra::dir::{copy,CopyOptions};
use std::path::{PathBuf, Path};
use tempfile::tempdir;
use xshell::{Cmd, pushd};

use bom;
use bom::bom::options::{Options,Subcommand,BitcodeOptions,ExtractOptions};

static SOURCE_DIR: &'static str = "tests/sources";

// Download the file at the given URL to [tests/sources/<filename>] if it
// doesn't already exist, returning the canonical absolute path to that file.
fn fetch_if_needed(url : &str, filename : &str) -> anyhow::Result<PathBuf> {
    let path = Path::new(SOURCE_DIR).join(filename);
    if !path.exists() {
        let cmd = Cmd::new("wget").arg("-O").arg(path.as_path()).arg(url);
        cmd.run()?;
    }

    let abs_path = std::fs::canonicalize(path.as_path())?;
    Ok(abs_path)
}

// Get the clang command provided by the user (via the CLANG environment variable), if any
//
// If the user did not provide one, just return None, which is interpreted by build-bom as 'clang'
fn user_clang_cmd() -> Option<PathBuf> {
    std::env::var("CLANG").map(|s| { let mut p = std::path::PathBuf::new(); p.push(s); p }).ok()
}

// Get the user-provided llvm-link command (via the LLVM_LINK environment variable), if any
//
// If the user did not provide one, return None, which build-bom interprets as 'llvm-link'
fn user_llvm_link_cmd() -> Option<String> {
    std::env::var("LLVM_LINK").ok()
}

fn gen_bitcode(gen_opts : BitcodeOptions) -> anyhow::Result<()> {
    let gen_cmd = Subcommand::GenerateBitcode(gen_opts);
    let gen_opt = Options { subcommand: gen_cmd };
    let rc = bom::run_bom(gen_opt)?;
    assert_eq!(rc, 0);
    Ok(())
}

fn extract_bitcode(extract_opts : ExtractOptions) -> anyhow::Result<()> {
    let extract_cmd = Subcommand::ExtractBitcode(extract_opts);
    let extract_opt = Options { subcommand: extract_cmd };
    let rc = bom::run_bom(extract_opt)?;
    assert_eq!(rc, 0);
    Ok(())
}

#[test]
fn test_zlib() -> anyhow::Result<()> {
    let url = "https://www.zlib.net/zlib-1.2.11.tar.gz";
    let filename = "zlib-1.2.11.tar.gz";
    let dir_name = "zlib-1.2.11";
    let abs_src = fetch_if_needed(url, filename)?;

    let tdir = tempdir()?;
    let _push1 = pushd(tdir.path())?;
    let tar = Cmd::new("tar").arg("xf").arg(abs_src);
    tar.run()?;
    let _push2 = pushd(dir_name)?;
    let conf = Cmd::new("bash").arg("configure");
    conf.run()?;

    let cmd_opts = vec![String::from("make")];
    let gen_opts = BitcodeOptions { clang_path: user_clang_cmd(),
                                    bcout_path: None,
                                    suppress_automatic_debug: false,
                                    inject_arguments: Vec::new(),
                                    remove_arguments: Vec::new(),
                                    verbose: false,
                                    command: cmd_opts };
    gen_bitcode(gen_opts)?;

    let mut so_path = std::path::PathBuf::new();
    so_path.push("libz.so.1.2.11");
    let mut bc_path = std::path::PathBuf::new();
    bc_path.push("libz.so.1.2.11.bc");
    let bc_path2 = bc_path.clone();
    let extract_opts = ExtractOptions { input: so_path, output: bc_path, llvm_link_path: user_llvm_link_cmd() };
    extract_bitcode(extract_opts)?;
    assert!(bc_path2.exists());
    Ok(())
}

#[test]
fn test_no_compile_only() -> anyhow::Result<()> {
    // This test builds an executable without the -c flag; we want to make sure
    // that build-bom can recognize that and do something reasonable
    let path = Path::new(SOURCE_DIR).join("no_compile_only");
    let abs_path = std::fs::canonicalize(path.as_path())?;

    let tdir = tempdir()?;
    let _push1 = pushd(tdir.path())?;

    let options = CopyOptions::new();
    copy(abs_path, ".", &options)?;
    let _push2 = pushd("no_compile_only")?;

    let cmd_opts = vec![String::from("make")];
    let gen_opts = BitcodeOptions { clang_path: user_clang_cmd(),
                                    bcout_path: None,
                                    suppress_automatic_debug: false,
                                    inject_arguments: Vec::new(),
                                    remove_arguments: Vec::new(),
                                    verbose: false,
                                    command: cmd_opts };
    gen_bitcode(gen_opts)?;

    let mut exe_path = std::path::PathBuf::new();
    exe_path.push("hello-world");
    let mut bc_path = std::path::PathBuf::new();
    bc_path.push("hello-world.bc");
    let bc_path2 = bc_path.clone();
    let extract_opts = ExtractOptions { input: exe_path, output: bc_path, llvm_link_path: user_llvm_link_cmd() };
    extract_bitcode(extract_opts)?;
    assert!(bc_path2.exists());
    Ok(())
}
