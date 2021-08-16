use std::path::Path;
use tempfile::tempdir;
use xshell::{Cmd, cmd, pushd};

use bom;
use bom::bom::options::{Options,Subcommand,BitcodeOptions,ExtractOptions};

#[test]
fn test_zlib() -> anyhow::Result<()> {
    let url = "https://www.zlib.net/zlib-1.2.11.tar.gz";
    let filename = "zlib-1.2.11.tar.gz";
    let dir_name = "zlib-1.2.11";
    let path = Path::new("tests/sources").join(filename);
    let abs_src = std::fs::canonicalize(path.as_path())?;
    print!("Checking if tarball exists\n");
    if !abs_src.exists() {
        print!("Fetching tarball\n");
        let cmd = Cmd::new("wget").arg("-O").arg(path).arg(url);
        cmd.run()?;
    }

    let tdir = tempdir()?;
    let _push1 = pushd(tdir.path())?;
    let tar = Cmd::new("tar").arg("xf").arg(abs_src);
    tar.run()?;
    let _push2 = pushd(dir_name)?;
    let conf = Cmd::new("bash").arg("configure");
    conf.run()?;

    let clang = std::env::var("CLANG").map(|s| { let mut p = std::path::PathBuf::new(); p.push(s); p });

    let cmd_opts = vec![String::from("make")];
    let gen_opts = BitcodeOptions { clang_path: clang.ok(), bcout_path: None, verbose: false, command: cmd_opts };
    let gen_cmd = Subcommand::GenerateBitcode(gen_opts);
    let gen_opt = Options { subcommand: gen_cmd };
    bom::run_bom(gen_opt)?;

    let llvm_link = std::env::var("LLVM_LINK");
    let mut so_path = std::path::PathBuf::new();
    so_path.push("libz.so.1.2.11");
    let mut bc_path = std::path::PathBuf::new();
    bc_path.push("libz.so.1.2.11.bc");
    let bc_path2 = bc_path.clone();
    let extract_opts = ExtractOptions { input: so_path, output: bc_path, llvm_link_path: llvm_link.ok() };
    let extract_cmd = Subcommand::ExtractBitcode(extract_opts);
    let extract_opt = Options { subcommand: extract_cmd };
    bom::run_bom(extract_opt)?;
    if bc_path2.exists() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Missing bitcode"))
    }
}
