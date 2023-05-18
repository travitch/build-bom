use fs_extra::dir::{copy,CopyOptions};
use std::ffi::OsStr;
use std::path::{PathBuf, Path};
use std::env;
use tempfile::tempdir;
use xshell::{Cmd, pushd};

use bom;
use bom::bom::options::{Options,Subcommand,BitcodeOptions,ExtractOptions};
use bom::bom::clang_support::{is_compile_command_name,
                              is_option_arg,
                              next_arg_is_option_value,
                              is_blacklisted_clang_argument};


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
fn test_is_compile_cmd() -> anyhow::Result<()> {
    assert!(is_compile_command_name(OsStr::new("gcc")));
    assert!(is_compile_command_name(OsStr::new("arm-musl-gcc")));
    assert!(is_compile_command_name(OsStr::new("/usr/local/bin/gcc-9/bin/gcc")));
    assert!(!is_compile_command_name(OsStr::new("gcc-musl-arm")));


    assert!(is_compile_command_name(OsStr::new("arm-musl-gcc")));
    assert!(is_compile_command_name(OsStr::new("/usr/local/bin/gcc-9/bin/gcc")));
    assert!(!is_compile_command_name(OsStr::new("gcc-musl-arm")));
    Ok(())
}

#[test]
fn test_option_recognition() -> anyhow::Result<()> {

    assert!(is_option_arg(OsStr::new("-o")));
    assert!(is_option_arg(OsStr::new("-or")));
    assert!(is_option_arg(OsStr::new("--o")));
    assert!(is_option_arg(OsStr::new("--or")));
    assert!(!is_option_arg(OsStr::new("o-")));
    assert!(!is_option_arg(OsStr::new("\"-o\"")));

    assert!(next_arg_is_option_value(OsStr::new("-o")));
    assert!(next_arg_is_option_value(OsStr::new("-rpath")));

    // Single-letter unary options can take their argument with no intervening
    // space.  In that situation, the next argument is *not* the option value.
    assert!(!next_arg_is_option_value(OsStr::new("-ofile")));

    // Single-letter unary options do not use an = separator and interpret it as
    // part of the argument value.
    assert!(!next_arg_is_option_value(OsStr::new("-o=file")));  // value is "=file"

    // Multi-letter unary options starting with two dashes can use a space or an
    // = separator.
    assert!(next_arg_is_option_value(OsStr::new("--param")));
    assert!(!next_arg_is_option_value(OsStr::new("--param=x=y")));

    // Multi-letter unary options starting with a single dash (non-standard)
    // usually have a space before their argument.
    assert!(next_arg_is_option_value(OsStr::new("-rpath")));
    assert!(!next_arg_is_option_value(OsStr::new("-rpathfoo")));
    assert!(!next_arg_is_option_value(OsStr::new("-rpath=foo")));
    assert!(!next_arg_is_option_value(OsStr::new("--rpath")));

    // However, some compilers have multi-letter options starting with a single
    // dash that *can* use a = separator instead of a space.  For those, it
    // should not indicate that the next argument is the option value.
    assert!(next_arg_is_option_value(OsStr::new("-aux-info")));
    assert!(!next_arg_is_option_value(OsStr::new("-aux-info=file.aux")));
    assert!(!next_arg_is_option_value(OsStr::new("--aux-info")));

    // While allowed by getopt, neither gcc nor clang (nor any other compiler we
    // support) allows combining single-letter nullary options into a single
    // word.  For example, "-w" and "-H" are both single letter options, but
    // "-wH" and "-Hw" are both unrecognized.  This includes situations where the
    // last option is a unary option.
    //
    // These tests assume -o is a single-letter unary option and neither Q nor Qo
    // is a unary option.
    assert!(!next_arg_is_option_value(OsStr::new("-Qo")));
    assert!(!next_arg_is_option_value(OsStr::new("-oQ")));  // value is Q

    // Some older tools deviate even further.  For example, "tar" has "options"
    // but some of those options are *required*, so it always treats its first
    // argument as options even if there's no initial dash.  This is not
    // supported for gcc/clang/et-al, so this argument parse is not valid here.
    assert!(!next_arg_is_option_value(OsStr::new("o")));

    // Miscellaneous additional tests

    assert!(!next_arg_is_option_value(OsStr::new("--o")));
    assert!(!next_arg_is_option_value(OsStr::new("--ofile")));
    assert!(!next_arg_is_option_value(OsStr::new("-Cofile")));

    Ok(())
}

#[test]
fn test_blacklist() -> anyhow::Result<()> {
    assert!(!is_blacklisted_clang_argument(false, OsStr::new("-D")));
    assert!(is_blacklisted_clang_argument(false, OsStr::new("-MD")));
    assert!(is_blacklisted_clang_argument(false, OsStr::new("-MMD")));
    assert!(!is_blacklisted_clang_argument(false, OsStr::new("-MMMD")));
    assert!(!is_blacklisted_clang_argument(false, OsStr::new("-MMD2")));
    assert!(!is_blacklisted_clang_argument(false, OsStr::new("-mmd")));
    assert!(!is_blacklisted_clang_argument(false, OsStr::new("MMD")));
    assert!(!is_blacklisted_clang_argument(false, OsStr::new("--file=my-MMD")));

    assert!(is_blacklisted_clang_argument(false, OsStr::new("-quiet")));
    assert!(!is_blacklisted_clang_argument(false, OsStr::new("--quiet")));
    assert!(!is_blacklisted_clang_argument(false, OsStr::new("-quieter")));

    assert!(is_blacklisted_clang_argument(false, OsStr::new("--param=")));
    assert!(is_blacklisted_clang_argument(false, OsStr::new("--param=something")));
    assert!(is_blacklisted_clang_argument(false, OsStr::new("--param=\"many things\"")));

    // Some arguments are only blacklisted if not in strict mode:
    assert!(is_blacklisted_clang_argument(false, OsStr::new("-O2")));
    assert!(is_blacklisted_clang_argument(false, OsStr::new("-Ofast")));
    assert!(is_blacklisted_clang_argument(false, OsStr::new("-march=arm")));

    assert!(!is_blacklisted_clang_argument(true, OsStr::new("-O2")));
    assert!(!is_blacklisted_clang_argument(true, OsStr::new("-Ofast")));
    assert!(!is_blacklisted_clang_argument(true, OsStr::new("-march=arm")));

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
                                    strict: false,
                                    command: cmd_opts,
                                    any_fail: false };
    // n.b. any_fail must be false because zlib runs autoconf/configure and the
    // failures there are tallied and cause build-bom to exit with a failure.
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
    eprintln!("## Canonicalizing input: {:?} (from {:?})", path, env::current_dir());
    let abs_path = match std::fs::canonicalize(path.as_path()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("## Unable to canonicalize path {:?} (got {:?})", path, e);
            return Err(From::from(e));
        }
    };
    eprintln!("## Using source from: {:?}", abs_path);

    let tdir = tempdir()?;
    let _push1 = pushd(tdir.path())?;

    let options = CopyOptions::new();
    copy(abs_path, ".", &options)?;
    let _push2 = pushd("no_compile_only")?;

    eprintln!("## build-bom generate bitcode via make and clang at {:?}", user_clang_cmd());
    let cmd_opts = vec![String::from("make")];
    let gen_opts = BitcodeOptions { clang_path: user_clang_cmd(),
                                    bcout_path: None,
                                    suppress_automatic_debug: false,
                                    inject_arguments: Vec::new(),
                                    remove_arguments: Vec::new(),
                                    verbose: false,
                                    strict: false,
                                    command: cmd_opts,
                                    any_fail: true };
    gen_bitcode(gen_opts)?;
    eprintln!("## bitcode generation complete");

    let mut exe_path = std::path::PathBuf::new();
    exe_path.push("hello-world");
    let mut bc_path = std::path::PathBuf::new();
    bc_path.push("hello-world.bc");
    let bc_path2 = bc_path.clone();
    eprintln!("## extract bitcode from {:?} to {:?} using llvm-link at {:?}",
              exe_path, bc_path, user_llvm_link_cmd());
    let extract_opts = ExtractOptions { input: exe_path, output: bc_path, llvm_link_path: user_llvm_link_cmd() };
    extract_bitcode(extract_opts)?;
    eprintln!("## bitcode extracted");
    assert!(bc_path2.exists());
    Ok(())
}
