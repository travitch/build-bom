use fs_extra::dir::{copy,CopyOptions};
use serial_test::serial;  // for tests that change directories
use std::ffi::OsStr;
use std::path::{Path};
use std::env;
use tempfile::tempdir;
use xshell::{pushd};

use bom;
use bom::bom::options::{BitcodeOptions,ExtractOptions};
use bom::bom::clang_support::{is_compile_command_name,
                              is_option_arg,
                              next_arg_is_option_value,
                              is_blacklisted_clang_argument};

mod common;


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
    assert!(is_blacklisted_clang_argument(false, OsStr::new("-mmd")));
    assert!(is_blacklisted_clang_argument(false, OsStr::new("-mspecial-arch-flag")));
    assert!(is_blacklisted_clang_argument(false, OsStr::new("-mpreferred-stack-boundary=33")));

    assert!(!is_blacklisted_clang_argument(true, OsStr::new("-O2")));
    assert!(!is_blacklisted_clang_argument(true, OsStr::new("-Ofast")));
    assert!(!is_blacklisted_clang_argument(true, OsStr::new("-march=arm")));
    assert!(!is_blacklisted_clang_argument(true, OsStr::new("-mmd")));
    assert!(!is_blacklisted_clang_argument(true, OsStr::new("-mspecial-arch-flag")));
    assert!(!is_blacklisted_clang_argument(true, OsStr::new("-mpreferred-stack-boundary=33")));

    Ok(())
}


#[test]
#[serial]
#[test_log::test]
fn test_no_compile_only() -> anyhow::Result<()> {
    // This test builds an executable without the -c flag; we want to make sure
    // that build-bom can recognize that and do something reasonable
    let path = Path::new(common::SOURCE_DIR).join("no_compile_only");
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

    eprintln!("## build-bom generate bitcode via make and clang at {:?}",
              common::user_clang_cmd());
    let cmd_opts = vec![String::from("make")];
    let gen_opts = BitcodeOptions { clang_path: common::user_clang_cmd(),
                                    objcopy_path: None,
                                    bcout_path: None,
                                    suppress_automatic_debug: false,
                                    inject_arguments: Vec::new(),
                                    remove_arguments: Vec::new(),
                                    verbose: 0,
                                    strict: false,
                                    preproc_native: false,
                                    command: cmd_opts,
                                    any_fail: true };
    common::gen_bitcode(gen_opts)?;
    eprintln!("## bitcode generation complete");

    let mut exe_path = std::path::PathBuf::new();
    exe_path.push("hello-world");
    let mut bc_path = std::path::PathBuf::new();
    bc_path.push("hello-world.bc");
    let bc_path2 = bc_path.clone();
    eprintln!("## extract bitcode from {:?} to {:?} using llvm-link at {:?}",
              exe_path, bc_path, common::user_llvm_link_cmd());
    let extract_opts = ExtractOptions { input: exe_path,
                                        output: bc_path,
                                        llvm_link_path: common::user_llvm_link_cmd(),
                                        objcopy_path: None,
                                        verbose: 0 };
    common::extract_bitcode(extract_opts)?;
    eprintln!("## bitcode extracted");
    assert!(bc_path2.exists());
    Ok(())
}

#[test]
#[serial]
#[test_log::test]
fn test_blddir() -> anyhow::Result<()> {
    // This test creates a separate build directory and executes all build
    // operations from that directory, using relative paths to the original
    // source locations.
    let path = Path::new(common::SOURCE_DIR).join("blddir_test");
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

    let mut options = CopyOptions::new();
    options.depth = 2; // get headers, but not blddir subdirs generated files
    copy(abs_path, ".", &options)?;
    let _push2 = pushd("blddir_test")?;

    eprintln!("## build-bom generate bitcode via make and clang at {:?}",
              common::user_clang_cmd());
    let cmd_opts = vec![String::from("make")];
    let gen_opts = BitcodeOptions { clang_path: common::user_clang_cmd(),
                                    objcopy_path: None,
                                    bcout_path: None,
                                    suppress_automatic_debug: false,
                                    inject_arguments: vec!(
                                        [
                                            // Strict is true, as is
                                            // preproc_native, so make will
                                            // invoke gcc which will be used for
                                            // the preprocessing stage, which
                                            // generates some definitions not
                                            // valid for clang.  When not strict,
                                            // build-bom disables these
                                            // automatically, but in strict mode,
                                            // the argument injection is needed.
                                            "-D__malloc__(X,Y)=",
                                        ]
                                            .iter()
                                            .map(|s| String::from(*s))
                                            .collect()),
                                    remove_arguments: Vec::new(),
                                    verbose: 1,
                                    strict: true,
                                    preproc_native: true,
                                    command: cmd_opts,
                                    any_fail : true };
    common::gen_bitcode(gen_opts)?;
    eprintln!("## bitcode generation complete");

    let mut exe_path = std::path::PathBuf::new();
    exe_path.push("blddir");
    exe_path.push("bin");
    exe_path.push("hello-world");
    let mut bc_path = std::path::PathBuf::new();
    bc_path.push("hello-world.bc");
    let bc_path2 = bc_path.clone();
    eprintln!("## extract bitcode from {:?} to {:?} using llvm-link at {:?}",
              exe_path, bc_path, common::user_llvm_link_cmd());
    let extract_opts = ExtractOptions { input: exe_path,
                                        output: bc_path,
                                        llvm_link_path: common::user_llvm_link_cmd(),
                                        objcopy_path: None,
                                        verbose: 1 };
    common::extract_bitcode(extract_opts)?;
    eprintln!("## bitcode extracted");
    assert!(bc_path2.exists());
    Ok(())
}

#[test]
#[serial]
#[test_log::test]
fn test_direct_compile() -> anyhow::Result<()> {
    // This test invokes the compiler directly as the build operation (instead of
    // invoking a build tool such as "make") to ensure that build is handled
    // appropriately.
    let path = Path::new(common::SOURCE_DIR).join("no_compile_only");
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

    eprintln!("## build-bom generate bitcode via gcc and clang at {:?}",
              common::user_clang_cmd());
    let cmd_opts = vec!["gcc", "-Wall", "-Werror",
                        "-o", "hi-world",
                        "hello-world.c"
    ].iter().map(|s| (*s).into()).collect();
    let gen_opts = BitcodeOptions { clang_path: common::user_clang_cmd(),
                                    objcopy_path: None,
                                    bcout_path: None,
                                    suppress_automatic_debug: false,
                                    inject_arguments: Vec::new(),
                                    remove_arguments: Vec::new(),
                                    verbose: 2,
                                    strict: false,
                                    preproc_native: true,
                                    command: cmd_opts,
                                    any_fail: true };
    common::gen_bitcode(gen_opts)?;
    eprintln!("## bitcode generation complete");

    let mut exe_path = std::path::PathBuf::new();
    exe_path.push("hi-world");
    let mut bc_path = std::path::PathBuf::new();
    bc_path.push("hi-world.bc");
    let bc_path2 = bc_path.clone();
    eprintln!("## extract bitcode from {:?} to {:?} using llvm-link at {:?}",
              exe_path, bc_path, common::user_llvm_link_cmd());
    let extract_opts = ExtractOptions { input: exe_path,
                                        output: bc_path,
                                        llvm_link_path: common::user_llvm_link_cmd(),
                                        objcopy_path: None,
                                        verbose: 2 };
    common::extract_bitcode(extract_opts)?;
    eprintln!("## bitcode extracted");
    assert!(bc_path2.exists());
    Ok(())
}
