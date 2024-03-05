use anyhow::Context;
use fs_extra::dir::{copy,CopyOptions};
use serial_test::serial;  // for tests that change directories
use std::fs::File;
use std::io::Read;
use std::path::{PathBuf, Path};
use tempfile::{TempDir,tempdir};
use xshell::{Cmd, pushd};

use bom;
use bom::bom::options::{BitcodeOptions,ExtractOptions};

mod common;

/// Runs a series of tests by using/building the zlib sources.  The zlib
/// distribution is rather ideal for this because:
///
///  1. It is relatively small, but does consist of multiple sources
///  2. It builds both shared and static libraries
///  3. It builds sample executables, some statically linked, some share linked
///
/// These features allow a number of different verifications of build-bom to be
/// performed here.

// Download the file at the given URL to [tests/sources/<filename>] if it
// doesn't already exist, returning the canonical absolute path to that file.
fn fetch_if_needed(url : &str, filename : &str) -> anyhow::Result<PathBuf> {
    let path = Path::new(common::SOURCE_DIR).join(filename);
    if !path.exists() {
        let cmd = Cmd::new("wget").arg("-O").arg(path.as_path()).arg(url);
        cmd.run()?;
    }

    let abs_path = std::fs::canonicalize(path.as_path())?;
    Ok(abs_path)
}


struct ZlibBld {
    tdir: TempDir,
    tgt_path: PathBuf,
    zlib_version: String,
}

lazy_static::lazy_static! {
    static ref ZLIB_BLD: ZlibBld = {
        match zlib_do_build() {
            Ok((tdir, zlib_version, tgt_path)) =>
                ZlibBld { tdir, tgt_path, zlib_version },
            Err(e) =>
                panic!("Unable to compile zlib for testing: {:?}", e),
        }
    };
}


fn zlib_do_build() -> anyhow::Result<(TempDir, String, PathBuf)> {
    let url = "https://www.zlib.net/current/zlib.tar.gz";
    let filename = "zlib.tar.gz";
    let abs_src = fetch_if_needed(url, filename)?;

    let tdir = tempdir()?;
    let _push1 = pushd(tdir.path())?;
    let tar = Cmd::new("tar").arg("xf").arg(abs_src);
    tar.run()?;
    let dir_name = &glob::glob("zlib-*")?.filter_map(Result::ok).collect::<Vec<PathBuf>>()[0];
    let zlib_version = &dir_name.to_str().unwrap()["zlib-".len()..];
    let _push2 = pushd(dir_name)?;
    let conf = Cmd::new("bash").arg("configure");
    conf.run()?;

    let cmd_opts = vec![String::from("make")];
    let gen_opts = BitcodeOptions { clang_path: common::user_clang_cmd(),
                                    bcout_path: None,
                                    suppress_automatic_debug: false,
                                    inject_arguments: Vec::new(),
                                    remove_arguments: Vec::new(),
                                    verbose: vec![true],
                                    strict: false,
                                    command: cmd_opts,
                                    any_fail: false };
    // n.b. any_fail must be false because zlib runs autoconf/configure and the
    // failures there are tallied and cause build-bom to exit with a failure.
    common::gen_bitcode(gen_opts)?;

    let mut tgt_path = std::path::PathBuf::from(tdir.path());
    tgt_path.push(dir_name);

    Ok((tdir, zlib_version.into(), tgt_path))
}

fn get_llvm_str(bc_file: &Path) -> anyhow::Result<String> {
    Cmd::new(common::user_llvm_dis_cmd()).arg(bc_file).run()
        .context("Disassembling")?;
    let mut ll_path = PathBuf::from(bc_file);
    ll_path.set_extension("ll");
    let mut ll = String::new();
    File::open(ll_path)?.read_to_string(&mut ll)?;
    Ok(ll)
}

#[test]
#[serial]
fn test_zlib_sharedlib() -> anyhow::Result<()> {
    let ZlibBld { ref tdir, ref zlib_version, ref tgt_path } = *ZLIB_BLD;
    let mut so_path = tgt_path.clone();
    so_path.push(format!("libz.so.{}", zlib_version));
    assert!(so_path.exists(), "build did not successfully generate a shared library");
    let mut bc_path = tgt_path.clone();
    bc_path.push(format!("libz.so.{}.bc", zlib_version));
    let bc_path2 = bc_path.clone();
    let extract_opts = ExtractOptions { input: so_path,
                                        output: bc_path,
                                        llvm_link_path: common::user_llvm_link_cmd(),
                                        verbose: vec![true, true]};
    common::extract_bitcode(extract_opts)?;

    // Bitcode extracted from a shared library is the sum total of all the
    // executable code in that shared library.  Verify the bitcode contains
    // entries from the various input files.
    let ll = get_llvm_str(&bc_path2)?;
    assert!(ll.contains("inflateCopy"), "missing contents from inflate.c");
    assert!(ll.contains("compressBound"), "missing contents from compress.c");
    assert!(ll.contains("deflateSetHeader"), "missing contents from deflate.c");
    assert!(ll.contains("gzfread"), "missing contents from gzread.c");
    assert!(ll.contains("gzfwrite"), "missing contents from gzwrite.c");
    assert!(tdir.path().exists(), "tempdir still exists");
    Ok(())
}

#[test]
#[serial]
fn test_zlib_staticlib() -> anyhow::Result<()> {
    let ZlibBld { ref tdir, ref tgt_path, .. } = *ZLIB_BLD;
    let mut lib_path = tgt_path.clone();
    lib_path.push("libz.a");
    assert!(lib_path.exists(), "build did not successfully generate a static library");
    let mut bc_path = tgt_path.clone();
    bc_path.push("libz.bc");
    let bc_path2 = bc_path.clone();
    let extract_opts = ExtractOptions { input: lib_path,
                                        output: bc_path,
                                        llvm_link_path: common::user_llvm_link_cmd(),
                                        verbose: vec![true, true]};
    common::extract_bitcode(extract_opts)?;

    // When extracting bitcode from a static library, build-bom extracts only the
    // bitcode from the *last* entry in the static library.  This actually occurs
    // because objcopy (which is used to extract the .llvm_bitcode section from
    // the ELF file) will actually iterate over every .llvm_bitcode section in
    // each static library entry, extracting each and writing them to the same
    // file.
    //
    // Because bitcode files cannot be directly combined, the static library
    // format is not entirely useful anyhow.  The result of linking against a
    // static library is a single bitcode file with all the utilized functions,
    // but the library itself is more of the potential of an analyzable bitcode.


    // Now verify the bitcode contains entries from the various input files
    let ll = get_llvm_str(&bc_path2)?;
    let fnd = vec![
        ll.contains("inflateCopy"),
        ll.contains("compressBound"),
        ll.contains("deflateSetHeader"),
        ll.contains("gzfread"),
        ll.contains("gzfwrite"),
    ];
    assert_eq!(fnd, vec![false, false, false, false, true]);
    assert!(tdir.path().exists(), "tempdir still exists");
    Ok(())
}

#[test]
#[serial]
fn test_zlib_exe_static() -> anyhow::Result<()> {
    let ZlibBld { ref tdir, ref tgt_path, .. } = *ZLIB_BLD;
    let mut exe_path = tgt_path.clone();
    exe_path.push("example64");
    assert!(exe_path.exists(), "build did not successfully generate a static executable");
    let mut bc_path = tgt_path.clone();
    bc_path.push("example64.bc");
    let bc_path2 = bc_path.clone();
    let extract_opts = ExtractOptions { input: exe_path,
                                        output: bc_path,
                                        llvm_link_path: common::user_llvm_link_cmd(),
                                        verbose: vec![true, true]};
    common::extract_bitcode(extract_opts)?;

    // Bitcode extracted from an executable linked against a static library
    // contains the bitcode from the executable and bitcode from every module in
    // the static library that the executable utilizes.

    let ll = get_llvm_str(&bc_path2)?;
    let fnd = vec![
        ll.contains("inflateCopy"),   // static lib
        ll.contains("compressBound"),   // static lib
        ll.contains("deflateSetHeader"),   // static lib
        ll.contains("gzfread"),   // static lib
        ll.contains("gzfwrite"),   // static lib
        ll.contains("test_gzio"),  // exe src
    ];
    assert_eq!(fnd, vec![true, true, true, true, true, true]);
    assert!(tdir.path().exists(), "tempdir still exists");
    Ok(())
}

#[test]
#[serial]
fn test_zlib_exe_sharedlib() -> anyhow::Result<()> {
    let ZlibBld { ref tdir, ref tgt_path, .. } = *ZLIB_BLD;
    let mut exe_path = tgt_path.clone();
    exe_path.push("examplesh");
    assert!(exe_path.exists(), "build did not successfully generate a shared executable");
    let mut bc_path = tgt_path.clone();
    bc_path.push("examplesh.bc");
    let bc_path2 = bc_path.clone();
    let extract_opts = ExtractOptions { input: exe_path,
                                        output: bc_path,
                                        llvm_link_path: common::user_llvm_link_cmd(),
                                        verbose: vec![true, true]};
    common::extract_bitcode(extract_opts)?;

    // Bitcode extracted from an executable linked against a shared library is
    // just the contents of the executable code, but does *not* include any of
    // the bitcode from the shared library.

    let ll = get_llvm_str(&bc_path2)?;
    let fnd = vec![
        ll.contains("inflateCopy"),   // shared lib
        ll.contains("compressBound"),   // shared lib
        ll.contains("deflateSetHeader"),   // shared lib
        ll.contains("gzfread"),   // shared lib
        ll.contains("gzfwrite"),   // shared lib
        ll.contains("test_gzio"),  // exe src
    ];
    assert_eq!(fnd, vec![false, false, false, false, false, true]);
    assert!(tdir.path().exists(), "tempdir still exists");
    Ok(())
}

#[test]
#[serial]
fn test_zlib_exe_modified() -> anyhow::Result<()> {
    // In this test, one of the files that is part of the static library is
    // modified, and the library is rebuilt *without* using build-bom.  Then the
    // executable is rebuild *using* build-bom.
    //
    // Because this modifies the build, and all tests run in parallel, this first
    // copies the build tree to a new location and then operates on that new
    // location; this should still be faster than doing a full build in a new
    // location.

    let ZlibBld { ref tdir, ref tgt_path, .. } = *ZLIB_BLD;
    let my_tdir = tempdir()?;

    {
        let my_tgt_path = my_tdir.path();
        let mut cpopts = CopyOptions::new();
        cpopts.content_only = true;
        copy(tgt_path, my_tgt_path, &cpopts)?;

        // While the above copy is intended to preserve the file timestamps, it
        // is not always guaranteed that there will be enough system time
        // resolution to preserve the "make finished" status, so re-run the build
        // via build-bom to ensure it is up-to-date before making any changes.
        let cmd_opts = vec![String::from("make")];
        let gen_opts = BitcodeOptions { clang_path: common::user_clang_cmd(),
                                        bcout_path: None,
                                        suppress_automatic_debug: false,
                                        inject_arguments: Vec::new(),
                                        remove_arguments: Vec::new(),
                                        verbose: vec![true, true],
                                        strict: false,
                                        command: cmd_opts,
                                        any_fail: false };
        {
            let _push2 = pushd(my_tgt_path)?;
            common::gen_bitcode(gen_opts.clone())?;
        }

        let mut exe_path = PathBuf::from(my_tgt_path);
        exe_path.push("example64");
        assert!(exe_path.exists(), "build did not successfully generate a static executable");

        // Now make specific changes and rebuild *without* build-bom
        Cmd::new("sed").arg("-ie").arg("s,Copyright,COPYRIGHT,")
            .arg(my_tgt_path.join("gzread.c"))
            .run()?;
        Cmd::new("make").arg("-C").arg(my_tgt_path)
            .arg("-f").arg("Makefile.in").arg("libz.a").run()?;

        // And finally, build the remaining parts with build-bom
        {
            let _push2 = pushd(my_tgt_path)?;
            common::gen_bitcode(gen_opts)?;
        }
        assert!(exe_path.exists(), "build did not successfully regenerate a static executable");

        let mut bc_path = PathBuf::from(my_tgt_path);
        bc_path.push("example64.bc");
        let bc_path2 = bc_path.clone();
        let extract_opts = ExtractOptions { input: exe_path,
                                            output: bc_path,
                                            llvm_link_path: common::user_llvm_link_cmd(),
                                            verbose: vec![true, true]};
        common::extract_bitcode(extract_opts)?;

        // Bitcode extracted from an executable linked against a static library
        // contains the bitcode from the executable and bitcode from every module in
        // the static library that the executable utilizes.

        let ll = get_llvm_str(&bc_path2)?;
        let fnd = vec![
            ll.contains("inflateCopy"),   // static lib
            ll.contains("compressBound"),   // static lib
            ll.contains("deflateSetHeader"),   // static lib
            ll.contains("gzfread"),   // static lib, rebuilt outside of build-bom
            ll.contains("gzfwrite"),   // static lib
            ll.contains("test_gzio"),  // exe src
        ];
        assert_eq!(fnd, vec![true, true, true, false, true, true]);
    }
    assert!(tdir.path().exists(), "tempdir still exists");
    Ok(())
}
