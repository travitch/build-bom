use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bom::options::ExtractOptions;
use crate::bom::bitcode::ELF_SECTION_NAME;

#[derive(thiserror::Error,Debug)]
pub enum ExtractError {
    #[error("Error running command {0:} {1:?} ({2:?})")]
    ErrorRunningCommand(String,Vec<OsString>,std::io::Error),

    #[error("Temp directory lost during extraction")]
    ErrorLostTmpDir,
}

pub fn extract_bitcode_entrypoint(extract_options : &ExtractOptions) -> anyhow::Result<i32> {
    let tmp_dir = tempfile::TempDir::new()?;
    let res = do_bitcode_extraction(extract_options, tmp_dir.path());

    // The tmp_dir should always exist, so this should never execute the body of
    // the if statement. However, the point of this is that *the tmp_dir should
    // still exist*, and part of this is avoiding the "Early drop pitfall"
    // described at https://docs.rs/tempfile/latest/tempfile, so this if
    // expression uses the original tmp_dir thus allowing Rust to help us ensure
    // it isn't dropped somewhere in do_bitcode_extraction by an inadvertent
    // Copy/move that would trigger resource cleanup in disposal of this original
    // object.
    if !tmp_dir.path().exists() {
        return Err(anyhow::Error::new(ExtractError::ErrorLostTmpDir));
    };
    res
}

pub fn do_bitcode_extraction(extract_options : &ExtractOptions,
                             tmp_path : &Path) -> anyhow::Result<i32> {
    let mut tar_path = PathBuf::new();
    tar_path.push(tmp_path);
    tar_path.push("bitcode.tar");
    let ok_tar_name = OsString::from(tar_path.clone()).into_string().unwrap();

    // Use objcopy to extract our tar file from the target.  Note that objcopy
    // expects to write an output object.  If not given an output file, it will
    // try to replace the input file with the generated version by copying the
    // input file to a temporary file (adjacent to the input file) and then
    // reading that temporary file to rewriting the input file with the output
    // data.
    //
    // This is not necessarily a problem for the use of objcopy during the
    // generate-bitcode phase, but extraction may be performed from installed
    // targets where the current user does not have permissions to create a
    // temporary file adjacent to the installed target.
    //
    // The most obvious solution is to supply /dev/null as the output file: then
    // the input file is not copied to an adjacent location and the objcopy can
    // run as needed.  This works... except for when the input file is an archive
    // (a.k.a static library file, as in libxyz.a).  When the input file is an
    // archive file, then objcopy appears to create a temporary output file for
    // each member of the archive and then re-combine those into the output
    // archive file.  The problem is that the temporary output files are adjacent
    // to the provided output file, thus when /dev/null is provided as the output
    // file, objcopy with an archive input will try to write to /dev/{tempfile},
    // which fails.
    //
    // Thus the more robust solution is to specify the output file in a temporary
    // directory, and there is already a convenient temporary directory created
    // above to hold the output llvm bitcode tar file.
    let mut objcopy_args = Vec::new();
    objcopy_args.push(OsString::from("--dump-section"));
    objcopy_args.push(OsString::from(format!("{}={}", ELF_SECTION_NAME, ok_tar_name)));

    objcopy_args.push(OsString::from(&extract_options.input));

    let mut objres = PathBuf::new();
    objres.push(tmp_path);
    objres.push("discard{output-file}");
    objcopy_args.push(OsString::from(objres));

    match Command::new("objcopy").args(&objcopy_args).spawn() {
        Err(msg) => {
            return Err(anyhow::Error::new(ExtractError::ErrorRunningCommand(String::from("objcopy"), objcopy_args, msg)));
        }
        Ok(mut child) => {
            match child.wait() {
                Err(msg) => {
                    return Err(anyhow::Error::new(ExtractError::ErrorRunningCommand(String::from("objcopy"), Vec::new() /*objcopy_args*/, msg)));
                }
                Ok(sts) => {
                    if !sts.success() {
                        match sts.code() {
                            Some(rc) => { return Ok(rc) }
                            None => { return Ok(-1) }
                        }
                    }
                }
            }
        }
    }

    // The tar file containing all of our bitcode is now in tar_path ("/tmp/{random}/bitcode.tar").
    //
    // We can extract it in that directory.  Note that we need to use tar -i because we
    // concatenated a number of tar files together.
    //
    // NOTE: Ideally, we would be able to use the tar library for this instead
    // of calling out to tar.
    let mut tar_args = Vec::new();
    tar_args.push(OsString::from("xif"));
    tar_args.push(OsString::from(ok_tar_name));
    match Command::new("tar").args(&tar_args).current_dir(tmp_path).spawn() {
        Err(msg) => {
            return Err(anyhow::Error::new(ExtractError::ErrorRunningCommand(String::from("tar"), tar_args, msg)));
        }
        Ok(mut child) => {
            let _rc = child.wait();
        }
    }

    // Now all the files extracted from bitcode.tar into tmp_dir should be linked
    // together to create the final bitcode file.

    let mut llvm_link_args = Vec::new();
    llvm_link_args.push(OsString::from("-o"));
    llvm_link_args.push(OsString::from(&extract_options.output));

    let mut bc_glob = String::new();
    bc_glob.push_str(&OsString::from(tmp_path).into_string().unwrap());
    bc_glob.push_str("/*.bc");
    let bc_files = glob::glob(&bc_glob)?;
    for bc_entry in bc_files {
        let bc_file = bc_entry?;
        llvm_link_args.push(OsString::from(bc_file));
    }

    let llvm_link = OsString::from(extract_options.llvm_link_path.as_ref().unwrap_or(&String::from("llvm-link")));
    match Command::new(&llvm_link).args(&llvm_link_args).spawn() {
        Err(msg) => {
            let llvm_link_str = llvm_link.into_string().unwrap();
            return Err(anyhow::Error::new(ExtractError::ErrorRunningCommand(llvm_link_str, llvm_link_args, msg)));
        }
        Ok(mut child) => {
            let _rc = child.wait();
        }
    }

    Ok(0)
}
