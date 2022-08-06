use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use crate::bom::options::ExtractOptions;
use crate::bom::bitcode::ELF_SECTION_NAME;

#[derive(thiserror::Error,Debug)]
pub enum ExtractError {
    #[error("Error running command {0:} {1:?} ({2:?})")]
    ErrorRunningCommand(String,Vec<OsString>,std::io::Error)
}

pub fn extract_bitcode_entrypoint(extract_options : &ExtractOptions) -> anyhow::Result<i32> {
    let tmp_dir = tempfile::TempDir::new()?;
    let mut tar_path = PathBuf::new();
    tar_path.push(tmp_dir.path());
    tar_path.push("bitcode.tar");

    // Use objcopy to extract our tar file from the target.
    //
    // Note that objcopy wants to create an output file and if not given an
    // output file it will try to copy the input file to an adjacent temp file
    // and thus require write permissions to the directory and input file.
    //
    // For the generate-bitcode phase, this is not a problem (and is a desired
    // feature since that phase adds the bitcode to the original object file),
    // but the extraction phase may be run at a later time, and possibly on
    // installed files (for which the user has no write permissions).
    //
    // There is no need for a modified object file in the extraction phase, but
    // objcopy will insist on generating one, so giving it an output target in
    // the same temp directory where the extracted bitcode tar file will be
    // written avoids the permissions issues.
    let mut objcopy_args = Vec::new();
    objcopy_args.push(OsString::from("--dump-section"));
    let ok_tar_name = OsString::from(tar_path).into_string().unwrap();
    objcopy_args.push(OsString::from(format!("{}={}", ELF_SECTION_NAME, ok_tar_name)));
    objcopy_args.push(OsString::from(&extract_options.input));
    // The objres is the obligatory but unneeded rewritten object file target.
    // Since this isn't needed, simply use /dev/null (currently only targeting
    // Unix support).
    let mut objres = PathBuf::new();
    objres.push("/dev/null");
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

    // The tar file containing all of our bitcode is now in /tmp/{random}/bitcode.tar
    //
    // We can extract it in that directory.  Note that we need to use tar -i because we
    // concatenated a number of tar files together.
    //
    // NOTE: Ideally, we would be able to use the tar library for this instead
    // of calling out to tar.
    let mut tar_args = Vec::new();
    tar_args.push(OsString::from("xif"));
    tar_args.push(OsString::from(ok_tar_name));
    match Command::new("tar").args(&tar_args).current_dir(&tmp_dir).spawn() {
        Err(msg) => {
            return Err(anyhow::Error::new(ExtractError::ErrorRunningCommand(String::from("tar"), tar_args, msg)));
        }
        Ok(mut child) => {
            let _rc = child.wait();
        }
    }

    // Now all the files contained in the extracted bitcode.tar should be linked together
    // to create the final bitcode file.

    let mut llvm_link_args = Vec::new();
    llvm_link_args.push(OsString::from("-o"));
    llvm_link_args.push(OsString::from(&extract_options.output));

    let mut bc_glob = String::new();
    bc_glob.push_str(&OsString::from(tmp_dir.path()).into_string().unwrap());
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
