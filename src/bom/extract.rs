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

pub fn extract_bitcode_entrypoint(extract_options : &ExtractOptions) -> anyhow::Result<()> {
    let tmp_dir = tempfile::TempDir::new()?;
    let mut tar_path = PathBuf::new();
    tar_path.push(tmp_dir.path());
    tar_path.push("bitcode.tar");

    // Use objcopy to extract our tar file from the target
    let mut objcopy_args = Vec::new();
    objcopy_args.push(OsString::from("--dump-section"));
    let ok_tar_name = OsString::from(tar_path).into_string().unwrap();
    objcopy_args.push(OsString::from(format!("{}={}", ELF_SECTION_NAME, ok_tar_name)));
    objcopy_args.push(OsString::from(&extract_options.input));
    match Command::new("objcopy").args(&objcopy_args).spawn() {
        Err(msg) => {
            return Err(anyhow::Error::new(ExtractError::ErrorRunningCommand(String::from("objcopy"), objcopy_args, msg)));
        }
        Ok(mut child) => {
            let _rc = child.wait();
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

    let mut llvm_link = OsString::from("llvm-link");
    match &extract_options.llvm_tool_suffix {
        None => {}
        Some(suffix) => {
            llvm_link.push(OsString::from(suffix));
        }
    }
    match Command::new(&llvm_link).args(&llvm_link_args).current_dir(&tmp_dir).spawn() {
        Err(msg) => {
            let llvm_link_str = llvm_link.into_string().unwrap();
            return Err(anyhow::Error::new(ExtractError::ErrorRunningCommand(llvm_link_str, llvm_link_args, msg)));
        }
        Ok(mut child) => {
            let _rc = child.wait();
        }
    }

    Ok(())
}
