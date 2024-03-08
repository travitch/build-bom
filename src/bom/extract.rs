use log::{info};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use chainsop::{ChainedOps, Executable, ExeFileSpec, OpInterface,
               FileArg, FilesPrep};

use crate::bom::options::{ExtractOptions, get_executor};
use crate::bom::bitcode::ELF_SECTION_NAME;
use crate::bom::executables::{run, TAR_EXTRACT, LLVM_LINK};

#[derive(thiserror::Error,Debug)]
pub enum ExtractError {
    #[error("Temp directory lost during extraction")]
    ErrorLostTmpDir,
}

pub fn extract_bitcode_entrypoint(extract_options : &ExtractOptions) -> anyhow::Result<i32> {
    let tmp_dir = tempfile::TempDir::new()?;
    let res = do_bitcode_extraction(extract_options, tmp_dir.path());

    // The following ensures that tmp_dir still has ownership of the associated
    // resources and that they weren't inadvertently dropped during bitcode
    // extraction.  This uses Rust's ownership to help avoid the "Early drop
    // pitfall" described at https://docs.rs/tempfile/latest/tempfile.
    std::mem::drop(tmp_dir);

    res
}

pub fn do_bitcode_extraction(extract_options : &ExtractOptions,
                             tmp_path : &Path) -> anyhow::Result<i32> {
    info!("#=> Extracting bitcode from {:?}", extract_options.input);

    let mut tar_path = PathBuf::new();
    tar_path.push(tmp_path);
    tar_path.push("bitcode.tar");
    let ok_tar_name = OsString::from(tar_path.clone()).into_string().unwrap();

    let mut extract_ops = ChainedOps::new("bitcode extraction ops");
    extract_ops.set_input_file(&FileArg::loc(extract_options.input.clone()));
    extract_ops.set_output_file(&FileArg::loc(extract_options.output.clone()));

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
    let mut dummy_output = PathBuf::from(tmp_path);
    dummy_output.push("discard{output-file}");  // arbitrary name

    extract_ops.push_op(
        &run(&Executable::new("objcopy", ExeFileSpec::Append, ExeFileSpec::Append),
             &extract_options.objcopy_path)
            .set_label("objcopy:extract-bitcode")
            .push_arg("--dump-section")
            .push_arg(format!("{}={}", ELF_SECTION_NAME, ok_tar_name))
            .set_output_file(&FileArg::loc(dummy_output)));

    // The tar file containing all of our bitcode is now in tar_path ("/tmp/{random}/bitcode.tar").
    //
    // We can extract it in that directory.  Note that we need to use tar -i because we
    // concatenated a number of tar files together.
    //
    // NOTE: Ideally, we would be able to use the tar library for this instead
    // of calling out to tar.

    extract_ops.push_op(&run(&TAR_EXTRACT, &None)
                        .set_label("tar:unpack")
                        .set_dir(tmp_path)  // Extracted files will be placed here
                        // Input here is explicitly the section dump target file
                        // rather than the output of the previous op.
                        .set_input_file(&FileArg::loc(tar_path)));

    // Now all the files extracted from bitcode.tar into tmp_dir should be linked
    // together to create the final bitcode file.

    let mut link_bc_files = extract_ops.push_op(
        &run(&*LLVM_LINK, &extract_options.llvm_link_path));

    link_bc_files.set_input_file(&FileArg::glob_in(tmp_path, "*.bc"));

    let executor = get_executor(extract_options.verbose);
    extract_ops.execute_here(&executor).map(|_| 0)
}
