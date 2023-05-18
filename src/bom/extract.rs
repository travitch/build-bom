use std::ffi::OsString;
use std::path::PathBuf;

use crate::bom::options::ExtractOptions;
use crate::bom::bitcode::ELF_SECTION_NAME;
use crate::bom::chainsop::{ChainedSubOps, FileSpec, NamedFile, SubProcOperation};

pub fn extract_bitcode_entrypoint(extract_options : &ExtractOptions) -> anyhow::Result<i32> {
    let tmp_dir = tempfile::TempDir::new()?;

    // Create a sub-context to ensure the tmp_dir remains during the entirety of
    // the enclosed operations...
    {
        // Name of the tar file we will extract from the input file's ELF
        // section.
        let mut tar_path = PathBuf::new();
        tar_path.push(tmp_dir.path());
        tar_path.push("bitcode.tar");

        let extract_ops = ChainedSubOps::new();
        extract_ops.set_out_file_for_chain(&Some(extract_options.output.clone()));

        // Use objcopy to extract our tar file from the target.  Note that
        // objcopy expects to write an output object.  If not given an output
        // file, it will try to replace the input file with the generated version
        // by copying the input file to a temporary file (adjacent to the input
        // file) and then reading that temporary file to rewriting the input file
        // with the output data.
        //
        // This is not necessarily a problem for the use of objcopy during the
        // generate-bitcode phase, but extraction may be performed from installed
        // targets where the current user does not have permissions to create a
        // temporary file adjacent to the installed target.
        //
        // The most obvious solution is to supply /dev/null as the output file:
        // then the input file is not copied to an adjacent location and the
        // objcopy can run as needed.  This works... except for when the input
        // file is an archive (a.k.a static library file, as in libxyz.a).  When
        // the input file is an archive file, then objcopy appears to create a
        // temporary output file for each member of the archive and then
        // re-combine those into the output archive file.  The problem is that
        // the temporary output files are adjacent to the provided output file,
        // thus when /dev/null is provided as the output file, objcopy with an
        // archive input will try to write to /dev/{tempfile}, which fails.
        //
        // Thus the more robust solution is to specify the (ignored) output file
        // in the standard temporary directory so that objcopy-created files next
        // to it are in a valid temporary location.
        let objcopy = extract_ops.push_op(
            SubProcOperation::new(
                &"objcopy",
                &FileSpec::Append(NamedFile::actual(&extract_options.input)),
                &FileSpec::Append(NamedFile::temp(".o"))));
        objcopy.push_arg("--dump-section");

        let ok_tar_name = OsString::from(&tar_path).into_string().unwrap();
        objcopy.push_arg(format!("{}={}", ELF_SECTION_NAME, ok_tar_name));

        // The tar file containing all of our bitcode is now in
        // /tmp/{random}/bitcode.tar
        //
        // We can extract it in that directory.  Note that we need to use tar -i
        // because we concatenated a number of tar files together.
        //
        // NOTE: Ideally, we would be able to use the tar library for this
        // instead of calling out to tar.
        let tar = extract_ops.push_op(
            SubProcOperation::new(
                &"tar",
                // if an output file was specified, the chained ops would
                // override this with the output file of the objcopy operation;
                // in this case, we are not using the actual objcopy output file
                // but instead the tarfile create as a side-effect via the
                // --dump-section, so declare no input file and explicitly add
                // the tarfile via a push_arg below
                &FileSpec::Unneeded,
                &FileSpec::Unneeded));  // tar has no output file spec.
        tar.push_arg("xif");
        tar.push_arg(&tar_path);
        tar.set_dir(&tmp_dir);

        // Now all the files contained in the extracted bitcode.tar should be
        // linked together to create the final bitcode file.

        extract_ops.push_op(
            SubProcOperation::new(
                &"llvm-link",
                &FileSpec::Append(NamedFile::glob_in(tmp_dir.path(), "*.bc")),
                &FileSpec::Option(String::from("-o"), NamedFile::TBD)));

        let mut bc_glob = String::new();
        bc_glob.push_str(&OsString::from(tmp_dir.path()).into_string().unwrap());
        bc_glob.push_str("/*.bc");

        extract_ops.execute::<String>(&None)?;
        Ok(0)
    }
}
