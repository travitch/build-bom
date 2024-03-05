use chainsop::{Executable, ExeFileSpec, SubProcOperation};
use std::path::PathBuf;

lazy_static::lazy_static! {

    pub static ref CLANG_LLVM : Executable =
        Executable::new("clang",
                        ExeFileSpec::Append,
                        ExeFileSpec::option("-o"))
        .push_arg("-emit-llvm")
        .push_arg("-c");

    pub static ref TAR_EXTRACT : Executable =
        Executable::new("tar",
                        ExeFileSpec::option("-f"),
                        ExeFileSpec::NoFileUsed)
        .push_arg("xi");

    pub static ref LLVM_LINK : Executable =
        Executable::new("llvm-link",
                        ExeFileSpec::Append,
                        ExeFileSpec::option("-o"));

}


/// Returns a [chainsop::SubProcOperation] for the specified executable, with a
/// possible override for the name of the executable.
pub fn run(exe: &Executable, userspec: &Option<PathBuf>) -> SubProcOperation {
    let e = match userspec {
        Some(p) => exe.set_exe(p),
        None => exe.clone(),
    };
    SubProcOperation::new(&e)
}
