/// This module provides functionality for running one or more sub-process
/// operations.  Each sub-process operation is specified as the command to run,
/// the arguments to the command, and the input and output files.
///
/// The input and output files can be supplied to the command in a number of
/// ways: by replacing a pattern in one or more of the args, or by simply
/// appending the file to the list of arguments (if both input and output files
/// are marked this way, the input file(s) are appended first, followed by the
/// output file.
///
/// There can also be a chain of operations which are performed in sequential
/// order.  The assumption is that each subsequent operation consumes the output
/// of the previous operation (i.e. the out_file of an operation becomes the
/// inp_file of the next operation) and this linkage is automatically setup when
/// executing the chain.  This is especially useful when the input files are
/// specified as NamedFile::Temp files in which case the chain is provided with
/// the original input file that starts the chain and the final output file that
/// the chain should produce and it can automatically generate the intermediary
/// files as temporary files.
///
/// To facilitate the generation of a chain of commands where the individual
/// commands may or may not actually be executed as part of the final chain, each
/// chained command can be enabled or disabled, where the latter effectively
/// erases it from the actually executed chain, but while the chain is built the
/// arguments can still be specified for that operation (allowing the calling
/// code to avoid a series of conditional updates).
///
/// ----------------------------------------------------------------------
/// Alternatives:
///
/// * subprocess crate (https://crates.io/crates/subprocess)
///
///     The subprocess crate allows creation of pipelines connected via
///     stdin/stdout, but not sequences using shared input/output files.
///
///     In addition, chainsop provides automatic creation and management of
///     temporary files used in the above.
///
///     The chainsop package provides more direct support for incrementally
///     building the set of commands with outputs; the subprocess crate would
///     require more discrete management and building of a Vec<Exec>.
///
///     The chainsop allows elements of the chain to be local functions called in
///     the proper sequence of operations and for elements of the chain to be
///     disabled prior to actual execution (where they are skipped).
///
///     The subprocess crate provides more features for handling stdout/stderr
///     redirection, non-blocking and timed sub-process waiting, and interaction
///     with the sub-process.
///
///     Summary: significant overlap in capabilities with slightly different
///     use-case targets and features.
///
/// * duct (https://github.com/oconner663/duct.rs
///
///     Lightweight version of the subprocess crate
///
/// * cargo-make, devrc, rhiz, run-cli, naumann, yamis
///
///    Task runners, requiring an external specification of the commands and no
///    support for chaining inputs/outputs.  These could be written on top of
///    chainsop.
///
/// * steward crate (https://crates.io/crates/steward)
///
///    Useful for running multiple commands and allows dependency management, but
///    not input/output chaining or incremental command building.  Does support
///    other features like environment control and process pools.  Closer to
///    chainsop than the task runners, but again, this could be written on top of
///    chainsop.

use std::cell::{RefCell, RefMut};
use std::env::current_dir;
use std::ffi::{OsString};
use std::fmt;
use std::path::{Path,PathBuf};
use std::process;
use std::rc::Rc;


/// Designates a type of file that can be identified by name on the command line.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum NamedFile {
    /// Create a temporary file; str is suffix to give temporary filename
    Temp(String),

    /// Actual filename (may or may not currently exist)
    Actual(PathBuf),

    // Multiple input files: not yet supported.  It is ostensibly better to
    // represent them here because all input files should share the same FileSpec
    // enum type, but multiple output files isn't really supported for chaining
    // to the next input...
    //
    // Actuals(Vec<PathBuf>),

    /// glob search in specified dir for all matching files
    GlobIn(PathBuf, String),

    /// allowed on initial construction, but an error for execute
    TBD
}

impl NamedFile {
    /// Generates the designation indicating the need for a temporary file with
    /// the specified suffix.  If no particular suffix is needed, a blank suffix
    /// value should be specified.
    pub fn temp<T>(suffix: T) -> NamedFile
    where String: From<T>
    {
        NamedFile::Temp(String::from(suffix))
    }

    /// Generates a reference to an actual file
    pub fn actual<T>(fpath: T) -> NamedFile
    where PathBuf: From<T>
    {
        NamedFile::Actual(PathBuf::from(fpath))
    }

    pub fn glob_in<T,U>(dpath: T, glob: U) -> NamedFile
    where PathBuf: From<T>, String: From<U>
    {
        NamedFile::GlobIn(PathBuf::from(dpath), String::from(glob))
    }
}


/// Determines how a file should be specified for the associated command when
/// issuing the command at execution time.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub enum FileSpec {
    /// No file is expressed or needed
    #[default]
    Unneeded,

    /// Append the named file to the command string
    Append(NamedFile),

    /// first string is the option to emit, which will be followed by the file
    Option(String, NamedFile),

    /// replace the specified text in any argument with the named file.
    Replace(String, NamedFile)

    // ReplaceOrAppend(String, NamedFile),  // first string string is the marker (in args) to be replaced with the file specified as the second string.  If the marker never appears, fallback to Append behavior.

}

impl FileSpec {

    // Internal function to resolve a FileSpec and insert the actual named file
    // into the argument list.  This also returns the file; the file may be a
    // temporary file object which will delete the file at the end of its
    // lifetime, so the returned value should be held until the file is no longer
    // needed.
    fn setup_file<E>(&self, args: &mut Vec<OsString>, on_missing: E)
                     -> anyhow::Result<SubProcFile>
    where E: Fn() -> anyhow::Result<SubProcFile>
    {
        match &self {
            FileSpec::Unneeded => (),
            FileSpec::Append(nf) =>
                match nf {
                    NamedFile::TBD => return on_missing(),
                    NamedFile::Temp(sfx) => {
                        let tf = tempfile::Builder::new().suffix(sfx).tempfile()?;
                        args.push(OsString::from(tf.path()));
                        return Ok(SubProcFile::TempOutputFile(tf))
                    }
                    NamedFile::Actual(fpath) => {
                        args.push(fpath.into());
                        return Ok(SubProcFile::StaticOutputFile(fpath.clone()));
                    }
                    NamedFile::GlobIn(dpath, glob) => {
                        let mut bc_glob = String::new();
                        bc_glob.push_str(&OsString::from(dpath).into_string().unwrap());
                        bc_glob.push_str("/");
                        bc_glob.push_str(glob);
                        let bc_files = glob::glob(&bc_glob)?;
                        for bc_entry in bc_files {
                            let bc_file = bc_entry?;
                            args.push(OsString::from(bc_file));
                        }
                    }
                }
            FileSpec::Option(optflag, nf) =>
                match nf {
                    NamedFile::TBD => return on_missing(),
                    NamedFile::Temp(sfx) => {
                        let tf = tempfile::Builder::new().suffix(sfx).tempfile()?;
                        args.push(OsString::from(optflag));
                        args.push(OsString::from(tf.path()));
                        return Ok(SubProcFile::TempOutputFile(tf))
                    }
                    NamedFile::Actual(fpath) => {
                        args.push(OsString::from(optflag));
                        args.push(fpath.into());
                        return Ok(SubProcFile::StaticOutputFile(fpath.clone()));
                    }
                    NamedFile::GlobIn(dpath, glob) => {
                        let mut bc_glob = String::new();
                        bc_glob.push_str(&OsString::from(dpath).into_string().unwrap());
                        bc_glob.push_str("/");
                        bc_glob.push_str(glob);
                        let bc_files : Vec<PathBuf> = glob::glob(&bc_glob)?
                            .filter_map(Result::ok)
                            .collect();
                        let bc_files_str = bc_files.iter()
                            .map(|x| OsString::from(x).into_string().unwrap())
                            .collect::<Vec<String>>() ;
                        args.push(OsString::from(optflag));
                        args.push(OsString::from(bc_files_str.join(",")));
                        return Ok(SubProcFile::StaticOutputFiles(bc_files));
                    }
                }
            FileSpec::Replace(needle, nf) =>
                match nf {
                    NamedFile::TBD => return on_missing(),
                    NamedFile::Temp(sfx) => {
                        let tf = tempfile::Builder::new().suffix(sfx).tempfile()?;
                        let tfs = OsString::from(tf.path());
                        *args =
                            args.into_iter()
                            .map(|arg| replace(needle, &tfs, arg))
                            .collect();
                        return Ok(SubProcFile::TempOutputFile(tf))
                    }
                    NamedFile::Actual(fpath) => {
                        *args =
                            args.into_iter()
                            .map(|arg| replace(needle, &fpath.into(), arg))
                            .collect();
                        return Ok(SubProcFile::StaticOutputFile(fpath.clone()));
                    }
                    NamedFile::GlobIn(dpath, glob) => {
                        let mut bc_glob = String::new();
                        bc_glob.push_str(&OsString::from(dpath).into_string().unwrap());
                        bc_glob.push_str("/");
                        bc_glob.push_str(glob);
                        let bc_files = glob::glob(&bc_glob)?
                            .filter_map(Result::ok)
                            .map(|x| OsString::from(x).into_string().unwrap())
                            .collect::<Vec<String>>()
                            .join(",")
                            ;
                        args.push(OsString::from(bc_files))
                    }
                }
        }
        Ok(SubProcFile::NoOutputFile)
    }

    // Alternative to the setup_file function which instead uses the specified
    // file instead of the existing specification, modifying the args in the
    // appropriate manner to insert the file reference.
    fn setup_file_override(&self,
                           ovrf: &PathBuf,
                           mut args: Vec<OsString>)
                           -> Vec<OsString>
    {
        match &self {
            FileSpec::Unneeded => args,
            FileSpec::Append(_) => { args.push(ovrf.into()); args },
            FileSpec::Option(flg, _) => {
                args.push(OsString::from(flg));
                args.push(ovrf.into());
                args
            },
            FileSpec::Replace(pat, _) =>
                args.into_iter()
                .map(|arg| replace(pat, &ovrf.into(), &arg))
                .collect()
        }
    }
}


// ----------------------------------------------------------------------
// Single sub-process operation management

/// This structure represents a single command to run as a sub-process, the
/// command's arguments, and the input and output files for that sub-process.
/// The structure itself is public but the fields are private
/// (i.e. implementation specific); the impl section below defines the visible
/// operations that can be performed on this structure.
#[derive(Debug)]
pub struct SubProcOperation {
    cmd : Operation,
    args : Vec<OsString>,
    inp_file : FileSpec,
    out_file : FileSpec,
    in_dir : Option<PathBuf>,
}

enum Operation {
    /// Name of executable to invoke in subprocess
    Execute(OsString),

    /// Local function to call instead of executing a subprocess.  The first
    /// argument is the current working directory, the second is the argument
    /// vector (the input and output files will be part of the argument vector as
    /// determined by their corresponding FileSpec).
    Call(Box<dyn Fn(&Path, Vec<OsString>) -> anyhow::Result<()>>)
    // n.b. Would prefer this to be an FnOnce, but that breaks move semantics
    // when trying to call it while it's a part of an enclosing Enum.
}

impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result
    {
        match self {
            Operation::Execute(cmd) => cmd.fmt(f),
            Operation::Call(_) => "Local function call".fmt(f)
        }
    }
}
impl From<&Operation> for String {
    fn from(op: &Operation) -> Self {
        match op {
            Operation::Execute(cmd) =>
                cmd.clone().into_string().unwrap_or(String::from("<command>")),
            Operation::Call(_) => String::from("local-function")
        }
    }
}

#[derive(Debug)]
pub enum SubProcFile {
    NoOutputFile,
    StaticOutputFile(PathBuf),
    StaticOutputFiles(Vec<PathBuf>),
    TempOutputFile(tempfile::NamedTempFile),
}

#[derive(thiserror::Error,Debug)]
pub enum SubProcError {

    #[error("Sub-process {1:} file not specified for command {0:?}")]
    ErrorMissingFile(String, String),

    #[error("Error {2:?} running command {0:?} {1:?} in dir {3:?}\n{4:}")]
    ErrorRunningCmd(String, Vec<OsString>, Option<i32>, PathBuf, String),

    #[error("Error {2:?} setting up running command {0:?} {1:?} in dir {3:?}")]
    ErrorCmdSetup(String, Vec<OsString>, std::io::Error, PathBuf)
}

impl SubProcOperation {

    /// Creates a new SubProcOperation that will be capable of executing the
    /// specified command with the corresponding input and output files.
    pub fn new<'a, T>(cmd : &'a T,
                      inp_file : &FileSpec,
                      out_file : &FileSpec)
                      -> SubProcOperation
    where OsString: From<&'a T>
    {
        SubProcOperation {
            cmd : Operation::Execute(OsString::from(cmd)),
            args : Vec::new(),
            inp_file : inp_file.clone(),
            out_file : out_file.clone(),
            in_dir : None,
        }
    }

    /// Creates a new SubProcOperation that will call a local function instead of
    /// executing a command in a sub-process.  This is useful for interleaving
    /// local processing into the command chain where that local processing is
    /// executed in proper sequence with the other commands.  The local function
    /// is provided with the "argument list" that would have been passed on the
    /// command-line; this argument list will contain any input or output
    /// filenames that should be used by the function.
    ///
    /// A local function execution in the chain can only pass an output file to
    /// the subsequent operation in the chain; more complex data exchange would
    /// need to be serialized into that output file and appropriately consumed by
    /// the next stage. This might initially seem awkward, but makes sense when
    /// you consider that most operations are executions in subprocesses that are
    /// in a separate address space already.
    pub fn calling<T>(f: T) -> SubProcOperation
    where T: Fn(&Path, Vec<OsString>) -> anyhow::Result<()> + 'static
    {
        SubProcOperation {
            cmd : Operation::Call(Box::new(f)),
            args : Vec::new(),
            inp_file : Default::default(),
            out_file : Default::default(),
            in_dir : None,
        }
    }

    /// Adds a command-line argument to use when executing the command.
    #[inline]
    pub fn push_arg<T>(&mut self, arg: T) -> &SubProcOperation
    where OsString: From<T>
    {
        self.args.push(OsString::from(arg));
        self
    }

    /// Sets the input file for the command, overriding any previous input file
    /// specification.
    #[inline]
    pub fn set_input_file(&mut self, inp_file: &FileSpec) -> &SubProcOperation
    {
        self.inp_file = inp_file.clone();
        self
    }

    /// Sets the output file for the command, overriding any previous output file
    /// specification.
    #[inline]
    pub fn set_output_file(&mut self, out_file: &FileSpec) -> &SubProcOperation
    {
        self.out_file = out_file.clone();
        self
    }

    /// Sets the directory from which the operation will be executed.  The caller
    /// is responsible for ensuring any Actual FileSpec paths are valid when
    /// operating from that directory and any Temp FileSpec files created will
    /// still be created in the normal temporary directory location.
    #[inline]
    pub fn set_dir<T>(&mut self, in_dir: T) -> &SubProcOperation
    where T: AsRef<Path>
    {
        self.in_dir = Some(in_dir.as_ref().to_path_buf());
        self
    }

    /// Executes this command in a subprocess in the specified directory.  The
    /// input and output files will be determined and added to the command-line
    /// as indicated by their FileSpec values.  The successful result specifies
    /// the output file written (if any).
    pub fn execute(&self, cwd: &Path) -> anyhow::Result<SubProcFile>
    {
        let mut args = self.args.clone();
        let outfile;
        if self.emit_output_file_first() {
            outfile = self.out_file.setup_file(
                &mut args,
                || Err(anyhow::Error::new(
                    SubProcError::ErrorMissingFile(String::from(&self.cmd),
                                                   String::from("output")))))?;
            self.inp_file.setup_file(
                &mut args,
                || Err(anyhow::Error::new(
                    SubProcError::ErrorMissingFile(String::from(&self.cmd),
                                                   String::from("input")))))?;
        } else {
            self.inp_file.setup_file(
                &mut args,
                || Err(anyhow::Error::new(
                    SubProcError::ErrorMissingFile(String::from(&self.cmd),
                                                   String::from("input")))))?;
            outfile = self.out_file.setup_file(
                &mut args,
                || Err(anyhow::Error::new(
                    SubProcError::ErrorMissingFile(String::from(&self.cmd),
                                                   String::from("output")))))?;
        }
        self.run_cmd(cwd, outfile, args)
    }
    // Output option arguments before positional arguments because some command's
    // parsers are limited in this way.  This function returns true if the output
    // file should be specified before the input file; the normal order is input
    // file and then output file (e.g. "cp inpfile outfile").
    fn emit_output_file_first(&self) -> bool
    {
        if let FileSpec::Option(_, _) = self.out_file {
            if let FileSpec::Append(_) = self.inp_file {
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    // After the files are setup, this performs the actual run
    fn run_cmd(&self, cwd: &Path, outfile : SubProcFile, args : Vec<OsString>)
               -> anyhow::Result<SubProcFile>
    {
        match &self.cmd {
            Operation::Execute(cmd) => {
                match process::Command::new(&cmd)
                .args(&args)
                .current_dir(self.in_dir.as_ref().unwrap_or(&cwd.to_path_buf()))
                .stdout(process::Stdio::piped())
                .stderr(process::Stdio::piped())
                .spawn()
            {
                Ok(child) => {
                    let out = child.wait_with_output()?;
                    if !out.status.success() {
                        return Err(anyhow::Error::new(
                            SubProcError::ErrorRunningCmd(
                                String::from(&self.cmd), args,
                                out.status.code(),
                                cwd.to_path_buf(),
                                String::from_utf8_lossy(&out.stderr).into_owned())))
                    }
                }
                Err(e) => {
                    return Err(anyhow::Error::new(
                        SubProcError::ErrorCmdSetup(String::from(&self.cmd),
                                                    args, e,
                                                    cwd.to_path_buf())))
                }
            }
            }
            Operation::Call(func) => {
                func(cwd, args)?
            }
        }
        Ok(outfile)
    }

    /// Executes this command in a subprocess in the specified directory,
    /// overriding the input.  There might be multiple input files (e.g. with
    /// GlobIn): the FileSpec application is repeated for each input file.  If
    /// there are no input files, then this behaves just as the normal execute
    /// function.
    pub fn execute_with_inp_override(&self,
                                     cwd: &Path,
                                     inps: &Vec<PathBuf>)
                                     -> anyhow::Result<SubProcFile> {
        if inps.len() == 0 {
            return self.execute(cwd);
        }

        let mut args = self.args.clone();
        let mut outfile = SubProcFile::NoOutputFile;
        if self.emit_output_file_first() {
            outfile = self.out_file.setup_file(
                &mut args,
                || Err(anyhow::Error::new(
                    SubProcError::ErrorMissingFile(String::from(&self.cmd),
                                                   String::from("output")))))?;
        }
        for inpf in inps {
            args = self.inp_file.setup_file_override(inpf, args);
        }
        if !self.emit_output_file_first() {
            outfile = self.out_file.setup_file(
                &mut args,
                || Err(anyhow::Error::new(
                    SubProcError::ErrorMissingFile(String::from(&self.cmd),
                                                   String::from("output")))))?;
        }
        self.run_cmd(cwd, outfile, args)
    }

    // Executes this command in a subprocess in the specified directory,
    // overriding the input *and* the output files.  If the output override is
    // None this acts the same as execute_with_inp_override.
    pub fn execute_with_file_overrides(&self,
                                       cwd: &Path,
                                       inps: &Vec<PathBuf>,
                                       out: &Option<PathBuf>)
                                       -> anyhow::Result<SubProcFile> {
        match &out {
            None => self.execute_with_inp_override(cwd, inps),
            Some (outf) => {
                let mut args = self.args.clone();
                let outfile = SubProcFile::StaticOutputFile(outf.clone());
                if self.emit_output_file_first() {
                    args = self.out_file.setup_file_override(outf, args);
                }
                if inps.len() == 0 {
                    self.inp_file.setup_file(
                        &mut args,
                        || Err(anyhow::Error::new(
                            SubProcError::ErrorMissingFile(String::from(&self.cmd),
                                                           String::from("input")))))?;
                } else {
                    for inpf in inps {
                        args = self.inp_file.setup_file_override(inpf, args);
                    }
                }
                if !self.emit_output_file_first() {
                    args = self.out_file.setup_file_override(outf, args);
                }
                self.run_cmd(cwd, outfile, args)
            }
        }
    }
}

fn replace(pat : &String, subs : &OsString, inpstr : &OsString) -> OsString
{
    match subs.clone().into_string() {
        Ok(sub) => match inpstr.clone().into_string() {
            Ok(inps) => OsString::from(inps.replace(pat, &sub)),
            Err(orig) => orig
        }
        Err(_) => inpstr.clone()

    }
}

// ----------------------------------------------------------------------
/// Chained sub-process operations
///
/// General notes about structure organization:
///
///   The ChainedSubProcOperations is the core structure that contains the list
///   of operations that should be chained together, along with the initial input
///   file and final output file.
///
///   When adding an operation to ChainedSubProcOperations (via .push_op()) the
///   return value should allow subsequent examination/manipulation of that
///   specific operation in the chain (the ChainedOpRef struct).  To do so, and
///   honor Rust's ownership rules, this means that the result references the
///   core ChainedSubProcOperations via a reference counted (Rc) cell (RefCell)
///   to maintain a single copy via the Rc but allow updates of that object via
///   the RefCell.
///
///   To hide the complexity of the Rc<RefCell<ChainedSubProcOperations>> from
///   the user, this value is wrapped in the ChainedSubOps struct.
///
///   User API operations are therefore primarily defined for the ChainedSubOps
///   and ChainedOpRef structs.
///
///   The typical API usage:
///
///    let all_ops = ChainedSubOps::new()
///    let op1 = all_ops.push_op(
///               SubProcOperation::new("command",
///                                     <how to specify input file to command>,
///                                     <how to specify output file to command>))
///    let op2 = all_ops.push_op(
///               SubProcOperation::new("next-command",
///                                     <how to specify input file>,
///                                     <how to specify output file>))
///    ...
///    op1.push_arg("-x")
///    op2.push_arg("-f")
///    op2.push_arg(filename)
///    op2.disable()
///    ...
///    all_ops.set_input_file_for_chain(input_filename)
///    all_ops.set_output_file_for_chain(output_filename)
///    match all_ops.execute() {
///      Err(e) => ...,
///      Ok(sts) -> ...,
///    }

/// Internal structure managing the chain of operations
#[derive(Debug)]
struct ChainedSubProcOperations {
    chain : Vec<SubProcOperation>,
    initial_inp_file : Option<PathBuf>,
    final_out_file : Option<PathBuf>,
    disabled : Vec<usize>
}

#[derive(Clone,Debug)]
pub struct ChainedOpRef {
    opidx : usize,
    chop : Rc<RefCell<ChainedSubProcOperations>>
}


pub struct ChainedSubOps {
    chops : Rc<RefCell<ChainedSubProcOperations>>
}

impl fmt::Debug for ChainedSubOps {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.chops.borrow(), f)
    }
}

impl ChainedSubOps {
    // The result is Rc'd so that the ChainedOpRef instances can have a
    // reference to the target as well.
    pub fn new() -> ChainedSubOps
    {
        ChainedSubOps {
            chops :
            Rc::new(
                RefCell::new(
                    ChainedSubProcOperations { chain : Vec::new(),
                                               initial_inp_file : None,
                                               final_out_file : None,
                                               disabled : Vec::new()
                    }
                )
            )
        }
    }
}


impl ChainedSubOps
{
    /// Adds a new operation to the end of the chain.  Returns a reference for
    /// modifying that operation.
    pub fn push_op(self: &ChainedSubOps, op: SubProcOperation) -> ChainedOpRef
    {
        {
            let mut ops: RefMut<_> = self.chops.borrow_mut();
            ops.chain.push(op);
        }
        ChainedOpRef { opidx : self.chops.borrow().chain.len() - 1,
                       chop : Rc::clone(&self.chops)
        }
    }

    /// Retrieves the name of input file providing the original input to the
    /// entire chain.
    #[inline]
    pub fn inp_file_for_chain(&self, inp_file: &Option<PathBuf>) -> ()
    {
        let mut ops: RefMut<_> = self.chops.borrow_mut();
        ops.initial_inp_file = inp_file.clone();
    }

    /// Sets the output file for the entire chain (i.e. the end file)
    #[inline]
    pub fn set_out_file_for_chain(&self, out_file: &Option<PathBuf>) -> ()
    {
        let mut ops: RefMut<_> = self.chops.borrow_mut();
        ops.final_out_file = out_file.clone();
    }

    /// Gets the output file path for the end of the chain.  Returns None if the
    /// output file is not specified or is indefinite/temporary and therefore
    /// cannot be accessed.
    #[inline]
    pub fn out_file_for_chain(&self) -> Option<PathBuf>
    {
        self.chops.borrow().final_out_file.clone()
    }

    /// Executes all the enabled operations in this chain sequentially, updating
    /// the input file of each operation to be the output file from the previous
    /// operation.  On success, returns the number of operations executed.
    pub fn execute<T>(&self, cwd: &Option<T>) -> anyhow::Result<usize>
    where PathBuf: From<T>, T: Clone
    {
        let curdir = match &cwd {
            Some(p) => PathBuf::from(p.clone()),
            None => current_dir()?
        };
        let chops = self.chops.borrow();
        // n.b. cannot Clone the chain (thus, cannot alter it), so instead build
        // a vec of the valid indices.  Build it in reverse so the operations can
        // simply .pop() the next index off the end.
        let mut enabled_opidxs : Vec<usize> = chops.chain.iter()
            .enumerate()
            .filter(|(i,_op)| ! chops.disabled.contains(i))
            .map(|(i,_op)| i)
            .rev()
            .collect();
        execute_chain(&chops.chain, curdir.as_path(), &mut enabled_opidxs,
                      &match &chops.initial_inp_file {
                          Some(f) => vec![f.clone()],
                          None => vec![]
                      },
                      &chops.final_out_file)
            .map(|r| r + 1)
    }
}

fn execute_chain(chops: &Vec<SubProcOperation>,
                 cwd: &Path,
                 mut op_idxs: &mut Vec<usize>,
                 inp_files : &Vec<PathBuf>,  // usually just one, except GlobIn
                 out_file : &Option<PathBuf>)
                 -> anyhow::Result<usize>
{
    let op_idx = op_idxs.pop().unwrap();
    let spo = &chops[op_idx];
    let last_op = op_idxs.is_empty();
    if last_op {
        spo.execute_with_file_overrides(cwd, inp_files, out_file)?;
        return Ok(1);
    }

    let outfile = spo.execute_with_inp_override(cwd, inp_files)?;
    let nxt_inpfile = match &outfile {
        SubProcFile::NoOutputFile => vec![],
        SubProcFile::StaticOutputFile(f) => vec![f.clone()],
        SubProcFile::TempOutputFile(tf) => vec![tf.path().to_path_buf()],
        SubProcFile::StaticOutputFiles(fs) => fs.clone(),
    };
    let nxt = execute_chain(chops, cwd, &mut op_idxs, &nxt_inpfile, &out_file)?;
    Ok(nxt + 1)
}

impl ChainedOpRef {
    /// Add an argument to this operation in the chain
    #[inline]
    pub fn push_arg<T>(&self, arg: T) -> &ChainedOpRef
    where OsString: From<T>
    {
        {
            let mut ops: RefMut<_> = self.chop.borrow_mut();
            ops.chain[self.opidx].args.push(OsString::from(arg));
        }
        self
    }

    /// Sets the default directory for execution of this operation
    pub fn set_dir<T>(&self, tgtdir: T) -> &ChainedOpRef
    where T: AsRef<Path>
    {
        {
            let mut ops: RefMut<_> = self.chop.borrow_mut();
            ops.chain[self.opidx].set_dir(tgtdir);
        }
        self
    }

    /// Enables this operation in the chain.  By default, an operation added to
    /// the chain is automatically enabled, but it can be explicitly disabled or
    /// enabled prior to execution.  See disable() for more information.
    #[inline]
    pub fn enable(&self) -> &ChainedOpRef
    {
        {
            let mut ops: RefMut<_> = self.chop.borrow_mut();
            ops.disabled.retain(|&x| x != self.opidx);
        }
        self
    }

    /// Disables this operation in the chain.  By default, an operation added to
    /// the chain is automatically enabled, but it can be explicitly disabled or
    /// enabled prior to execution.
    /// This is useful for building a chain
    /// consisting of all possible operations and then "removing" those that are
    /// subsequently determined not to be needed by disabling them.
    #[inline]
    pub fn disable(&self) -> &ChainedOpRef
    {
        {
            let mut ops: RefMut<_> = self.chop.borrow_mut();
            ops.disabled.push(self.opidx);
        }
        self
    }

    /// Sets the input file specification for this operation, overriding any
    /// previous specification.
    pub fn set_input(&self, inp_spec : &FileSpec) -> &ChainedOpRef
    {
        {
            let mut ops: RefMut<_> = self.chop.borrow_mut();
            ops.chain[self.opidx].set_input_file(inp_spec);
        }
        self
    }

    /// Sets the output file specification for this operation, overriding any
    /// previous specification.
    pub fn set_output(&self, inp_spec : &FileSpec) -> &ChainedOpRef
    {
        {
            let mut ops: RefMut<_> = self.chop.borrow_mut();
            ops.chain[self.opidx].set_output_file(inp_spec);
        }
        self
    }
}
