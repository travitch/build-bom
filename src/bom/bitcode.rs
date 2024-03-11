// Overall Design
// ==============
//
// The generate-bitcode command will execute the specified build
// command (e.g. make) within a process tracing mechanism (provided by
// the "pete" package).  Each trace event is examined to see if it is
// of interest relative to the generation of a bitcode file:
//
// Event:
//
// * SyscallEnter -- if this is an execve syscall, the execve target
//                   may be a clang invocation on a source code file.
//                   At syscall entry, the cmdline arguments are
//                   captured for that determination later.
//
// * SyscallExit -- if this is the exit from an execve syscall and it
//                  failed, the preserved arguments from above can be
//                  discarded.  Note that even if this is an execve,
//                  the syscall has returned to the *original*
//                  executable (albeit to libc library code therein),
//                  so this does *not* represent successfull
//                  completion of the exec'd target (which may or may
//                  not be clang).  Thus, a successful syscall_exit
//                  leaves the cmdline argument information available
//                  and is otherwise ignored.
//
// * Exec -- this is the trace that records the actual change of
//           executable code to the new target.  This is actually
//           ignored below and just described here for completeness.
//
// * Exiting -- this is the trace that is called when the process
//              itself is exiting and cleaning up.  It is at this
//              point that the cmdline arguments for the process and
//              are looked up and evaluated: if they were an LLVM
//              compilation, an new invocation of that command is
//              executed with the arguments altered to cause
//              generation of an LLVM bitcode file instead.  If the
//              LLVM bitcode file is generated successfully, it is
//              wrapped in a tar file and then added to the object
//              file as an additional ELF section. Conveniently,
//              tarfiles can be concatenated together, which is the
//              action that will automatically happen during linking
//              operations: the final library or executable will have
//              this ELF section that is a tarfile containing all the
//              bitcode files generated from the sources.  Note that
//              this also works in the partial-rebuild situation where
//              only some sources are rebuilt to regenerate the target
//              library or executable.
//
//              Note that there may be multiple exec events for a
//              specific process. If there was previously an exec for
//              this same process, it indicates that the initially
//              exec'd command is itself invoking an exec.  An example
//              of this is:
//
//                $ cat localbin/clang++
//                #!/bin/sh
//                : -- various code processing arguments --
//                exec actual/path/to/clang++ ...modified-arguments...
//
//              Or an example from cmake:
//
//                /bin/sh -c "cd local/source/path; clang++ ....
//
//              These wrappers and execs may be nested. It is the
//              final exec which will create the needed output file,
//              but it is not necessarily the initial exec nor the
//              final which has the arguments available.
//
// When the extract-bitcode command is run, it retrieves the tarfile
// from the special ELF section created during the generate-bitcode
// phase and extracts the requested bitcode file(s) from that section.
// This means that the extract-bitcode command can be run multiple
// times and only needs access to the final object/library/executable
// to extract any requested bitcode file; the build tree no longer
// needs to be present.

use anyhow::{bail, Context};
use log::{debug, warn, error};
use regex::RegexSet;
use std::collections::HashMap;
use std::path::{Path,PathBuf};
use std::io::{Read,Write};
use std::process;
use std::ffi::{OsString};
use std::os::unix::ffi::OsStringExt;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use sha2::{Digest,Sha256};
use thiserror::Error;
use chainsop::{ChainedOps, Executable, ExeFileSpec, OpInterface, Activation,
               FileArg, FilesPrep, FunctionOperation, OsRun};

use crate::bom::options::{BitcodeOptions, get_executor};
use crate::bom::syscalls::load_syscalls;
use crate::bom::event::RawString;
use crate::bom::executables::{run, CLANG_LLVM};
use crate::bom::proc_read::{read_str_from,read_str_list_from,read_environment,read_cwd};
use crate::bom::clang_support;

#[derive(Error, Debug)]
pub enum TracerError {
    #[error("Unexpected exit state on top-level subprocess exit")]
    UnexpectedExitState(pete::Stop),
    #[error("No command given")]
    NoCommandGiven,
    #[error("Unable to start tracee process")]
    NoTraceeOnExit,
}

/// Options controlling bitcode generation that we need to plumb through most of the process
#[derive(Clone)]
struct BCOpts<'a,  Exec: OsRun> {
    /// The clang command to use to generate bitcode
    clang_path : &'a Option<PathBuf>,
    /// The objcopy command to use to generate bitcode
    objcopy_path : &'a Option<PathBuf>,
    /// The directory to store generated bitcode in
    bitcode_directory : &'a Option<&'a PathBuf>,
    /// If true, do *not* force the generation of debug information
    suppress_automatic_debug : bool,
    /// Arguments to inject when building bitcode
    inject_arguments : &'a Vec<String>,
    /// Arguments to remove when building bitcode
    remove_arguments : &'a RegexSet,
    /// Strict: maintain strict adherence between the bitcode and the target code
    /// (optimization, target architecture, etc.)
    strict : bool,
    /// If true, use the native compiler to pre-process the code before
    /// generating the bitcode with clang.
    native_preproc : bool,
    verbosity: u8,
    executor: Exec,
}

pub fn bitcode_entrypoint(bitcode_options : &BitcodeOptions) -> anyhow::Result<i32> {
    if bitcode_options.command.len() == 0 {
        bail!(TracerError::NoCommandGiven);
    }

    let (cmd0, args0) = bitcode_options.command.split_at(1);
    let cmd_path = which::which(OsString::from(&cmd0[0]))?;

    let mut cmd = Command::new(cmd_path.clone());
    cmd.args(args0);
    let mut ptracer = pete::Ptracer::new();

    // Spawn the subprocess for the command and start it (it starts off
    // suspended to allow the ptracing process to attach)
    let child = ptracer.spawn(cmd);
    match child {
        Ok(_) => {}
        Err(e) => {
            error!("ERROR spawning tracee (command: {}, explicitly: {:?}): {}",
                   bitcode_options.command.join(" "), cmd_path, e);
            bail!(TracerError::NoTraceeOnExit);
        }
    }
    match ptracer.wait()? {
        None => {
            error!("Error spawning tracee (command: {})", bitcode_options.command.join(" "));
            bail!(TracerError::NoTraceeOnExit);
        }
        Some(tracee) => {
            ptracer.restart(tracee, pete::Restart::Syscall)?;
        }
    }

    let (mut sender, receiver) = mpsc::channel();
    let event_consumer = thread::spawn(move || { collect_events(receiver) });

    // This is a bit awkward. We would like to take a union over all of our
    // regexes so that we only need to perform the match test once per argument
    // (pre-computing the necessary automaton).
    //
    // However, RegexSet only takes a sequence of `str`, which is not what we
    // have. We pre-parsed all of the user inputs into `Regex` already. It is
    // nice to parse those as soon as possible to give the user early feedback
    // that their regex is wrong. As a result, we have to convert *back* to str
    // here.
    let rx_strs = bitcode_options.remove_arguments.iter().map(|rx| rx.as_str());
    let remove_rx = RegexSet::new(rx_strs)?;

    let verbosity = bitcode_options.verbose;
    let bc_opts = BCOpts { clang_path : &bitcode_options.clang_path,
                           objcopy_path : &bitcode_options.objcopy_path,
                           bitcode_directory : &bitcode_options.bcout_path.as_ref(),
                           suppress_automatic_debug : bitcode_options.suppress_automatic_debug,
                           inject_arguments : &bitcode_options.inject_arguments,
                           remove_arguments : &remove_rx,
                           strict : bitcode_options.strict,
                           verbosity,
                           native_preproc : bitcode_options.preproc_native,
                           executor : get_executor(verbosity),
    };
    let ptracer1 = generate_bitcode(&mut sender, ptracer, &bc_opts)?;

    // Send a token to shut down the event collector thread
    sender.send(None)?;
    let summary = event_consumer.join().unwrap();
    let exitmod =
        if bitcode_options.any_fail && summary.has_failures() {
            // If the mainline succeeded (ec == 0), return an error indicating
            // that the bitcode-generation attempt failed.  This just needs to be
            // a non-zero value; 76 is arbitrarily chosen as possibly
            // recognizeable for tests.
            |ec| if ec == 0 { 76 } else { ec }
        } else {
            |ec| ec
        };
    if bc_opts.verbosity > 0 {
        print_summary(summary);
    }

    let (mut last_ptracer, exitcode) = ptracer1;
    let tracee = last_ptracer.wait()?;
    match tracee {
        None => Ok(exitcode),
        Some(t) =>
            match t.stop {
                pete::Stop::Exiting { exit_code: ec } => { Ok(ec) }
                _ => { Err(anyhow::anyhow!(TracerError::UnexpectedExitState(t.stop))) }
            }
    }
    .map(exitmod)
}

#[derive(Debug)]
pub enum Event {
    PipeInputOrOutput(RunCommand),
    ResponseFile(RunCommand),
    MultipleInputsWithImplicitOutput(OsString,Vec<OsString>),
    BuildFailureSkippedBitcode(RunCommand, i32),
    BuildFailureUnknownEffect(RunCommand, i32),
    SkippingAssembleOnlyCommand(RunCommand),
    BitcodeGenerationError(PathBuf, anyhow::Error),
    BitcodeGenerationAttempts,
    BitcodeCaptured(PathBuf)
}


fn make_bitcode_filename(target : &OsString, bc_dir : &Option<&PathBuf>) -> PathBuf {
    let mut target_path = match bc_dir {
        None => PathBuf::from(&target),
        Some(p) => {
            let mut pp = PathBuf::from(&p);
            pp.push(&PathBuf::from(&target).file_name().expect("target is not a file"));
            pp
        }
    };
    target_path.set_extension("bc");
    target_path
}

/// Given original arguments (excluding argv[0]), construct the command line we
/// will pass to clang to build bitcode.  This will occur in one of two ways:
///
///  1) call clang with all arguments from the original compile command except
///     those that are blacklisted (and whitelisted unless --strict) and with
///     additional flags to emit LLVM bitcode instead of object code.
///
///  2) if native_preproc is true, call the original compiler with most original
///     compile arguments (except those that are blacklisted and, if not
///     --strict, whitelisted) and pass -E to run the pre-processor only.  Then
///     run the clang bitcode generation (with only those arguments relating to
///     code generation) on that pre-processor output.
///
/// This handles removing flags that clang can't handle (or that we definitely
/// do not want for bitcode generation), as well as transforming the output file
/// path
fn build_bitcode_arguments(chan : &mut mpsc::Sender<Option<Event>>,
                           bc_opts : &BCOpts<impl OsRun>,
                           orig_compiler_cmd: &OsString,
                           orig_args : &[OsString],
                           ops : &mut ChainedOps) -> anyhow::Result<OsString>
{
    let mut orig_target = None;

    // Determine the language of the original input file, so that the bitcode can
    // utilize the same language, because using C++ mode to compile C will cause
    // errors:
    //
    // char* greeting() { return "hello, world"; }
    //
    // The above is perfectly acceptable C, but if compile as C++ it yields:
    // error: ISO C++11 does not allow conversion from string literal to 'char*'.
    //
    // Re use of [0] below: If there are multiple input file (candidates)
    // detected on the line, it is probably safe to just use the first since they
    // all appeared together originally; all compilation commands must have at
    // least one input file.
    let file_ext = clang_support::input_language(&orig_args)[0].file_ext();

    // If the native compiler is used for preprocessing, it will write to a
    // temporary output file that is subsequently consumed by clang to generate
    // the bitcode.
    let mut preprocess = ops.push_op(
        &run(&Executable::new(orig_compiler_cmd,
                              ExeFileSpec::Append,
                              ExeFileSpec::option("-o")), &None)
            .push_arg("-E")
            .set_output_file(&FileArg::temp(file_ext)));

    let mut bcgen_op = ops.push_op(&run(&*CLANG_LLVM, bc_opts.clang_path)
                                   .set_label("clang:emit-llvm"));

    if bc_opts.native_preproc {
        // Make automatic corrections for preprocessing definitions not
        // compatible with clang.
        //
        // If --strict is set, these are not applied and must be done manually
        // via --inject-argument="-D..." if still needed.
        if !bc_opts.strict {
            for ppd in clang_support::CLANG_PREPROC_DEFINES {
                bcgen_op.push_arg(ppd);
            }
        }
    } else {
        preprocess.active(&Activation::Disabled);
    };

    // Force debug information (unless directed not to)
    if !bc_opts.suppress_automatic_debug {
        bcgen_op.push_arg("-g");
    }

    // If not in strict mode, explicitly disable optimization (favoring a maximal
    // amount of information in the generated bitcode and avoiding things like
    // inlining, dead code elimination, etc.
    if !bc_opts.strict {
        bcgen_op.push_arg("-O0");
    }

    // Sometimes -Werror might be in the arguments, so make sure this doesn't
    // cause a failure exit if any other command-line arguments are unused.  Note
    // that this argument is valid for clang only, not gcc.
    if CLANG_RE.is_match(orig_compiler_cmd.to_str().unwrap_or_else(|| "cc")) {
        preprocess.push_arg("-Wno-error=unused-command-line-argument");
    }
    bcgen_op.push_arg("-Wno-error=unused-command-line-argument");

    // C99 and later do not support implicit function declarations, but be more
    // permissive (as GCC seems to be).
    bcgen_op.push_arg("-Wno-error=implicit-function-declaration");

    // Add any arguments that the user directed us to
    let mut add_it = bc_opts.inject_arguments.iter();
    while let Some(arg) = add_it.next() {
        bcgen_op.push_arg(arg);
    }

    // Next, copy over all of the flags we want to keep
    let mut it = orig_args.iter();
    while let Some(arg) = it.next() {

        // Skip any arguments explicitly blacklisted or any matching any of the
        // user-provided regexes.  Note that this is of course as unsafe as users
        // make it.  In particular, rejecting '-o' would be very bad.
        if clang_support::is_blacklisted_clang_argument(bc_opts.strict, arg) ||
            bc_opts.remove_arguments.is_match(arg.to_string_lossy().to_mut())
        {
            if clang_support::next_arg_is_option_value(arg) {
                it.next();
            }
            continue;
        }

        // If the argument specifies the output file, we need to munge the name
        // of the output file (which is either the remainder of this argument or
        // the next argument) to have an appropriate extension and to put it in
        // the requested bitcode directory (if any).  If no argument explicitly
        // specifies an output file then it will need to be inferred (later
        // below) from the input files.
        if arg.to_string_lossy().starts_with("-o") {
            if arg == "-o" {
                match it.next() {
                    None => {
                        bail!(BitcodeError::MissingOutputFile(
                            bc_opts.clang_path.clone().unwrap_or("clang".into()),
                            Vec::from(orig_args)));
                    }
                    Some(target) => {
                        orig_target = Some(PathBuf::from(&target).into_os_string());
                        let target_path = make_bitcode_filename(target, bc_opts.bitcode_directory);
                        bcgen_op.set_output_file(&FileArg::loc(target_path));
                    }
                }
            } else {
                let (_,tgt) = arg.to_str().unwrap().split_at(2);
                let target = OsString::from(tgt);
                let target_path = make_bitcode_filename(&target,
                                                        bc_opts.bitcode_directory);
                orig_target = Some(target);
                bcgen_op.set_output_file(&FileArg::loc(target_path));
            }
        } else {
            // This is not an output specifying argument.
            if arg.to_string_lossy().starts_with("-") {
                preprocess.push_arg(arg);
                bcgen_op.push_arg(arg);
                if clang_support::next_arg_is_option_value(arg) {
                    match it.next() {
                        Some(val) => {
                            preprocess.push_arg(val);
                            bcgen_op.push_arg(val);
                        }
                        None => {
                            bail!(BitcodeError::MissingArgValue(
                                orig_compiler_cmd.into(),
                                orig_args.to_vec(),
                                arg.clone()));
                        }
                    }
                }
            } else {
                ops.add_input_file(&FileArg::loc(arg));
            }
        }
    }

    match orig_target {
        Some(t) => {
            // We found a target explicitly specified with -o
            ops.set_output_file(&FileArg::loc(t.clone()));
            Ok(t)
        }
        None => {
            // There was no explicitly-specified object file.  If there was a
            // single input source file, the object file name will be that input
            // source with the extension replaced by .o.
            match input_sources(orig_args) {
                Ok(source_file) => {
                    let mut target_path = PathBuf::from(source_file);
                    target_path.set_extension("o");
                    ops.set_output_file(&FileArg::loc(target_path.clone()));
                    Ok(OsString::from(target_path))
                }
                Err(msg) => {
                    let _res = chan.send(
                        Some(Event::MultipleInputsWithImplicitOutput(
                            bc_opts.clang_path.clone().unwrap_or("clang".into()).into(),
                            orig_args.to_vec())));
                    Err(anyhow::Error::new(msg))
                }
            }
        }
    }
}

lazy_static::lazy_static! {
    static ref CLANG_RE: regex::Regex = regex::Regex::new("clang").unwrap();
}


fn build_bitcode_compile_only(chan : &mut mpsc::Sender<Option<Event>>,
                              bc_opts : &BCOpts<impl OsRun>,
                              orig_compiler_cmd: &OsString,
                              args : &[OsString],
                              cwd : &Path) -> anyhow::Result<OsString>
{
    let mut bitcode_ops = ChainedOps::new("bitcode generation ops");

    // Analyze the original compilation arguments to determine the output object
    // file and setup the arguments to obtain bitcode from clang.
    let objfile = build_bitcode_arguments(chan, bc_opts,
                                          orig_compiler_cmd, args,
                                          &mut bitcode_ops)?;

    if !obj_already_has_bitcode(bc_opts, cwd, &objfile) {
        let _res = chan.send(Some(Event::BitcodeGenerationAttempts));

        // Inserts the generated bitcode file into a tarfile.
        bitcode_ops.push_call(
            FunctionOperation::calling(
                "gen_bitcode_tar",
                |in_dir, inpfiles, outfile|
                build_bitcode_tar(
                    &inpfiles.to_path(&Some(in_dir))
                        .context("getting bitcode inputs for making a tarfile")?,
                    outfile.writeable()?))
                .set_output_file(&FileArg::temp(".tar")));

        // Inserts the tarfile into the ELF object file as a new named section
        bitcode_ops.push_op(
            &run(&Executable::new("objcopy",
                                  ExeFileSpec::option(&format!("{}=", ELF_SECTION_NAME)),
                                  ExeFileSpec::Append),
                 &bc_opts.objcopy_path)
                .push_arg("--add-section"));

        match bitcode_ops.execute(&bc_opts.executor, &Some(cwd)) {
            Ok(obj_output) => {
                let objf = obj_output.to_paths(&Some(cwd))
                    .context("getting result object file")?
                    .iter().map(|p| p.to_str().unwrap()).collect::<Vec<_>>()
                    .join(",");
                let _res = chan.send(Some(Event::BitcodeCaptured(objf.into())));
                debug!("#: injected bitcode into {:?}", obj_output);
            }
            Err(e) => {
                error!("Error attaching bitcode: {:?}", e);
                let err = Event::BitcodeGenerationError(
                    PathBuf::from(objfile.clone()), e);
                let _res = chan.send(Some(err))?;
                // n.b. no error is returned, because bitcode generation failure
                // should not halt the overall build operation.
            }
        }
    }

    Ok(objfile)
}

/// Attempt to identify the source files provided as inputs to the build command
///
/// This is unfortunately a bit heuristic.  We don't really use filenames
/// because they are unreliable. Instead, we look at options that are known to
/// have zero or one arguments and ignore them.  Everything else is an input
/// file.  If there is only a single candidate identified, we return it.
///
/// Note that this is only used if there is no explicit output file specified
/// (via -o) on the command line, where we need to figure out what the implicit
/// output filename will be.  This is an unusual case.
fn input_sources<'a>(args : &'a[OsString]) -> Result<&'a OsString,BitcodeError> {
    let mut inputs = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if clang_support::is_option_arg(arg) {
            if clang_support::next_arg_is_option_value(arg) {
                // Discard the next argument since it can't be a source file
                let _next_arg = it.next();
            }
            // ignore it whether there's a following argument or not
        } else {
            // This is an argument
            inputs.push(arg);
        }
    }

    if inputs.len() == 1 {
        Ok(inputs[0])
    } else {
        if inputs.len() == 0 {
            Err(BitcodeError::NoInputFileFound(Vec::from(args)))
        } else {
            Err(BitcodeError::MultipleInputFiles(
                inputs.iter().map(|s| s.to_string_lossy().into_owned()).collect(),
                Vec::from(args))
            )
        }
    }
}

#[derive(thiserror::Error,Debug)]
pub enum BitcodeError {
    #[error("Error attaching bitcode file '{2:?}' to '{1:?}' in {0:?} ({3:?} / {4:?})")]
    ErrorAttachingBitcode(PathBuf, OsString, OsString, std::io::Error, String),
    #[error("Missing output file in command {0:?} {1:?}")]
    MissingOutputFile(PathBuf, Vec<OsString>),
    #[error("Expected argument {2:?} value not present in {0:?} {1:?}")]
    MissingArgValue(PathBuf, Vec<OsString>, OsString),
    #[error("Error generating bitcode from {0:?}: {1:?}")]
    ErrorGeneratingBitcode(PathBuf, anyhow::Error),
    #[error("Error {2:?} generating bitcode with command {0:?} {1:?}")]
    ErrorCodeGeneratingBitcode(PathBuf, Vec<OsString>, std::io::Error),
    #[error("Unreadable memory address {0:}")]
    UnreadableMemoryAddress(u64),
    #[error("No input file found in compilation from args {0:?}")]
    NoInputFileFound(Vec<OsString>),
    #[error("Multiple input files found for command: files {0:?} from args {1:?}")]
    MultipleInputFiles(Vec<String>, Vec<OsString>),
    #[error("Unexpected target tarfile for bitcode attach: {0}")]
    InvalidInternalTarFile(String),
}

/// Returns true if the specified object file target already has an
/// LLVM bitcode section attached to it.
///
/// This can typically occur when using a wrapper tool such as ccache.
///
/// Detailed explanation:
/// ---------------------
//
/// The ccache tool provides a "clang" target in the PATH, which is
/// actually a symlink to the ccache executable: the ccache executable
/// will issue a pre-proc only (-E) actual clang operation and compare
/// the results to the cached version to determine whether to issue
/// the actual requested clang operation.
///
/// * If the ccache tool runs the actual clang operation, then
/// build-bom will see that operation complete first and perform the
/// requested bitcode attachment.  Then the ccache invocation
/// completes but build-bom also identified it as a clang operation,
/// so it will re-attempt to attach the bitcode.  This will normally
/// fail the `objcopy` with a `bad value` error which is an indication
/// that the named value already exists.
///
/// * If the ccache tool found that the cached object file should be
/// used, build-bom will then try to generate and attach the bitcode
/// again, resulting in the same `bad value` error described above.
///
/// One solution to this would be to explicitly ignore "bad value"
/// errors on the `objcopy` phase with the assumption that this is the
/// only situation where that will occur.  A second solution would be
/// to check for symlinks to the ccache executable; this is not
/// desireable because it will limit build-bom's support to only known
/// and standard tools. The third solution (implemented here) is to
/// check if an ELF_SECTION_NAME section already exists in the object
/// file.  The advantage of this latter solution is that it will avoid
/// re-generating the bitcode file for both cases described above (and
/// also avoiding the assumption that a duplicate section name is the
/// only cause of the "bad value" error report from `objcopy`).
///
/// There is a slight risk (to ALL the approaches described above)
/// that there exists a section whose name matches the
/// ELF_SECTION_NAME, but whose contents are not the bitcode file.
/// That is a much more complex (and unlikely) scenario that is not
/// addressed here.
fn obj_already_has_bitcode(bc_opts : &BCOpts<impl OsRun>,
                           cwd : &Path,
                           obj_target : &OsString) -> bool {
    // Could use objdump for this as well, but in cases where cross-compilation
    // is being performed, the user would need a way to specify the objdump
    // executable to use that is similar to the ability to specify the objcopy
    // executable.  Since objcopy is already specified, just use that here.
    //
    // However, to use objcopy we need a directory because objcopy always writes
    // at least one output and sometimes multiple outputs (see note in extract.rs
    // for more details).
    match tempfile::TempDir::new() {
        Err(_) => false,
        Ok(tmp_dir) => {
            let res = obj_already_has_bitcode_inner(bc_opts, cwd, obj_target,
                                                    tmp_dir.path());
            // The following ensures that tmp_dir still has ownership of the
            // associated resources and that they weren't inadvertently dropped
            // during bitcode extraction.  This uses Rust's ownership to help
            // avoid the "Early drop pitfall" described at
            // https://docs.rs/tempfile/latest/tempfile.
            std::mem::drop(tmp_dir);
            res
        }
    }
}

fn obj_already_has_bitcode_inner(bc_opts : &BCOpts<impl OsRun>,
                                 cwd : &Path,
                                 obj_target : &OsString,
                                 tmp_path : &Path) -> bool {
    let mut dummy_output = PathBuf::from(tmp_path);
    dummy_output.push("discard{out-file}");  // arbitrary name
    let mut section_output = PathBuf::from(tmp_path);
    section_output.push("discard{section-file}");  // arbitrary name
    match run(&Executable::new("objcopy",
                               ExeFileSpec::Append,
                               ExeFileSpec::Append),
              &bc_opts.objcopy_path)
        .push_arg("--dump-section")
        .push_arg(format!("{}={}", ELF_SECTION_NAME, section_output.display()))
        .set_input_file(&FileArg::loc(obj_target))
        .set_output_file(&FileArg::loc(dummy_output))
        .execute(&bc_opts.executor, &Some(cwd)) {
            Err(_) => false,
            Ok(_) => section_output.exists(),
        }
}


/// Create a singleton tar file with the bitcode file.
///
/// We use the original relative name to make it easy to unpack.
///
/// In most cases, this should avoid duplicates, but it is possible that
/// there could be collisions if the build system does a lot of changing of
/// directories with source files that have similar names.
///
/// To avoid collisions, we append a hash to each filename
fn build_bitcode_tar(bc_path : &Path,
                     tar_file : impl Write) -> anyhow::Result<()>
{
    let hash = bitcode_hashval(bc_path)?;
    let mut tb = tar::Builder::new(tar_file);

    let mut archived_name = OsString::new();
    archived_name.push(bc_path.file_stem().unwrap());
    archived_name.push("-");
    archived_name.push(hash);
    archived_name.push(".");
    archived_name.push(bc_path.extension().unwrap());

    tb.append_path_with_name(bc_path, &archived_name)?;
    tb.into_inner()?;

    Ok(())
}


fn bitcode_hashval(bc_path : &Path) -> anyhow::Result<String> {
    let mut hasher = Sha256::new();
    let mut bc_content = Vec::new();
    let mut bc_file = std::fs::File::open(&bc_path)?;
    bc_file.read_to_end(&mut bc_content)?;
    hasher.update(bc_content);
    let hash = hasher.finalize();
    Ok(hex::encode(hash.as_slice()))
}


pub const ELF_SECTION_NAME : &str = ".llvm_bitcode";


struct SummaryStats {
    num_pipe_io : usize,
    num_responsefile : usize,
    unresolved_implicit_outputs : usize,
    build_failures_skipping_bitcode : usize,
    build_failures_unknown_effect : usize,
    skipping_assemble_only : usize,
    bitcode_compile_errors : usize,
    bitcode_attach_errors : usize,
    bitcode_generation_attempts : usize,
    bitcode_captures : usize,
    last_capture_file : Option<PathBuf>
}

fn print_summary(summary : SummaryStats) {
    println!("Bitcode Generation Summary");
    println!(" {} build steps skipped due to having a pipe as an input or output", summary.num_pipe_io);
    println!(" {} build steps skipped due to using a response file (@file)", summary.num_responsefile);
    println!(" {} unresolved outputs with multiple inputs", summary.unresolved_implicit_outputs);
    println!(" {} original build commands failed, causing us to skip bitcode generation", summary.build_failures_skipping_bitcode);
    println!(" {} inputs skipped due to being only assembled (-S)", summary.skipping_assemble_only);
    println!(" {} bitcode compilation errors", summary.bitcode_compile_errors);
    println!(" {} errors attaching bitcode to object files", summary.bitcode_attach_errors);
    println!(" {} attempts at generating bitcode", summary.bitcode_generation_attempts);
    println!(" {} successful bitcode captures", summary.bitcode_captures);
    println!(" last bitcode capture: {:?}", summary.last_capture_file.map_or("<none>".into(),
                                                                             |f| f.into_os_string()));
}

impl SummaryStats {
    fn has_failures(&self) -> bool {
        self.build_failures_skipping_bitcode > 0 ||
            self.build_failures_unknown_effect > 0 ||
            self.bitcode_compile_errors > 0 ||
            self.bitcode_attach_errors > 0
    }
}

fn collect_events(chan : mpsc::Receiver<Option<Event>>) -> SummaryStats {
    let mut summary = SummaryStats { num_pipe_io : 0,
                                     num_responsefile : 0,
                                     unresolved_implicit_outputs : 0,
                                     build_failures_skipping_bitcode : 0,
                                     build_failures_unknown_effect : 0,
                                     skipping_assemble_only : 0,
                                     bitcode_compile_errors : 0,
                                     bitcode_attach_errors : 0,
                                     bitcode_generation_attempts : 0,
                                     bitcode_captures : 0,
                                     last_capture_file : None
    };
    loop {
        match chan.recv() {
            Err(err_msg) => {
                error!("Event collector exiting early due to error: {:?}", err_msg);
                return summary;
            }
            Ok(None) => { return summary }
            Ok(Some(evt)) => {
                match evt {
                    Event::PipeInputOrOutput(cmd) => {
                        summary.num_pipe_io += 1;
                        error!("Pipe I/O in command '{:?} {:?}'", cmd.bin, cmd.args);
                    }
                    Event::ResponseFile(cmd) => {
                        summary.num_responsefile += 1;
                        error!("Response file in command '{:?} {:?}'", cmd.bin, cmd.args);
                    }
                    Event::MultipleInputsWithImplicitOutput(cmd, args) => {
                        summary.unresolved_implicit_outputs += 1;
                        error!("Unresolved implicit outputs with multiple input files in command '{:?} {:?}'", cmd, args);
                    }
                    Event::BuildFailureSkippedBitcode(cmd, exit_code) => {
                        summary.build_failures_skipping_bitcode += 1;
                        error!("Skipping bitcode generation due to failed compile command '{:?} {:?} = {}'", cmd.bin, cmd.args, exit_code);
                    }
                    Event::BuildFailureUnknownEffect(cmd, exit_code) => {
                        summary.build_failures_unknown_effect += 1;
                        error!("Failed compile command may affect bitcode coverage '{:?} {:?} = {}'", cmd.bin, cmd.args, exit_code);
                    }
                    Event::SkippingAssembleOnlyCommand(cmd) => {
                        summary.skipping_assemble_only += 1;
                        error!("Skipping bitcode generation for assemble-only command '{:?} {:?}'", cmd.bin, cmd.args);
                    }
                    Event::BitcodeGenerationError(on_file, err) => {
                        summary.bitcode_compile_errors += 1;
                        error!("Error while generating bitcode for {:?}: {}",
                               on_file, err);
                    }
                    Event::BitcodeGenerationAttempts => {
                        summary.bitcode_generation_attempts += 1;
                    }
                    Event::BitcodeCaptured(into) => {
                        summary.bitcode_captures += 1;
                        summary.last_capture_file = Some(into);
                    }
                }
            }
        }
    }
}


/// A command that was run by a process we are tracing
///
/// This is the saved version that we attempt to postprocess to see if we need
/// to generate bitcode for it
#[derive(Debug,Clone)]
pub struct RunCommand {
    bin : OsString,
    args : Vec<OsString>,
    env : Vec<u8>,
    cwd : PathBuf
}

enum ProcessState {
    TryExec(RunCommand),
    FinishExec(RunCommand)
}

/// Make an entry in the exec process state table if we can decode the command.
fn handle_start_execve(tracee : &mut pete::Tracee, regs : pete::Registers, process_state : &mut HashMap<i32, ProcessState>) {
    let bin = read_str_from(tracee, regs.rdi);
    let args = read_str_list_from(tracee, regs.rsi);
    let env = read_environment(&tracee);
    let cwd = read_cwd(&tracee);

    // Record the fact that we saw this PID try to start a process
    //
    // NOTE: It may not succeed (we'll find out in the matching
    // SyscallExitStop)
    match make_command(&bin, &args, env, cwd) {
        Err(msg) => {
            warn!("Error decoding strings to build command: {:?}", msg);
        }
        Ok(cmd) => {
            process_state.insert(tracee.pid.as_raw() as i32, ProcessState::TryExec(cmd));
        }
    }
}

/// Advance the state of the process if the exec succeeded (so that we can observe it when it exits)
fn handle_exit_execve(pid : pete::Pid, regs : pete::Registers, process_state : &mut HashMap<i32, ProcessState>) {
    let res = regs.rax as i32;
    let ipid = pid.as_raw() as i32;
    if res != 0 {
        // Exec failed, remove the binding
        process_state.remove(&ipid);
    } else {
        // Exec succeeded, update the binding so that we
        // know that we have execed this command
        match process_state.remove(&ipid) {
            None => {
                error!("Missing expected exec command for process id {}", ipid);
            }
            Some(ProcessState::TryExec(rc)) => {
                process_state.insert(ipid, ProcessState::FinishExec(rc));
            }
            Some(ProcessState::FinishExec(rc)) => {
                error!("Unexpected finish event for already finished command {:?}", rc);
            }
        }
    }
}

/// If the exited process was an exec, see if we need to build bitcode for it.
///
/// This is done here rather than when the syscall exits because the
/// syscall exits back to the original program, even for an execve;
/// the actual exec will be a separate ptrace event that will occur a
/// short time later, but the post_process_actions should only be run
/// when the output file exists (and therefore after the actual exec
/// completes.
fn handle_process_exit(chan : &mut mpsc::Sender<Option<Event>>,
                       pid : pete::Pid,
                       exit_code : i32,
                       process_state : &mut HashMap<i32, ProcessState>,
                       bc_opts : &BCOpts<impl OsRun>)
{
    let ipid = pid.as_raw() as i32;
    match process_state.remove(&ipid) {
        None => {
            // We weren't tracking this process
        }
        Some(ProcessState::TryExec(_)) => {
            // The process tried to exec some command but never succeeded
        }
        Some(ProcessState::FinishExec(rc)) => {
            if exit_code != 0 {
                let cmd_path = Path::new(&rc.bin);
                match cmd_path.file_name() {
                    None => {
                        let _rc = chan.send(Some(Event::BuildFailureUnknownEffect(rc, exit_code)));
                    }
                    Some(cmd_file_name) => {
                        if clang_support::is_compile_command_name(cmd_file_name) {
                            let _rc = chan.send(Some(Event::BuildFailureSkippedBitcode(rc, exit_code)));
                        } else {
                            let _rc = chan.send(Some(Event::BuildFailureUnknownEffect(rc, exit_code)));
                        };
                    }
                };
                return;
            }
            // The process successfully exec'd - see if we want to do anything with it
            post_process_actions(rc, chan, bc_opts);
        }
    }
}

/// Compilation modifiers are flags that can be passed to the compiler that
/// affect our handling of the command
///
/// We need to process the command line to determine which of these is actually set
struct CompileModifiers {
    /// Corresponding to specifying pipe IO either for an input or output (passing -)
    is_pipe_io : bool,

    /// Corresponding to the command line being specified with a response file (filename prefixed with @)
    is_response_file : bool,

    /// Corresponding to the compile command including -S to generate an assembly file instead of an object file
    is_assemble_only : bool,

    /// Corresponding to the -E preprocess only flag.  Note that this is a subset
    /// of is_non_generative, but kept for analytical reasons.
    is_pre_proc_only : bool,

    /// Compiler invocation does not actually generate any code output.  For
    /// example, "gcc --version".
    is_non_generative : bool,
}

fn extract_compile_modifiers(rc : &RunCommand) -> CompileModifiers {
    let mut mods = CompileModifiers { is_pipe_io : false,
                                      is_response_file : false,
                                      is_assemble_only : false,
                                      is_pre_proc_only : false,
                                      is_non_generative : false,
    };

    for arg in &rc.args {
        // We want to recognize cases where the compilation
        // input is stdin or the output is stdout; we can't
        // replicate those build steps since we don't know
        // where either is really going to/coming from.
        mods.is_pipe_io = mods.is_pipe_io || arg == "-";

        // We could potentially track builds that assemble-only, but the
        // worry is that gnarly things happen to artifacts constructed
        // that way that we might miss (e.g., evil mangler scripts whose
        // effects can't be mirrored on llvm assembly).
        //
        // For now, ignore them.  This could be guarded behind an
        // option.
        mods.is_assemble_only = mods.is_assemble_only || arg == "-S";

        // There is no code generated in preprocess only mode, so there is
        // nothing for build-bom to do
        mods.is_pre_proc_only = mods.is_pre_proc_only
            || arg == "-E"
            || arg == "-M"     // implies -E
            || arg == "-MM";   // implies -E

        // We would ideally like to handle response files, but we can't yet.
        // For now, we'll have to ignore them.
        mods.is_response_file = mods.is_response_file || arg.to_str().unwrap().starts_with("@");

        // Some configurations do not generate output, and thus there is no
        // bitcode to extract
        mods.is_non_generative =
            mods.is_non_generative || arg_is_non_generative(arg, &rc.args.len());

        // Oddly, "clang -c -emit-llvm -o foo.bc foo.s" results in the foo.bc
        // file containing post-preprocessor form of foo.s, and *not* bitcode,
        // so if it looks like and assembly source file, skip it.
        if !arg.to_str().unwrap().starts_with("-")
            && arg.to_str().unwrap().ends_with(".s") {
                mods.is_assemble_only = true;
            }
    }

    mods
}


fn arg_is_non_generative(arg: &OsString, num_args: &usize) -> bool {
    arg == "--version"  // even "gcc --version -o foo foo.c" is non-gen

    // Ugh:
    //  gcc -v   # non-generative config info
    //  gcc -v --version [..anything and everything]
    //           # non-generative, but invokes sub-commands with -v
    //  gcc -v -o foo foo.c  # generative of foo, echoing sub-commands
    //
    //  clang -v  # non-generative config info
    //  clang -v [..anything and everything] # non-generative config info
    //
        || (arg == "-v" && *num_args == 2)  // just $ cmd -v

    // This is actually generating llvm IR bitcode... but it's not an
    // actual compilation, so it is ignored.  This may be a separate
    // bitcode-capture operation, but this flag suppresses object
    // code generation so it can be ignored: build-bom only captures during
    // actual object code generation.
    //
        || arg == "-emit-llvm"

    // All of these are equivalent and instruct gcc to print the name of
    // the subprogram invoked and ignore all other args.
    //
    //  gcc -print-prog-name=ld
    //  gcc --print-prog-name=ld
    //  gcc --print-prog-name ld
    //
        || arg.to_str().unwrap().starts_with("--print-prog-name")
        || arg.to_str().unwrap().starts_with("-print-prog-name=")

    // These also ignore all other args and just dump the requested info
        || arg == "-print-search-dirs"
        || arg == "--print-search-dirs"
}


/// Returns true if we should make bitcode given this command.  May write to the
/// event channel on failure.
fn should_make_bc(rc : &RunCommand, comp_mods : &CompileModifiers,
                  chan : &mut mpsc::Sender<Option<Event>>
) -> bool {
    let cmd_path = Path::new(&rc.bin);
    match cmd_path.file_name() {
        None => { false }  // TODO: event for this
        Some(cmd_file_name) => {
            // n.b. ignore chan.send failures below: shouldn't happen and only
            // for stats collection anyhow, so don't let it kill this tracer
            // thread.

            // Is this a compile command we recognize?
            if !clang_support::is_compile_command_name(cmd_file_name) {
                return false;  // nope: just ignore it quietly
            }

            // Pipe input can't be re-processed a second time (so generating
            // bitcode would fail; the pipe is already drained)
            if comp_mods.is_pipe_io {
                let _res = chan.send(Some(Event::PipeInputOrOutput(rc.clone())));
                return false;
            }

            // In an assemble-only build, there is no object file to attach the
            // bitcode to.
            if comp_mods.is_assemble_only {
                let _res = chan.send(Some(Event::SkippingAssembleOnlyCommand(rc.clone())));
                return false;
            }

            // In a preprocess only build we have no object file to attach
            // bitcode to.
            if comp_mods.is_pre_proc_only {
                // TODO: event for this
                return false;
            }

            // This compilation command doesn't generate machine-code output
            if comp_mods.is_non_generative {
                // TODO: event for this
                return false;
            }

            // This compilation command uses a response file: cannot be reliably
            // read twice since only a file-descriptor is provided and it might
            // not be seekable.
            if comp_mods.is_response_file {
                let _res = chan.send(Some(Event::ResponseFile(rc.clone())));
                return false;
            }

            true
        }
    }
}


/// Determine what actions should be taken on the successful execution
/// completion of a build process action.
fn post_process_actions(rc : RunCommand,
                        chan : &mut mpsc::Sender<Option<Event>>,
                        bc_opts : &BCOpts<impl OsRun>)
{
    let comp_mods = extract_compile_modifiers(&rc);
    if should_make_bc(&rc, &comp_mods, chan) {
        // If this is a command we can build bitcode for, do
        // it.  We wait until the exec'd process exits
        // because we need the original object file to exist
        // (so that we can attach the bitcode).
        //
        // We drop the first argument because it is just the
        // original command name (i.e., argv[0])
        match build_bitcode_compile_only(chan, bc_opts,
                                         &rc.args[0], &rc.args[1..],
                                         &rc.cwd) {
            Err(err) => { error!("Error building bitcode: {:?}", err) }
            Ok(_) => {}
        }
    }
}


fn generate_bitcode(chan : &mut mpsc::Sender<Option<Event>>,
                    mut ptracer : pete::Ptracer,
                    bc_opts : &BCOpts<impl OsRun>)
                    -> anyhow::Result<(pete::Ptracer, i32)>
{
    let mut process_state = HashMap::new();
    let syscalls = load_syscalls();
    let mut last_exitcode = 0;

    // We want to observe execve syscalls. After a process (successfully) execs
    // a command we care about, we want to record that PID (along with the
    // arguments) and then, when that PID Exits, we want to generate bitcode and
    // attach it to the original object file result.
    while let Ok(Some(mut tracee)) = ptracer.wait() {
        let regs = tracee.registers()?;
        match tracee.stop {
            pete::Stop::SyscallEnter => {
                let rax = regs.orig_rax;
                match syscalls.get(&rax) {
                    // Unhandled syscall; we don't really care since we only really need execve
                    None => {}
                    Some(syscall) => {
                        if syscall == "execve" {
                            handle_start_execve(&mut tracee, regs, &mut process_state);
                        }
                    }
                }
            }
            pete::Stop::SyscallExit => {
                let syscall_num = regs.orig_rax;
                match syscalls.get(&syscall_num) {
                    None => {}
                    Some(syscall) => {
                        if syscall == "execve" {
                            handle_exit_execve(tracee.pid, regs, &mut process_state);
                        }
                    }
                }
            }
            pete::Stop::Exiting { exit_code }=> {
                last_exitcode = exit_code;
                handle_process_exit(chan, tracee.pid, exit_code, &mut process_state, bc_opts);
            }
            _ => {}
        }

        ptracer.restart(tracee, pete::Restart::Syscall)?;
    }

    Ok((ptracer, last_exitcode))
}

/// Try our best to decode a raw string into a string we can use (still an
/// OsString)
fn decode_raw_string(rs : &RawString) -> anyhow::Result<OsString> {
    match rs {
        RawString::SafeString(s) => { Ok(OsString::from(s)) }
        RawString::BinaryString(bytes) => { Ok(OsStringExt::from_vec(bytes.clone())) }
        RawString::UnreadableMemoryAddress(addr) => { Err(anyhow::Error::new(BitcodeError::UnreadableMemoryAddress(*addr))) }
    }
}

/// Try to resolve all of the strings we found into utf-8 strings that are
/// easier to work with.  We should try to find a way to not need this.
fn make_command(bin : &RawString, args : &[RawString], env : anyhow::Result<Vec<u8>>, cwd : anyhow::Result<PathBuf>) -> anyhow::Result<RunCommand> {
    let mut os_args = Vec::new();
    for arg in args {
        os_args.push(decode_raw_string(arg)?);
    }

    let cmd = RunCommand { bin : decode_raw_string(bin)?, args : os_args, env : env?, cwd : cwd? };
    Ok(cmd)
}


// ----------------------------------------------------------------------
// TESTS
// ----------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::mpsc;
    use super::*;
    use chainsop::{ActualFile, Executor, OsRun, OsRunResult};

    #[derive(Clone, Debug, PartialEq)]
    struct RunExec {
        name: String,
        exe: PathBuf,
        args: Vec<OsString>,
        dir: Option<PathBuf>
    }
    #[derive(Clone, Debug, PartialEq)]
    struct RunFunc{
        fname: String,
        inpfiles: Vec<PathBuf>,
        outfile: Option<PathBuf>,
        dir: Option<PathBuf>
    }
    #[derive(Clone, Debug, PartialEq)]
    enum TestOp {
        SPO(RunExec),
        FO(RunFunc)
    }
    struct TestCollector(RefCell<Vec<TestOp>>);
    impl TestCollector {
        pub fn new() -> TestCollector {
            TestCollector(RefCell::new(vec![]))
        }
    }

    fn clean_temp_in_args(args: &Vec<OsString>) -> Vec<OsString> {
        // The tests here would like to compare the actual args against a
        // known set, but sometimes the actual args contain generated
        // temporary files.  This function applies various heuristics to
        // identify and strip or convert those temporary files into a static
        // pattern for the simple equality comparisons below.  These
        // heuristics are based on the patterns used for those temp files in
        // the main code.
        args.iter().map(clean_temp_in_arg).collect()
    }
    fn clean_temp_with_suffix(argstr: &String, sfx: &str) -> String {
        if argstr.ends_with(sfx) {
            // If the argstr is something like "--foo=/tmp/dir/is/tmpfile{sfx}",
            // tries to just remove the file portion and return "--foo={sfx}".
            match argstr.find("/") {
                Some(i) => {
                    let mut r = String::new();
                    r.push_str(&argstr[..i]);
                    r.push_str(sfx);
                    r
                },
                None => String::from(sfx)
            }
        } else {
            String::from(argstr)
        }
    }
    fn clean_temp_in_arg(arg: &OsString) -> OsString {
        let argstr = arg.to_string_lossy();
        clean_temp_with_suffix(
            &clean_temp_with_suffix(&String::from(argstr),
                                    "discard{section-file}"),
            "discard{out-file}")
            .into()
    }


    impl OsRun for TestCollector {
        fn run_executable(&self,
                          label: &str,
                          exe_file: &Path,
                          args: &Vec<OsString>,
                          fromdir: &Option<PathBuf>) -> OsRunResult
        {
            self.0.borrow_mut()
                .push(TestOp::SPO(RunExec{ name: String::from(label),
                                           exe: PathBuf::from(exe_file),
                                           args: clean_temp_in_args(args),
                                           dir: fromdir.clone()
            }));
            OsRunResult::Good
        }
        fn run_function(&self,
                        name : &str,
                        _call : &Rc<dyn Fn(&Path, &ActualFile, &ActualFile)
                                           -> anyhow::Result<()>>,
                        inpfiles: &ActualFile,
                        outfile: &ActualFile,
                        fromdir: &Option<PathBuf>) -> OsRunResult
        {
            self.0.borrow_mut()
                .push(TestOp::FO(RunFunc{ fname: name.to_string(),
                                          inpfiles: inpfiles.to_paths::<PathBuf>(&None).unwrap(),
                                          outfile: outfile.to_path::<PathBuf>(&None).ok(),
                                          dir: fromdir.clone()
            }));
            OsRunResult::Good
        }
        fn glob_search(&self, _globpat: &String) -> anyhow::Result<Vec<PathBuf>>
        {
            Err(anyhow::anyhow!("glob_search not implemented for ArgCollector"))
        }
        fn mk_tempfile(&self, suffix: &String) -> anyhow::Result<tempfile::NamedTempFile>
        {
            Executor::DryRun.mk_tempfile(suffix)
        }
    }

    #[test]
    fn test_bitcode_compile_args() -> anyhow::Result<()> {
        let (mut sender, receiver) = mpsc::channel();
        let mut bcdir = PathBuf::new();
        bcdir.push("path");
        bcdir.push("to");
        bcdir.push("bitcode");
        let bcopts = BCOpts { clang_path: &Some("/path/to/clang".into()),
                              objcopy_path: &None,
                              bitcode_directory: &Some(&bcdir),
                              suppress_automatic_debug: false,
                              inject_arguments: &Vec::from(
                                  [
                                      "-arg1",
                                      "-arg2",
                                      "arg2val"
                                  ].map(|s| String::from(s))),
                              remove_arguments: &regex::RegexSet::new(
                                  [r"^-remove$", r"^--this" ],

                              ).unwrap(),
                              strict: false,
                              native_preproc: false,
                              verbosity: 0,
                              executor: TestCollector::new(),
        };

        // ----------------------------------------------------------------------
        // Simple cmdline specification
        let args = [
            "-g", "-O1", "-o", "foo.obj",
            "-march=mips",
            "-DDebug",
            "bar.c",
        ].map(|s| s.into());
        let bcargs = build_bitcode_compile_only(&mut sender, &bcopts,
                                                &OsString::from("gcc"), &args,
                                                &PathBuf::from("/somE/path"));
        match bcargs {
            Err(e) => assert_eq!(e.to_string(), "<no error expected>"),
            Ok(a) => {
                // output file:
                assert_eq!(a, "foo.obj");
                // channel messages:
                let chan_out1 = receiver.try_recv();
                match chan_out1 {
                    Ok(Some(Event::BitcodeGenerationAttempts)) => (),
                    o => assert!(false, "Unexpected channel output 1: {:?}", o),
                };
                let chan_out2 = receiver.try_recv();
                match chan_out2 {
                    Ok(Some(Event::BitcodeCaptured(pb))) =>
                        assert_eq!(pb, PathBuf::from("/somE/path/foo.obj")),
                    o => assert!(false, "Unexpected channel output 1: {:?}", o),
                };
                let chan_out3 = receiver.try_recv();
                assert!(chan_out3.is_err());
                assert_eq!(chan_out3.err(), Some(mpsc::TryRecvError::Empty));
            }
        };
        let captured = bcopts.executor.0.borrow().clone();
        // Check temporary output file in the middle of the chain
        let tarfile = match &captured[2] {
            TestOp::FO(rf) => match &rf.outfile {
                Some(tmp_path) => tmp_path.clone(),
                None => {
                    assert!(false, "no bitcode tarfile in {:?}", captured);
                    PathBuf::from("bad tarfile path")
                },
            },
            _ => {
                assert!(false, "unexpected SPO at tarfile step in {:?}", captured);
                PathBuf::from("bad tarfile path")
            }
        };
        // Verify full recorded sequence trace
        assert_eq!(captured,
                   [ TestOp::SPO(
                       RunExec { name: "objcopy".to_string(),
                                 exe: "objcopy".into(),
                                 args: [
                                     "--dump-section",
                                     &format!(".llvm_bitcode={}",
                                              "discard{section-file}"),
                                     "foo.obj",
                                     "discard{out-file}"
                                 ].map(OsString::from).to_vec(),
                                 dir: Some("/somE/path".into()) }),
                     TestOp::SPO(
                         RunExec { name: "clang:emit-llvm".to_string(),
                                   exe: "/path/to/clang".into(),
                                   args: [
                                       "-emit-llvm",
                                       "-c",
                                       "-g",
                                       "-O0",
                                       "-Wno-error=unused-command-line-argument",
                                       "-Wno-error=implicit-function-declaration",
                                       "-arg1",
                                       "-arg2", "arg2val",
                                       "-g",
                                       "-DDebug",
                                       "-o",
                                       "path/to/bitcode/foo.bc",
                                       "bar.c"
                                   ].map(OsString::from).to_vec(),
                                   dir: Some("/somE/path".into()) }),
                     TestOp::FO(
                         RunFunc { fname: "gen_bitcode_tar".to_string(),
                                   inpfiles: [
                                       PathBuf::from("path/to/bitcode/foo.bc"),
                                   ].to_vec(),
                                   outfile: Some(tarfile.clone()),
                                   dir: Some("/somE/path".into()) }),
                     TestOp::SPO(
                         RunExec { name: "objcopy".to_string(),
                                   exe: "objcopy".into(),
                                   args: [
                                       "--add-section",
                                       &format!(".llvm_bitcode={}",
                                                tarfile.display()),
                                       "foo.obj"
                                   ].map(OsString::from).to_vec(),
                                   dir: Some("/somE/path".into()) }),
                   ]);

        // ----------------------------------------------------------------------
        // Simple cmdline specification, strict bitcode
        let bcopts_strict = BCOpts { strict: true, native_preproc: true, ..bcopts };
        bcopts_strict.executor.0.swap(&RefCell::new(vec![])); // clear trace
        let bcargs1 = build_bitcode_compile_only(&mut sender, &bcopts_strict,
                                                 &OsString::from("g++"), &args,
                                                 &PathBuf::from("/A/path"));
        match bcargs1 {
            Err(e) => assert_eq!(e.to_string(), "<no error expected>"),
            Ok(a) => {
                // output file:
                assert_eq!(a, "foo.obj");
                // channel messages:
                let chan_out1 = receiver.try_recv();
                match chan_out1 {
                    Ok(Some(Event::BitcodeGenerationAttempts)) => (),
                    o => assert!(false, "Unexpected channel output 1: {:?}", o),
                };
                let chan_out2 = receiver.try_recv();
                match chan_out2 {
                    Ok(Some(Event::BitcodeCaptured(pb))) =>
                        assert_eq!(pb, PathBuf::from("/A/path/foo.obj")),
                    o => assert!(false, "Unexpected channel output 1: {:?}", o),
                };
                let chan_out3 = receiver.try_recv();
                assert!(chan_out3.is_err());
                assert_eq!(chan_out3.err(), Some(mpsc::TryRecvError::Empty));
            }
        }
        let captured1 = bcopts_strict.executor.0.borrow().clone();
        // Check temporary output files in the middle of the chain
        let preproc_c_file = match &captured1[1] {
            TestOp::SPO(ro) => ro.args[6].to_string_lossy().into(),  // I counted...
            _ => {
                assert!(false, "unexpected FPO at preproc step in {:?}", captured1);
                String::from("bad preprocessed c path")
            }
        };
        let tarfile = match &captured1[3] {
            TestOp::FO(rf) => match &rf.outfile {
                Some(tmp_path) => tmp_path.clone(),
                None => {
                    assert!(false, "no bitcode tarfile in {:?}", captured1);
                    PathBuf::from("bad tarfile path")
                },
            },
            _ => {
                assert!(false, "unexpected SPO at tarfile step in {:?}", captured1);
                PathBuf::from("bad tarfile path")
            }
        };
        // Verify full recorded sequence trace
        assert_eq!(captured1,
                   [ TestOp::SPO(
                       RunExec { name: "objcopy".to_string(),
                                 exe: "objcopy".into(),
                                 args: [
                                     "--dump-section",
                                     &format!(".llvm_bitcode={}",
                                              "discard{section-file}"),
                                     "foo.obj",
                                     "discard{out-file}"
                                 ].map(OsString::from).to_vec(),
                                 dir: Some("/A/path".into()) }),
                     TestOp::SPO(
                       RunExec { name: "g++".to_string(),
                                 exe: "g++".into(),
                                 args: [
                                     "-E",
                                     "-g",
                                     "-O1",
                                     "-march=mips",  // kept because strict = true
                                     "-DDebug",
                                     "-o",
                                     &preproc_c_file,
                                     "bar.c"
                                 ].map(OsString::from).to_vec(),
                                 dir: Some("/A/path".into()) }),
                     TestOp::SPO(
                       RunExec { name: "clang:emit-llvm".to_string(),
                                 exe: "/path/to/clang".into(),
                                 args: [
                                     "-emit-llvm",
                                     "-c",
                                     "-g",
                                     "-Wno-error=unused-command-line-argument",
                                     "-Wno-error=implicit-function-declaration",
                                     "-arg1",
                                     "-arg2", "arg2val",
                                     "-g",
                                     "-O1",
                                     "-march=mips",  // kept because strict = true
                                     "-DDebug",
                                     "-o",
                                     "path/to/bitcode/foo.bc",
                                     &preproc_c_file,
                                 ].map(OsString::from).to_vec(),
                                 dir: Some("/A/path".into()) }),
                     TestOp::FO(
                         RunFunc { fname: "gen_bitcode_tar".to_string(),
                                   inpfiles: [
                                       PathBuf::from("path/to/bitcode/foo.bc"),
                                   ].to_vec(),
                                   outfile: Some(tarfile.clone()),
                                   dir: Some("/A/path".into()) }),
                     TestOp::SPO(
                         RunExec { name: "objcopy".to_string(),
                                   exe: "objcopy".into(),
                                   args: [
                                       "--add-section",
                                       &format!(".llvm_bitcode={}",
                                                tarfile.display()),
                                       "foo.obj"
                                   ].map(OsString::from).to_vec(),
                                   dir: Some("/A/path".into()) }),
                   ]);

        // ----------------------------------------------------------------------
        // Alternate cmdline specification
        let bcopts_notstrict = BCOpts { strict: false, ..bcopts_strict };
        bcopts_notstrict.executor.0.swap(&RefCell::new(vec![])); // clear trace
        let bcargs2 = build_bitcode_compile_only(&mut sender,
                                                 &bcopts_notstrict,
                                                 &OsString::from("mvcc"),
                                                 &[ "-ofoo.obj",
                                                      "-remove",
                                                      "-O",
                                                      "--this=remove-also",
                                                      "-DDebug",
                                                      "bar.c"
                                                 ].map(|s| s.into()),
                                                 &PathBuf::from("here"));
        match bcargs2 {
            Err(e) => assert_eq!(e.to_string(), "<no error expected>"),
            Ok(a) => {
                // output file:
                assert_eq!(a, "foo.obj");
                // channel messages:
                let chan_out1 = receiver.try_recv();
                match chan_out1 {
                    Ok(Some(Event::BitcodeGenerationAttempts)) => (),
                    o => assert!(false, "Unexpected channel output 1: {:?}", o),
                };
                let chan_out2 = receiver.try_recv();
                match chan_out2 {
                    Ok(Some(Event::BitcodeCaptured(pb))) =>
                        assert_eq!(pb, PathBuf::from("here/foo.obj")),
                    o => assert!(false, "Unexpected channel output 1: {:?}", o),
                };
                let chan_out3 = receiver.try_recv();
                assert!(chan_out3.is_err());
                assert_eq!(chan_out3.err(), Some(mpsc::TryRecvError::Empty));
            }
        }
        let captured2 = bcopts_notstrict.executor.0.borrow().clone();
        // Check temporary output files in the middle of the chain
        let preproc_c_file2 = match &captured2[1] {
            TestOp::SPO(ro) => ro.args[3].to_string_lossy().into(),  // I counted...
            _ => {
                assert!(false, "unexpected FPO at preproc step in {:?}", captured1);
                String::from("bad preprocessed c path")
            }
        };
        let tarfile = match &captured2[3] {
            TestOp::FO(rf) => match &rf.outfile {
                Some(tmp_path) => tmp_path.clone(),
                None => {
                    assert!(false, "no bitcode tarfile in {:?}", captured2);
                    PathBuf::from("bad tarfile path")
                },
            },
            _ => {
                assert!(false, "unexpected SPO at tarfile step in {:?}", captured2);
                PathBuf::from("bad tarfile path")
            }
        };
        // Verify full recorded sequence trace
        assert_eq!(captured2,
                   [ TestOp::SPO(
                       RunExec { name: "objcopy".to_string(),
                                 exe: "objcopy".into(),
                                 args: [
                                     "--dump-section",
                                     &format!(".llvm_bitcode={}",
                                              "discard{section-file}"),
                                     "foo.obj",
                                     "discard{out-file}"
                                 ].map(OsString::from).to_vec(),
                                 dir: Some("here".into()) }),
                     TestOp::SPO(
                       RunExec { name: "mvcc".to_string(),
                                 exe: "mvcc".into(),
                                 args: [
                                     "-E",
                                     "-DDebug",
                                     "-o",
                                     &preproc_c_file2,
                                     "bar.c"
                                 ].map(OsString::from).to_vec(),
                                 dir: Some("here".into()) }),
                     TestOp::SPO(
                       RunExec { name: "clang:emit-llvm".to_string(),
                                 exe: "/path/to/clang".into(),
                                 args: [
                                     "-emit-llvm",
                                     "-c",
                                     "-D__malloc__(X,Y)=",
                                     "-D__atomic_store(X,Y,Z)=",
                                     "-D__atomic_fetch_add(X,Y,Z)=0",
                                     "-D__atomic_fetch_sub(X,Y,Z)=0",
                                     "-D__atomic_fetch_and(X,Y,Z)=0",
                                     "-D__atomic_fetch_or(X,Y,Z)=0",
                                     "-D__atomic_compare_exchange(A,B,C,D,E,F)=0",
                                     "-D__atomic_exchange(A,B,C,D)=0",
                                     "-D__atomic_load(A,B,C)=0",
                                     "-g",
                                     "-O0",
                                     "-Wno-error=unused-command-line-argument",
                                     "-Wno-error=implicit-function-declaration",
                                     "-arg1",
                                     "-arg2", "arg2val",
                                     "-DDebug",
                                     "-o",
                                     "path/to/bitcode/foo.bc",
                                     &preproc_c_file2,
                                 ].map(OsString::from).to_vec(),
                                 dir: Some("here".into()) }),
                     TestOp::FO(
                         RunFunc { fname: "gen_bitcode_tar".to_string(),
                                   inpfiles: [
                                       PathBuf::from("path/to/bitcode/foo.bc"),
                                   ].to_vec(),
                                   outfile: Some(tarfile.clone()),
                                   dir: Some("here".into()) }),
                     TestOp::SPO(
                         RunExec { name: "objcopy".to_string(),
                                   exe: "objcopy".into(),
                                   args: [
                                       "--add-section",
                                       &format!(".llvm_bitcode={}",
                                                tarfile.display()),
                                       "foo.obj"
                                   ].map(OsString::from).to_vec(),
                                   dir: Some("here".into()) }),
                   ]);

        Ok(())
    }
}
