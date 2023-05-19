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

use regex::RegexSet;
use std::collections::HashMap;
use std::path::{Path,PathBuf};
use std::io::{Read, Write};
use std::fs::File;
use std::process;
use std::ffi::{OsString};
use std::os::unix::ffi::OsStringExt;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use sha2::{Digest,Sha256};
use thiserror::Error;

use crate::bom::options::{BitcodeOptions};
use crate::bom::syscalls::load_syscalls;
use crate::bom::event::RawString;
use crate::bom::proc_read::{read_str_from,read_str_list_from,read_environment,read_cwd};
use crate::bom::clang_support;
use crate::bom::chainsop::{ChainedSubOps, FileSpec, NamedFile, SubProcOperation};

#[derive(Error, Debug)]
pub enum TracerError {
    #[error("No tracee on top-level subprocess exit")]
    NoTraceeOnExit,
    #[error("Unexpected exit state on top-level subprocess exit")]
    UnexpectedExitState(pete::Stop),
    #[error("No command given")]
    NoCommandGiven
}

/// Options controlling bitcode generation that we need to plumb through most of the process
struct BCOpts<'a> {
    /// The clang command to use to generate bitcode
    clang_path : &'a OsString,
    /// If true, do *not* force the generation of debug information
    suppress_automatic_debug : bool,
    /// Arguments to inject when building bitcode
    inject_arguments : &'a Vec<String>,
    /// Arguments to remove when building bitcode
    remove_arguments : &'a RegexSet,
    /// Strict: maintain strict adherence between the bitcode and the target code
    /// (optimization, target architecture, etc.)
    strict : bool
}

pub fn bitcode_entrypoint(bitcode_options : &BitcodeOptions) -> anyhow::Result<i32> {
    if bitcode_options.command.len() == 0 {
        return Err(anyhow::Error::new(TracerError::NoCommandGiven));
    }

    let (cmd0, args0) = bitcode_options.command.split_at(1);
    let cmd_path = which::which(OsString::from(&cmd0[0]))?;

    let mut cmd = Command::new(cmd_path);
    cmd.args(args0);
    let mut ptracer = pete::Ptracer::new();

    // Spawn the subprocess for the command and start it (it starts off
    // suspended to allow the ptracing process to attach)
    let _child = ptracer.spawn(cmd);
    match ptracer.wait()? {
        None => {
            println!("Error spawning tracee (command: {})", bitcode_options.command.join(" "));
        }
        Some(tracee) => {
            ptracer.restart(tracee, pete::Restart::Syscall)?;
        }
    }

    let (mut sender, receiver) = mpsc::channel();
    let stream_output = bitcode_options.verbose;
    let event_consumer = thread::spawn(move || { collect_events(stream_output, receiver) });

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

    let bc_opts = BCOpts { clang_path : &bitcode_options.clang_path.as_ref().map(|s| OsString::from(s.as_path().as_os_str()))
                                                        .unwrap_or(OsString::from("clang")),
                           suppress_automatic_debug : bitcode_options.suppress_automatic_debug,
                           inject_arguments : &bitcode_options.inject_arguments,
                           remove_arguments : &remove_rx,
                           strict : bitcode_options.strict
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
    print_summary(summary);

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

struct BitcodeArguments {
    ops : ChainedSubOps,
    resolved_object_target : OsString
}

/// Given original arguments (excluding argv[0]), construct the command line we
/// will pass to clang to build bitcode
///
/// This handles removing flags that clang can't handle (or that we definitely
/// do not want for bitcode generation), as well as transforming the output file
/// path
fn build_bitcode_arguments(chan : &mut mpsc::Sender<Option<Event>>,
                           bc_opts : &BCOpts,
                           orig_args : &[OsString]) -> anyhow::Result<BitcodeArguments> {
    let mut orig_target = None;
    let ops = ChainedSubOps::new();

    let gen_bitcode = ops.push_op(
        SubProcOperation::new(
            &bc_opts.clang_path,
            // Input file specification is not necessary: these will be collected
            // from the orig_args as they are processed.
            &FileSpec::Unneeded,
            &FileSpec::Option(String::from("-o"), NamedFile::temp(".bc"))));

    // We always need to add this key flag
    gen_bitcode.push_arg("-emit-llvm");
    // Always add the -c flag; if we don't, bitcode built from a compile command
    // that doesn't already specify -c, it will fail because you cannot specify
    // -emit-llvm when generating an executable
    gen_bitcode.push_arg("-c");

    // Force debug information (unless directed not to)
    if !bc_opts.suppress_automatic_debug {
        gen_bitcode.push_arg("-g");
    }

    // If not in strict mode, explicitly disable optimization (favoring a maximal
    // amount of information in the generated bitcode and avoiding things like
    // inlining, dead code elimination, etc.
    if !bc_opts.strict {
        gen_bitcode.push_arg("-O0");
    }

    // Sometimes -Werror might be in the arguments, so make sure this doesn't
    // cause a failure exit if any other command-line arguments are unused.
    gen_bitcode.push_arg("-Wno-error=unused-command-line-argument");

    // Add any arguments that the user directed us to
    let mut add_it = bc_opts.inject_arguments.iter();
    while let Some(arg) = add_it.next() {
        gen_bitcode.push_arg(arg);
    }

    // Next, copy over all of the flags we want to keep
    let mut it = orig_args.iter();
    let mut skip_next = false;
    while let Some(arg) = it.next() {
        // Skip value argument to a previous blacklisted argument
        if skip_next {
            skip_next = false;
            continue;
        }

        // Skip any arguments explicitly blacklisted
        if clang_support::is_blacklisted_clang_argument(bc_opts.strict, arg) {
            skip_next = clang_support::next_arg_is_option_value(arg);
            continue;
        }

        if arg.to_str().map_or(false, |s| bc_opts.remove_arguments.is_match(s)) {
            // Reject arguments matching any of the user-provided regexes.  Note
            // that this is of course as unsafe as users make it.  In
            // particular, rejecting '-o' would be very bad.
            skip_next = clang_support::next_arg_is_option_value(arg);  // hopeful here...
            continue;
        } else {
            if ! arg.to_str().unwrap().starts_with("-o") {
                gen_bitcode.push_arg(arg);
            }
        }

        // If the argument specifies the output file, we need to munge the name
        // of the output file (which is either the remainder of this argument or
        // the next argument) to have an appropriate extension and to put it in
        // the requested bitcode directory (if any)
        if arg.to_str().unwrap().starts_with("-o") {
            if arg == "-o" {
                match it.next() {
                    None => {
                        return Err(anyhow::Error::new(BitcodeError::MissingOutputFile(Path::new(&bc_opts.clang_path).to_path_buf(), Vec::from(orig_args))));
                    }
                    Some(target) => {
                        orig_target = Some(PathBuf::from(&target).into_os_string());
                    }
                }
            } else {
                let (_,tgt) = arg.to_str().unwrap().split_at(2);
                orig_target = Some(OsString::from(tgt));
            }
        }
    }

    let resolved_object_target;
    match orig_target {
        Some(t) => {
            // We found a target explicitly specified with -o
            resolved_object_target = t.clone();
            ops.set_out_file_for_chain(&Some(PathBuf::from(t)));
        }
        None => {
            // There was no explicitly-specified object file.  If there was a
            // single input source file, the object file name will be that input
            // source with the extension replaced by .o.
            match input_sources(orig_args) {
                Ok(source_file) => {
                    let mut target_path = PathBuf::from(source_file);
                    target_path.set_extension("o");
                    resolved_object_target = OsString::from(target_path.clone());
                    ops.set_out_file_for_chain(&Some(PathBuf::from(target_path)));
                }
                Err(msg) => {
                    let _res = chan.send(Some(Event::MultipleInputsWithImplicitOutput(bc_opts.clang_path.to_os_string(), orig_args.to_vec())));
                    return Err(anyhow::Error::new(msg));
                }
            }
        }
    }

    let res = BitcodeArguments {
        ops,
        resolved_object_target,
    };
    Ok(res)
}

fn build_bitcode_compile_only(chan : &mut mpsc::Sender<Option<Event>>,
                              bc_opts : &BCOpts,
                              args : &[OsString],
                              orig_compiler_cmd : &OsString,
                              cwd : &Path
) -> anyhow::Result<()> {
    let mut bc_args = build_bitcode_arguments(chan, bc_opts, args)?;

    match bc_args.ops.out_file_for_chain() {

        // Not typical: this means that the argument analysis performed above
        // could not identify an explicit output file or an implicit output
        // file determined by identifying an input file.
        None =>
            return Err(anyhow::Error::new(
                BitcodeError::MissingOutputFile(orig_compiler_cmd.into(),
                                                args.to_vec()))),

        Some(f) => {
            let fstr = f.clone().into_os_string();
            if !obj_already_has_bitcode(cwd, &fstr) {
                let _res = chan.send(Some(Event::BitcodeGenerationAttempts));
                let bctarget = bc_args.resolved_object_target.clone();
                attach_bitcode(cwd, &mut bc_args, &bctarget)?;
                let ops_result = bc_args.ops.execute(&Some(cwd));
                match ops_result {
                    Err(e) => {
                        let _ = // Ignore chan.send errors
                            chan.send(Some(Event::BitcodeGenerationError(f, e)));
                        // Errors are discarded here (bitcode generation behind
                        // the scenes).  If errors in the bitcode generation
                        // should fail the build-bom run, this is handled at the
                        // end where the chan.send statistics are evaluated.
                    }
                    Ok(_) =>
                        chan.send(Some(Event::BitcodeCaptured(PathBuf::from(&bctarget))))?
                }
            }
        }
    }

    Ok(())
}

/// Convert the (potentially relative) path to an absolute path
///
/// If the `partial_path` is already absolute, just return it.
///
/// Otherwise, make the path absolute by prefixing the `cwd`.
fn to_absolute(cwd : &Path, partial_path : &OsString) -> PathBuf {
    let mut p = PathBuf::new();
    let partial = Path::new(partial_path);
    if partial.is_absolute() {
        p.push(partial_path);
        p
    } else {
        // NOTE: Investigate this - PathBuf.push replaces the original root if
        // the thing pushed is absolute - we can probably just use that behavior
        p.push(cwd);
        p.push(partial_path);
        p
    }
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
    #[error("Error generating bitcode with command {0:?} {1:?}")]
    ErrorGeneratingBitcode(PathBuf, Vec<OsString>),
    #[error("Error {2:?} generating bitcode with command {0:?} {1:?}")]
    ErrorCodeGeneratingBitcode(PathBuf, Vec<OsString>, std::io::Error),
    #[error("Unreadable memory address {0:}")]
    UnreadableMemoryAddress(u64),
    #[error("No input file found in compilation from args {0:?}")]
    NoInputFileFound(Vec<OsString>),
    #[error("Multiple input files found for command: files {0:?} from args {1:?}")]
    MultipleInputFiles(Vec<String>, Vec<OsString>)
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
fn obj_already_has_bitcode(cwd : &Path, obj_target : &OsString) -> bool {
    match process::Command::new("objdump")
        .args(&["-h", "-j", ELF_SECTION_NAME,
                &obj_target.to_str().unwrap()])
        .current_dir(cwd)
        .output() {
            Err(err) => {
                println!("Error checking {:?} section existence: {:?}", ELF_SECTION_NAME, err);
                // TODO something else here?  another event?
                false
            }
            Ok(sts) => {
                // n.b. ignore success or failure of the command
                // because different objdump builds have different
                // results: the gnu objdump tends to fail with a
                // non-zero exit code, but the llvm objdump simply
                // generates a warning and exits with success).
                match std::str::from_utf8(&sts.stderr) {
                    Ok(estr) => {
                        estr.lines()
                            .filter(|l| (l.contains(&format!("section '{}' mentioned",
                                                             ELF_SECTION_NAME))
                                         && l.contains("but not found in any input file")))
                            .collect::<Vec<&str>>()
                            .is_empty()
                    }
                    Err(_) => { false }
                }
            }
        }
}

/// Given the name (path) of a tar file on disk, use objcopy to inject it into
/// the distinguished ELF section for holding the bitcode (see `ELF_SECTION_NAME`)
fn inject_bitcode(bc_args : &mut BitcodeArguments) -> anyhow::Result<()> {
    let objcopy = bc_args.ops.push_op(
        SubProcOperation::new(
            &"objcopy",
            &FileSpec::Replace(String::from("INPFILE"), NamedFile::temp("")),
            &FileSpec::Append(NamedFile::temp(".o"))));

    objcopy.push_arg("--add-section");
    objcopy.push_arg(format!("{}=INPFILE", ELF_SECTION_NAME));
    Ok(())
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
fn build_bitcode_tar<T: Write>(bc_target : &OsString,
                               bc_path : &Path,
                               hash : &OsString,
                               tar_file : T) -> anyhow::Result<()> {
    let mut tb = tar::Builder::new(tar_file);
    let bc_target_path = Path::new(bc_target);


    let mut archived_name = OsString::new();
    archived_name.push(bc_target_path.file_stem().unwrap());
    archived_name.push("-");
    archived_name.push(hash);
    archived_name.push(".");
    archived_name.push(bc_target_path.extension().unwrap());

    tb.append_path_with_name(bc_path, &archived_name)?;
    tb.into_inner()?;

    Ok(())
}

/// Attach the bitcode file at the given path to its associated object file target
///
/// We pass in the working directory in which the objects were constructed so
/// that we can generate appropriate commands (in terms of absolute paths) so
/// that we don't need to worry about where we are replaying the build from.
fn attach_bitcode(cwd : &Path,
                  bc_args : &mut BitcodeArguments,
                  bc_target : &OsString) -> anyhow::Result<()> {
    let mktar = bc_args.ops.push_op(
        SubProcOperation::calling(
            |_cwd, args|
            build_bitcode_tar(&args[0],
                              &PathBuf::from(args[2].clone()).as_path(),
                              &args[1],
                              File::create(PathBuf::from(args[3].clone()).as_path())?)));
    // Define the args in the order that matches the args in the calling() above.
    mktar.set_input(&FileSpec::Append(NamedFile::temp("")));
    mktar.set_output(&FileSpec::Append(NamedFile::temp(".tar")));
    let mut reprname = bc_args.ops.out_file_for_chain().unwrap_or(PathBuf::from("unk.bc"));
    reprname.set_extension("bc");
    mktar.push_arg(reprname);

    // To avoid name collisions on extract_bitcode unpack, each filename in the
    // tarfile should be unique.  Generate a hash of the contents to help provide
    // uniqueness to the name.
    {
        let mut hasher = Sha256::new();
        let mut bc_content = Vec::new();
        let bc_path = to_absolute(cwd, bc_target);
        let mut bc_file = std::fs::File::open(&bc_path)?;
        bc_file.read_to_end(&mut bc_content)?;
        hasher.update(bc_content);
        let hash = hasher.finalize();
        mktar.push_arg(hex::encode(hash.as_slice()));
    }

    inject_bitcode(bc_args)
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

fn collect_events(stream_errors : bool, chan : mpsc::Receiver<Option<Event>>) -> SummaryStats {
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
                println!("Event collector exiting early due to error: {:?}", err_msg);
                return summary;
            }
            Ok(None) => { return summary }
            Ok(Some(evt)) => {
                match evt {
                    Event::PipeInputOrOutput(cmd) => {
                        summary.num_pipe_io += 1;
                        if stream_errors {
                            println!("Pipe I/O in command '{:?} {:?}'", cmd.bin, cmd.args);
                        }
                    }
                    Event::ResponseFile(cmd) => {
                        summary.num_responsefile += 1;
                        if stream_errors {
                            println!("Response file in command '{:?} {:?}'", cmd.bin, cmd.args);
                        }
                    }
                    Event::MultipleInputsWithImplicitOutput(cmd, args) => {
                        summary.unresolved_implicit_outputs += 1;
                        if stream_errors {
                            println!("Unresolved implicit outputs with multiple input files in command '{:?} {:?}'", cmd, args);
                        }
                    }
                    Event::BuildFailureSkippedBitcode(cmd, exit_code) => {
                        summary.build_failures_skipping_bitcode += 1;
                        if stream_errors {
                            println!("Skipping bitcode generation due to failed compile command '{:?} {:?} = {}'", cmd.bin, cmd.args, exit_code);
                        }
                    }
                    Event::BuildFailureUnknownEffect(cmd, exit_code) => {
                        summary.build_failures_unknown_effect += 1;
                        if stream_errors {
                            println!("Failed compile command may affect bitcode coverage '{:?} {:?} = {}'", cmd.bin, cmd.args, exit_code);
                        }
                    }
                    Event::SkippingAssembleOnlyCommand(cmd) => {
                        summary.skipping_assemble_only += 1;
                        if stream_errors {
                            println!("Skipping bitcode generation for assemble-only command '{:?} {:?}'", cmd.bin, cmd.args);
                        }
                    }
                    Event::BitcodeGenerationError(on_file, err) => {
                        summary.bitcode_compile_errors += 1;
                        if stream_errors {
                            println!("Error while generating bitcode for {:?}: {}",
                                     on_file, err);
                        }
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
            println!("Error decoding strings to build command: {:?}", msg);
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
                println!("Missing expected exec command for process id {}", ipid);
            }
            Some(ProcessState::TryExec(rc)) => {
                process_state.insert(ipid, ProcessState::FinishExec(rc));
            }
            Some(ProcessState::FinishExec(rc)) => {
                println!("Unexpected finish event for already finished command {:?}", rc);
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
                       bc_opts : &BCOpts
) {
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


/// Returns true if we should make bitcode given this command
fn should_make_bc(rc : &RunCommand, comp_mods : &CompileModifiers) -> bool {
    let cmd_path = Path::new(&rc.bin);
    match cmd_path.file_name() {
        None => { false }
        Some(cmd_file_name) => {
            clang_support::is_compile_command_name(cmd_file_name) && // Is this a compile command we recognize
                !comp_mods.is_pipe_io &&                             // Pipe input can't be re-processed a second time (so generating bitcode would fail; the pipe is already drained)
                !comp_mods.is_assemble_only &&                       // In an assemble-only build, there is no object file to attach the bitcode to
                !comp_mods.is_pre_proc_only &&                       // Similarly, in a preprocess only build we have no object file to attach bitcode to
                !comp_mods.is_non_generative
        }
    }
}

/// Determine what actions should be taken on the successful execution
/// completion of a build process action.
fn post_process_actions(rc : RunCommand,
                        chan : &mut mpsc::Sender<Option<Event>>,
                        bc_opts : &BCOpts
) {
    let comp_mods = extract_compile_modifiers(&rc);
    if should_make_bc(&rc, &comp_mods) {
        // If this is a command we can build bitcode for, do
        // it.  We wait until the exec'd process exits
        // because we need the original object file to exist
        // (so that we can attach the bitcode).
        //
        // We drop the first argument because it is just the
        // original command name (i.e., argv[0])
        let (_, rest_args) = rc.args.split_at(1);
        match build_bitcode_compile_only(chan, bc_opts, rest_args, &rc.bin, &rc.cwd) {
            Err(err) => { println!("Error building bitcode: {:?}", err) }
            Ok(_) => {}
        }
    } else {
        // Bump a summary stat indicating a reason why this compile could not
        // attempt to generate bitcode.  Ignore situations where there wouldn't
        // have been any object code generated anyhow (e.g. pre-processor-only,
        // etc.).
        if !comp_mods.is_pre_proc_only {
            if comp_mods.is_pipe_io {
                // Ignore send failures... that really shouldn't happen and
                // we don't want to kill the tracer thread.
                let _res = chan.send(Some(Event::PipeInputOrOutput(rc.clone())));
            }
            if comp_mods.is_response_file {
                let _res = chan.send(Some(Event::ResponseFile(rc.clone())));
            }

            if comp_mods.is_assemble_only {
                let _res = chan.send(Some(Event::SkippingAssembleOnlyCommand(rc)));
            }
        }
    }
}


fn generate_bitcode(chan : &mut mpsc::Sender<Option<Event>>,
                    mut ptracer : pete::Ptracer,
                    bc_opts : &BCOpts
) -> anyhow::Result<(pete::Ptracer, i32)> {
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


#[cfg(test)]
mod tests {

    use std::sync::mpsc;
    use super::*;

    #[test]
    fn test_bitcode_compile_args() -> anyhow::Result<()> {
        let (mut sender, receiver) = mpsc::channel();
        let mut bcdir = PathBuf::new();
        bcdir.push("path");
        bcdir.push("to");
        bcdir.push("bitcode");
        let bcopts = BCOpts { clang_path: &"/path/to/clang".into(),
                              suppress_automatic_debug: false,
                              inject_arguments: &Vec::from(
                                  [ "-arg1",
                                      "-arg2",
                                      "arg2val"
                                  ].map(|s| String::from(s))),
                              remove_arguments: &regex::RegexSet::new(
                                  [r"^-remove$", r"^--this" ],

                              ).unwrap(),
                              strict: false };

        // Simple cmdline specification
        let args = [ "-g", "-O1", "-o", "foo.obj",
                       "-march=mips",
                       "-DDebug",
                       "bar.c" ].map(|s| s.into());
        let bcargs1 = build_bitcode_arguments(&mut sender, &bcopts, &args);
        match bcargs1 {
            Err(e) => assert_eq!(e.to_string(), "<no error expected>"),
            Ok(a) => {
                // This isn't a great way to check the contents of a
                // ChainedSubOp, but since the alternative is exposing a lot more
                // of the internals through the API, it's probably good enough.
                assert_eq!(format!("{:?}", a.ops),
                           "ChainedSubProcOperations \
                            { chain: [\
                                SubProcOperation \
                                { cmd: \"/path/to/clang\", \
                                  args: [\"-emit-llvm\", \
                                         \"-c\", \
                                         \"-g\", \
                                         \"-O0\", \
                                         \"-Wno-error=unused-command-line-argument\", \
                                         \"-arg1\", \
                                         \"-arg2\", \
                                         \"arg2val\", \
                                         \"-g\", \
                                         \"-DDebug\", \
                                         \"bar.c\"], \
                                  inp_file: Unneeded, \
                                  out_file: Option(\"-o\", Temp(\".bc\")), \
                                  in_dir: None \
                                }], \
                              initial_inp_file: None, \
                              final_out_file: Some(\"foo.obj\"), \
                              disabled: [] \
                            }");
                assert_eq!(a.resolved_object_target, "foo.obj");
                let chan_out = receiver.try_recv();
                assert!(chan_out.is_err());
                assert_eq!(chan_out.err(), Some(mpsc::TryRecvError::Empty));
            }
        }

        // Simple cmdline specification, strict bitcode
        let bcopts_strict = BCOpts { strict: true, ..bcopts };
        let bcargs1 = build_bitcode_arguments(&mut sender, &bcopts_strict, &args);
        match bcargs1 {
            Err(e) => assert_eq!(e.to_string(), "<no error expected>"),
            Ok(a) => {
                assert_eq!(format!("{:?}", a.ops),
                           "ChainedSubProcOperations \
                            { chain: [\
                                SubProcOperation \
                                { cmd: \"/path/to/clang\", \
                                  args: [\"-emit-llvm\", \
                                         \"-c\", \
                                         \"-g\", \
                                         \"-Wno-error=unused-command-line-argument\", \
                                         \"-arg1\", \
                                         \"-arg2\", \
                                         \"arg2val\", \
                                         \"-g\", \
                                         \"-O1\", \
                                         \"-march=mips\", \
                                         \"-DDebug\", \
                                         \"bar.c\"], \
                                  inp_file: Unneeded, \
                                  out_file: Option(\"-o\", Temp(\".bc\")), \
                                  in_dir: None \
                                }], \
                              initial_inp_file: None, \
                              final_out_file: Some(\"foo.obj\"), \
                              disabled: [] \
                            }");
                assert_eq!(a.resolved_object_target, "foo.obj");
                let chan_out = receiver.try_recv();
                assert!(chan_out.is_err());
                assert_eq!(chan_out.err(), Some(mpsc::TryRecvError::Empty));
            }
        }

        // Alternate cmdline specification
        let bcargs2 = build_bitcode_arguments(&mut sender, &bcopts,
                                              &[ "-ofoo.obj",
                                                   "-remove",
                                                   "-O",
                                                   "--this=remove-also",
                                                   "-DDebug",
                                                   "bar.c"
                                              ].map(|s| s.into()));
        match bcargs2 {
            Err(e) => assert_eq!(e.to_string(), "<no error expected>"),
            Ok(a) => {
                assert_eq!(format!("{:?}", a.ops),
                           "ChainedSubProcOperations \
                            { chain: [\
                                SubProcOperation \
                                { cmd: \"/path/to/clang\", \
                                  args: [\"-emit-llvm\", \
                                         \"-c\", \
                                         \"-g\", \
                                         \"-O0\", \
                                         \"-Wno-error=unused-command-line-argument\", \
                                         \"-arg1\", \
                                         \"-arg2\", \
                                         \"arg2val\", \
                                         \"-DDebug\", \
                                         \"bar.c\"], \
                                  inp_file: Unneeded, \
                                  out_file: Option(\"-o\", Temp(\".bc\")), \
                                  in_dir: None \
                                }], \
                              initial_inp_file: None, \
                              final_out_file: Some(\"foo.obj\"), \
                              disabled: [] \
                            }");
                assert_eq!(a.resolved_object_target, "foo.obj");
                let chan_out = receiver.try_recv();
                assert!(chan_out.is_err());
                assert_eq!(chan_out.err(), Some(mpsc::TryRecvError::Empty));
            }
        }

        Ok(())
    }
}
