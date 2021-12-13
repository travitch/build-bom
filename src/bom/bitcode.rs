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
// * syscall_enter -- if this is an execve syscall, the execve target
//                    may be a clang invocation on a source code file.
//                    At syscall entry, the cmdline arguments are
//                    captured for that determination later.
//
// * syscall_exit -- if this is the exit from an execve syscall and it
//                   failed, the preserved arguments from above can be
//                   discarded.  Note that even if this is an execve,
//                   the syscall has returned to the *original*
//                   executable (albeit to libc library code therein),
//                   so this does *not* represent successfull
//                   completion of the exec'd target (which may or may
//                   not be clang).  Thus, a successful syscall_exit
//                   leaves the cmdline argument information available
//                   and is otherwise ignored.
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

use std::collections::HashMap;
use std::path::{Path,PathBuf};
use std::io::Read;
use std::process;
use std::ffi::{OsStr,OsString};
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

#[derive(Error, Debug)]
pub enum TracerError {
    #[error("No tracee on top-level subprocess exit")]
    NoTraceeOnExit,
    #[error("Unexpected exit state on top-level subprocess exit")]
    UnexpectedExitState(pete::Stop)
}

pub fn bitcode_entrypoint(bitcode_options : &BitcodeOptions) -> anyhow::Result<i32> {
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
            println!("Error spawning tracee");
        }
        Some(tracee) => {
            ptracer.restart(tracee, pete::Restart::Syscall)?;
        }
    }

    let (mut sender, receiver) = mpsc::channel();
    let stream_output = bitcode_options.verbose;
    let event_consumer = thread::spawn(move || { collect_events(stream_output, receiver) });
    let clang_path = bitcode_options.clang_path.as_ref().map(|s| OsString::from(s.as_path().as_os_str()))
                                                        .unwrap_or(OsString::from("clang"));
    let mut ptracer1 = generate_bitcode(&mut sender, ptracer, clang_path.as_ref(), bitcode_options.bcout_path.as_ref())?;

    // Send a token to shut down the event collector thread
    sender.send(None)?;
    let summary = event_consumer.join().unwrap();
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

    let (mut last_ptracer, exitcode) = ptracer1;
    let tracee = last_ptracer.wait()?;
    match tracee {
        None => { Ok(exitcode) }
        Some(t) =>
            match t.stop {
                pete::Stop::Exiting { exit_code: ec } => { Ok(ec) }
                _ => { Err(anyhow::anyhow!(TracerError::UnexpectedExitState(t.stop))) }
            }
    }
}

#[derive(Debug)]
pub enum Event {
    PipeInputOrOutput(RunCommand),
    ResponseFile(RunCommand),
    MultipleInputsWithImplicitOutput(OsString,Vec<OsString>),
    BuildFailureSkippedBitcode(RunCommand, i32),
    BuildFailureUnknownEffect(RunCommand, i32),
    SkippingAssembleOnlyCommand(RunCommand),
    BitcodeCompileError(PathBuf, Vec<OsString>,Vec<u8>,Vec<u8>,Option<i32>),
    BitcodeAttachError(PathBuf, Vec<OsString>,Vec<u8>,Vec<u8>,Option<i32>),
    BitcodeGenerationAttempts,
    BitcodeCaptured(PathBuf)
}

fn build_bitcode_compile_only(chan : &mut mpsc::Sender<Option<Event>>,
                              bc_command : &OsStr,
                              args : &[OsString],
                              cwd : &Path,
                              bcdir : Option<&PathBuf>
) -> anyhow::Result<()> {
    let mut orig_target = None;
    let mut new_target = OsString::from("");
    let mut modified_args = Vec::new() as Vec<OsString>;
    modified_args.push(OsString::from("-emit-llvm"));
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        // Skip any argument on the clang argument blacklist
        if clang_support::is_blacklisted_clang_argument(arg) {
            continue;
        }

        modified_args.push(OsString::from(arg.to_owned()));
        if arg == "-o" {
            match it.next() {
                None => {
                    return Err(anyhow::Error::new(BitcodeError::MissingOutputFile(Path::new(bc_command).to_path_buf(), Vec::from(args))));
                }
                Some(target) => {
                    orig_target = Some(PathBuf::from(&target).into_os_string());
                    let mut target_path = match bcdir {
                        None => PathBuf::from(&target),
                        Some(p) => {
                            let mut pp = PathBuf::from(&p);
                            pp.push(&PathBuf::from(&target).file_name()
                                    .expect("target is not a file"));
                            pp
                        }
                    };
                    target_path.set_extension("bc");
                    new_target = OsString::from(target_path.clone());
                    modified_args.push(target_path.into_os_string());
                }
            }
        }
    }

    let resolved_object_target;
    let resolved_bitcode_target;
    match orig_target {
        Some(t) => {
            // We found a target explicitly specified with -o
            resolved_object_target = t;
            resolved_bitcode_target = new_target;
        }
        None => {
            // There was no explicitly-specified object file.  If there was a
            // single input source file, the object file name will be that input
            // source with the extension replaced by .o.
            match input_sources(args) {
                Ok(source_file) => {
                    let mut target_path = PathBuf::from(source_file);
                    target_path.set_extension("o");
                    resolved_object_target = OsString::from(target_path.clone());
                    let mut bc_path = target_path;
                    bc_path.set_extension("bc");
                    resolved_bitcode_target = OsString::from(bc_path.clone());
                }
                Err(msg) => {
                    let _res = chan.send(Some(Event::MultipleInputsWithImplicitOutput(bc_command.to_os_string(), args.to_vec())));
                    return Err(anyhow::Error::new(msg));
                }
            }
        }
    }

    if !obj_already_has_bitcode(cwd, &resolved_object_target) {
        let _res = chan.send(Some(Event::BitcodeGenerationAttempts));

        let child = process::Command::new(&bc_command).
            args(&modified_args).
            current_dir(cwd).
            stdout(process::Stdio::piped()).
            stderr(process::Stdio::piped()).
            spawn()?;
        let out = child.wait_with_output()?;
        if out.status.success() {
            attach_bitcode(chan, cwd, &resolved_object_target, &resolved_bitcode_target)?;
        } else {
            let err = Event::BitcodeCompileError(Path::new(bc_command).to_path_buf(),
                                                 Vec::from(modified_args.clone()),
                                                 out.stdout,
                                                 out.stderr,
                                                 out.status.code());
            let _res = chan.send(Some(err))?;
            return Err(anyhow::Error::new(BitcodeError::ErrorGeneratingBitcode(Path::new(bc_command).to_path_buf(),
                                                                               Vec::from(modified_args))));
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
        if clang_support::is_unary_option(arg) {
            // Discard the next argument since it can't be a source file
            let _next_arg = it.next();
        } else if clang_support::is_nullary_option(arg) {
            // Just ignore it
        } else {
            // This is an argument
            inputs.push(arg);
        }
    }

    if inputs.len() == 1 {
        Ok(inputs[0])
    } else {
        Err(BitcodeError::MultipleInputFiles(inputs.iter().map(|s| s.to_string_lossy().into_owned()).collect()))
    }
}

#[derive(thiserror::Error,Debug)]
pub enum BitcodeError {
    #[error("Error attaching bitcode file '{2:?}' to '{1:?}' in {0:?} ({3:?} / {4:?})")]
    ErrorAttachingBitcode(PathBuf, OsString, OsString, std::io::Error, String),
    #[error("Missing output file in command {0:?} {1:?}")]
    MissingOutputFile(PathBuf, Vec<OsString>),
    #[error("Error generating bitcode with command {0:?} {1:?})")]
    ErrorGeneratingBitcode(PathBuf, Vec<OsString>),
    #[error("Unreadable memory address {0:}")]
    UnreadableMemoryAddress(u64),
    #[error("Multiple input files found for command: {0:?}")]
    MultipleInputFiles(Vec<String>)
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


/// Attach the bitcode file at the given path to its associated object file target
///
/// We pass in the working directory in which the objects were constructed so
/// that we can generate appropriate commands (in terms of absolute paths) so
/// that we don't need to worry about where we are replaying the build from.
fn attach_bitcode(chan : &mut mpsc::Sender<Option<Event>>,
                  cwd : &Path,
                  orig_target : &OsString,
                  bc_target : &OsString) -> anyhow::Result<()> {
    let object_path = to_absolute(cwd, orig_target);
    let bc_path = to_absolute(cwd, bc_target);

    let mut hasher = Sha256::new();
    let mut bc_content = Vec::new();
    let mut bc_file = std::fs::File::open(&bc_path)?;
    bc_file.read_to_end(&mut bc_content)?;
    hasher.update(bc_content);
    let hash = hasher.finalize();

    let mut tar_file = tempfile::NamedTempFile::new()?;
    let tar_name = OsString::from(tar_file.path());
    let mut tb = tar::Builder::new(&mut tar_file);
    // Create a singleton tar file with the bitcode file.
    //
    // We use the original relative name to make it easy to unpack.
    //
    // In most cases, this should avoid duplicates, but it is possible that
    // there could be collisions if the build system does a lot of changing of
    // directories with source files that have similar names.
    //
    // To avoid collisions, we append a hash to each filename
    let bc_target_path = Path::new(bc_target);
    let mut archived_name = OsString::new();
    archived_name.push(bc_target_path.file_stem().unwrap());
    archived_name.push("-");
    archived_name.push(hex::encode(hash));
    archived_name.push(".");
    archived_name.push(bc_target_path.extension().unwrap());

    tb.append_path_with_name(bc_path, &archived_name)?;
    tb.into_inner()?;

    let mut objcopy_args = Vec::new();
    objcopy_args.push(OsString::from("--add-section"));
    let ok_tar_name = tar_name.into_string().ok().unwrap();
    objcopy_args.push(OsString::from(format!("{}={}", ELF_SECTION_NAME, ok_tar_name)));
    objcopy_args.push(object_path.into_os_string());

    match process::Command::new("objcopy").args(&objcopy_args).stdout(process::Stdio::piped()).stderr(process::Stdio::piped()).current_dir(cwd).spawn() {
        Err(msg) => {
            match process::Command::new("objcopy")
                .arg("--version")
                .stdout(process::Stdio::piped())
                .stderr(process::Stdio::piped())
                .spawn() {
                    Ok(child) => {
                        let ver = child.wait_with_output()?;
                        if !ver.status.success() {
                            return Err(anyhow::Error::new(
                                BitcodeError::ErrorAttachingBitcode(
                                    cwd.to_path_buf(),
                                    orig_target.clone(),
                                    bc_target.clone(),
                                    msg,
                                    format!("objcopy failed to return version\n{:?}\nErr: {:?}",
                                            ver.stdout, ver.stderr)
                                )));
                        }
                        return Err(anyhow::Error::new(
                            BitcodeError::ErrorAttachingBitcode(
                                cwd.to_path_buf(),
                                orig_target.clone(),
                                bc_target.clone(),
                                msg,
                                format!("{:?}\nErr: {:?}", ver.stdout, ver.stderr)
                            )));
                    }
                    Err(vermsg) => {
                        return Err(anyhow::Error::new(
                            BitcodeError::ErrorAttachingBitcode(
                                cwd.to_path_buf(),
                                orig_target.clone(),
                                bc_target.clone(),
                                msg,
                                format!("objcopy --version run failed: {}", vermsg))));
                    }
                }
        }
        Ok(child) => {
            let out = child.wait_with_output()?;
            if !out.status.success() {
                let err = Event::BitcodeAttachError(Path::new("objcopy").to_path_buf(),
                                                    Vec::from(objcopy_args),
                                                    out.stdout,
                                                    out.stderr,
                                                    out.status.code());
                let _res = chan.send(Some(err))?;
            } else {
                    let _res = chan.send(Some(Event::BitcodeCaptured(bc_target_path.to_path_buf())));
            }

            Ok(())
        }
    }
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
                    Event::BitcodeCompileError(cmd, args, stdout, stderr, exit_code) => {
                        summary.bitcode_compile_errors += 1;
                        if stream_errors {
                            println!("Error while compiling bitcode ('{:?} {:?}' = {:?})", cmd, args, exit_code);
                            println!("  stdout: {}", String::from_utf8_lossy(&stdout).into_owned());
                            println!("  stderr: {}", String::from_utf8_lossy(&stderr).into_owned());
                        }
                    }
                    Event::BitcodeAttachError(cmd, args, stdout, stderr, exit_code) => {
                        summary.bitcode_attach_errors += 1;
                        if stream_errors {
                            println!("Error while attaching bitcode ('{:?} {:?}' = {:?})", cmd, args, exit_code);
                            println!("  stdout: {}", String::from_utf8_lossy(&stdout).into_owned());
                            println!("  stderr: {}", String::from_utf8_lossy(&stderr).into_owned());
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
                       clang_path : &OsStr,
                       bcout_path : Option<&PathBuf>
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
            post_process_actions(rc, chan, clang_path, bcout_path);
        }
    }
}

/// Determine what actions should be taken on the successful execution
/// completion of a build process action.
fn post_process_actions(rc : RunCommand,
                        chan : &mut mpsc::Sender<Option<Event>>,
                        clang_path : &OsStr,
                        bcout_path : Option<&PathBuf>
) {
    let cmd_path = Path::new(&rc.bin);
    let mut has_compile_only_flag = false;
    let mut has_pipe_io = false;
    let mut has_responsefile = false;
    let mut is_assemble_only = false;
    let mut is_pre_proc_only = false;
    for arg in &rc.args {
        has_compile_only_flag = has_compile_only_flag || arg == "-c";
        // We want to recognize cases where the compilation
        // input is stdin or the output is stdout; we can't
        // replicate those build steps since we don't know
        // where either is really going to/coming from.
        has_pipe_io = has_pipe_io || arg == "-";
        // We could potentially track builds that assemble-only, but the
        // worry is that gnarly things happen to artifacts constructed
        // that way that we might miss (e.g., evil mangler scripts whose
        // effects can't be mirrored on llvm assembly).
        //
        // For now, ignore them.  This could be guarded behind an
        // option.
        is_assemble_only = is_assemble_only || arg == "-S";
        is_pre_proc_only = is_pre_proc_only || arg == "-E";
        has_responsefile = has_responsefile || arg.to_str().unwrap().starts_with("@");
    }
    let should_make_bc = match cmd_path.file_name() {
        None => { false }
        Some(cmd_file_name) => {
            has_compile_only_flag &&
                !has_pipe_io && !is_assemble_only && !is_pre_proc_only &&
                clang_support::is_compile_command_name(cmd_file_name)
        }
    };

    if should_make_bc {
        // If this is a command we can build bitcode for, do
        // it.  We wait until the exec'd process exits
        // because we need the original object file to exist
        // (so that we can attach the bitcode).
        //
        // We drop the first argument because it is just the
        // original command name
        let (_, rest_args) = rc.args.split_at(1);
        match build_bitcode_compile_only(chan, clang_path, rest_args, &rc.cwd, bcout_path) {
            Err(err) => { println!("Error building bitcode: {:?}", err) }
            Ok(_) => {}
        }
    } else {
        // Bump a summary stat indicating a reason why this compile
        // could not attempt to generate bitcode.  Ignore
        // pre-processor-only invocations, since they don't generate
        // object code anyhow.
        if !is_pre_proc_only {
            if has_pipe_io {
                // Ignore send failures... that really shouldn't happen and
                // we don't want to kill the tracer thread.
                let _res = chan.send(Some(Event::PipeInputOrOutput(rc.clone())));
            }
            if has_responsefile {
                let _res = chan.send(Some(Event::ResponseFile(rc.clone())));
            }

            if is_assemble_only {
                let _res = chan.send(Some(Event::SkippingAssembleOnlyCommand(rc)));
            }
        }
    }
}


fn generate_bitcode(chan : &mut mpsc::Sender<Option<Event>>,
                    mut ptracer : pete::Ptracer,
                    clang_path : &OsStr,
                    bcout_path : std::option::Option<&PathBuf>
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
                handle_process_exit(chan, tracee.pid, exit_code, &mut process_state, clang_path, bcout_path);
            }
            _ => {}
        }

        ptracer.restart(tracee, pete::Restart::Syscall)?;
    }

    Ok((ptracer, last_exitcode))
}

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
