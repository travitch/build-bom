use std::collections::HashMap;
use std::path::{Path,PathBuf};
use std::io::Read;
use std::process::Command;
use std::ffi::{OsStr,OsString};
use std::os::unix::ffi::OsStringExt;

use sha2::{Digest,Sha256};

use crate::bom::options::{BitcodeOptions};
use crate::bom::syscalls::load_syscalls;
use crate::bom::event::RawString;
use crate::bom::proc_read::{read_str_from,read_str_list_from,read_environment,read_cwd};

static COMPILE_COMMANDS: &'static [&str] =
    &[r"gcc",
      r"g\+\+",
      r"cc",
      r"c\+\+",
      r"clang",
      r"clang\+\+",
      r"gcc-\d+(\.\d+)",
      r"g\+\+-\d+(\.\d+)"
    ];

lazy_static::lazy_static! {
    static ref COMPILE_COMMAND_RE : regex::RegexSet = regex::RegexSet::new(COMPILE_COMMANDS).unwrap();
}

fn is_compile_command_name(cmd_name : &OsStr) -> bool {
    match cmd_name.to_str() {
        None => { false }
        Some(s) => { COMPILE_COMMAND_RE.is_match(s) }
    }
}

static CLANG_ARGUMENT_BLACKLIST : &'static [&str] =
    &[r"-fno-tree-loop-im",
      r"-Wmaybe-uninitialized",
      r"-Wno-maybe-uninitialized",
      r"-mindirect-branch-register",
      r"-mindirect-branch=.*",
      r"-mpreferred-stack-boundary=\d+",
      r"-Wframe-address",
      r"-Wno-frame-address",
      r"-Wno-format-truncation",
      r"-Wno-format-overflow",
      r"-Wformat-overflow",
      r"-Wformat-truncation",
      r"-Wpacked-not-aligned",
      r"-Wno-packed-not-aligned",
      r"-Werror=.*",
      r"-Wno-restrict",
      r"-Wrestrict",
      r"-Wno-unused-but-set-variable",
      r"-Wunused-but-set-variable",
      r"-Wno-stringop-truncation",
      r"-Wno-stringop-overflow",
      r"-Wstringop-truncation",
      r"-Wstringop-overflow",
      r"-Wzero-length-bounds",
      r"-Wno-zero-length-bounds",
      r"-fno-allow-store-data-races",
      r"-fno-var-tracking-assignments",
      r"-fmerge-constants",
      r"-fconserve-stack",
      r"-falign-jumps=\d+",
      r"-falign-loops=\d+",
      r"-mno-fp-ret-in-387",
      r"-mskip-rax-setup",
      r"--param=.*"
      ];

lazy_static::lazy_static! {
    static ref CLANG_ARGUMENT_BLACKLIST_RE : regex::RegexSet = regex::RegexSet::new(CLANG_ARGUMENT_BLACKLIST).unwrap();
}

fn build_bitcode_compile_only(bc_command : &OsStr, args : &[OsString], cwd : &Path) -> anyhow::Result<()> {
    let mut orig_target = OsString::from("");
    let mut new_target = OsString::from("");
    let mut modified_args = Vec::new() as Vec<OsString>;
    modified_args.push(OsString::from("-emit-llvm"));
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        // Skip any argument on the clang argument blacklist
        match arg.to_str() {
            None => { }
            Some(str_arg) => {
                if CLANG_ARGUMENT_BLACKLIST_RE.is_match(str_arg) {
                    continue;
                }
            }
        }

        modified_args.push(OsString::from(arg.to_owned()));
        if arg == "-o" {
            match it.next() {
                None => {
                    return Err(anyhow::Error::new(BitcodeError::MissingOutputFile(Path::new(bc_command).to_path_buf(), Vec::from(args))));
                }
                Some(target) => {
                    orig_target = PathBuf::from(&target).into_os_string();
                    let mut target_path = PathBuf::from(&target);
                    target_path.set_extension("bc");
                    new_target = OsString::from(target_path.clone());
                    modified_args.push(target_path.into_os_string());
                }
            }
        }
    }

    match Command::new(&bc_command).args(&modified_args).current_dir(cwd).spawn() {
        Err(msg) => {
            Err(anyhow::Error::new(BitcodeError::ErrorGeneratingBitcode(Path::new(bc_command).to_path_buf(), Vec::from(modified_args), msg)))
        }
        Ok(mut child) => {
            let _rc = child.wait();
            attach_bitcode(cwd, &orig_target, &new_target)?;
            Ok(())
        }
    }
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

#[derive(thiserror::Error,Debug)]
pub enum BitcodeError {
    #[error("Error attaching bitcode file '{2:?}' to '{1:?}' in {0:?} ({3:?})")]
    ErrorAttachingBitcode(PathBuf, OsString, OsString, std::io::Error),
    #[error("Missing output file in command {0:?} {1:?}")]
    MissingOutputFile(PathBuf, Vec<OsString>),
    #[error("Error generating bitcode with command {0:?} {1:?} ({2:?})")]
    ErrorGeneratingBitcode(PathBuf, Vec<OsString>, std::io::Error),
    #[error("Unreadable memory address {0:}")]
    UnreadableMemoryAddress(u64)
}

/// Attach the bitcode file at the given path to its associated object file target
///
/// We pass in the working directory in which the objects were constructed so
/// that we can generate appropriate commands (in terms of absolute paths) so
/// that we don't need to worry about where we are replaying the build from.
fn attach_bitcode(cwd : &Path, orig_target : &OsString, bc_target : &OsString) -> anyhow::Result<()> {
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
    match Command::new("objcopy").args(&objcopy_args).current_dir(cwd).spawn() {
        Err(msg) => {
            return Err(anyhow::Error::new(BitcodeError::ErrorAttachingBitcode(cwd.to_path_buf(), orig_target.clone(), bc_target.clone(), msg)));
        }
        Ok(mut child) => {
            let _rc = child.wait();
            Ok(())
        }
    }
}

pub const ELF_SECTION_NAME : &str = ".llvm_bitcode";

pub fn bitcode_entrypoint(bitcode_options : &BitcodeOptions) -> anyhow::Result<()> {
    let (cmd0, args0) = bitcode_options.command.split_at(1);
    let cmd_path = which::which(OsString::from(&cmd0[0]))?;
    let mut resolved_command = Vec::new();
    resolved_command.push(String::from(cmd_path.to_str().unwrap()));
    for a in args0 {
        resolved_command.push(String::from(a));
    }
    let cmd = pete::Command::new(resolved_command)?;
    let mut ptracer = pete::Ptracer::new();
    let tracee = ptracer.spawn(cmd)?;
    ptracer.restart(tracee, pete::Restart::Syscall)?;

    generate_bitcode(ptracer)?;

    Ok(())
}

#[derive(Debug)]
struct RunCommand {
    bin : OsString,
    args : Vec<OsString>,
    env : Vec<u8>,
    cwd : PathBuf
}

enum ProcessState {
    TryExec(RunCommand),
    FinishExec(RunCommand)
}

fn generate_bitcode(mut ptracer : pete::Ptracer) -> anyhow::Result<()> {
    let mut process_state = HashMap::new();
    let syscalls = load_syscalls();
    // We want to observe execve syscalls. After a process (successfully) execs
    // a command we care about, we want to record that PID (along with the
    // arguments) and then, when that PID Exits, we want to generate bitcode and
    // attach it to the original object file result.
    while let Ok(Some(mut tracee)) = ptracer.wait() {
        let regs = tracee.registers()?;
        match tracee.stop {
            pete::Stop::SyscallEnterStop(pid) => {
                let rax = regs.orig_rax;
                let syscall = syscalls.get(&rax).unwrap();
                if syscall == "execve" {
                    let bin = read_str_from(&mut tracee, regs.rdi);
                    let args = read_str_list_from(&mut tracee, regs.rsi);
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
                            process_state.insert(pid.as_raw() as i32, ProcessState::TryExec(cmd));
                        }
                    }
                }
            }
            pete::Stop::SyscallExitStop(pid) => {
                let syscall_num = regs.orig_rax;
                match syscalls.get(&syscall_num) {
                    None => {}
                    Some(syscall) => {
                        let res = regs.rax as i32;
                        if syscall == "execve" {
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
                    }
                }
            }
            pete::Stop::Exiting(pid, exit_code) => {
                let ipid = pid.as_raw() as i32;
                match process_state.remove(&ipid) {
                    None => {
                        // We weren't tracking this process
                    }
                    Some(ProcessState::TryExec(_)) => {
                        // The process tried to exec some command but never succeeded
                    }
                    Some(ProcessState::FinishExec(rc)) => {
                        // The process successfully execed - see if we want to do anything with it
                        let cmd_path = Path::new(&rc.bin);
                        let mut has_compile_only_flag = false;
                        let mut has_pipe_io = false;
                        for arg in &rc.args {
                            has_compile_only_flag = has_compile_only_flag || arg == "-c";
                            // We want to recognize cases where the compilation
                            // input is stdin or the output is stdout; we can't
                            // replicate those build steps since we don't know
                            // where either is really going to/coming from.
                            //
                            // FIXME: collect metrics on this
                            has_pipe_io = has_pipe_io || arg == "-";
                        }
                        let should_make_bc = match cmd_path.file_name() {
                            None => { false }
                            Some(cmd_file_name) => {
                                is_compile_command_name(cmd_file_name) && has_compile_only_flag && !has_pipe_io
                            }
                        };

                        if should_make_bc {
                            // If this is a command we can build bitcode for, do
                            // it.  We wait until the execed process exits
                            // because we need the original object file to exist
                            // (so that we can attach the bitcode).
                            //
                            // NOTE: We could also check the exit_code and just
                            // not do anything if it is non-zero.
                            let bc_command = OsString::from("clang");
                            // We drop the first argument because it is just the
                            // original command name
                            let (_, rest_args) = rc.args.split_at(1);
                            match build_bitcode_compile_only(&bc_command, rest_args, &rc.cwd) {
                                Err(err) => { println!("Error building bitcode: {:?}", err) }
                                Ok(_) => {}
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        ptracer.restart(tracee, pete::Restart::Syscall)?;
    }

    Ok(())
}

fn decode_raw_string(rs : &RawString) -> anyhow::Result<OsString> {
    match rs {
        RawString::SafeString(s) => { Ok(OsString::from(s)) }
        RawString::BinaryString(bytes) => { Ok(OsStringExt::from_vec(bytes.clone())) }
        RawString::UnreadableMemoryAddress(addr) => { Err(anyhow::Error::new(BitcodeError::UnreadableMemoryAddress(*addr))) }
    }
}

fn make_command(bin : &RawString, args : &[RawString], env : anyhow::Result<Vec<u8>>, cwd : anyhow::Result<PathBuf>) -> anyhow::Result<RunCommand> {
    let mut os_args = Vec::new();
    for arg in args {
        os_args.push(decode_raw_string(arg)?);
    }

    let cmd = RunCommand { bin : decode_raw_string(bin)?, args : os_args, env : env?, cwd : cwd? };
    Ok(cmd)
}
