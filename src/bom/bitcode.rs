use std::collections::HashMap;
use std::path::{Path,PathBuf};
use std::io::Read;
use std::process::Command;
use std::ffi::{OsStr,OsString};

use sha2::{Digest,Sha256};
use slab_tree::NodeRef;

use crate::bom::options::{BitcodeOptions,StringNormalizeStrategy,Normalization};
use crate::bom::loader::{SomeLoadedTrace,load_trace};
use crate::bom::normalize::normalize;
use crate::bom::event::{EventType,TraceEvent};
use crate::bom::deptree::{Task,build_task_tree};

fn group_events<E>(events : Vec<TraceEvent<E>>) -> HashMap<i32,Vec<TraceEvent<E>>> {
    let mut groups = HashMap::new();
    for evt in events {
        match groups.get(&evt.pid) {
            Some(_) => {}
            None => { groups.insert(evt.pid, Vec::new()); }
        }
        let task_vec = groups.get_mut(&evt.pid).unwrap();
        task_vec.push(evt);
    }

    groups
}

fn is_terminal_command( command : &str) -> bool {
    let cmd_path = Path::new(command);
    match cmd_path.file_name() {
        None => { true }
        Some(cmd_file_name) => {
            cmd_file_name == "gcc" ||
                cmd_file_name == "g++" ||
                cmd_file_name == "clang" ||
                cmd_file_name == "clang++" ||
                cmd_file_name == "ar" ||
                command == "/bin/sh"
        }
    }
}

fn debug_tree(n : NodeRef<Task>, level : i32, verbose : bool) {
    let mut is_terminal = false;
    for evt in &n.data().task_events {
        // If there is an exec, print it
        match &evt.evt {
            EventType::Exec { command, args, cwd, .. } => {
                is_terminal = is_terminal_command(command) || is_terminal;
                // Don't run the root command
                if level != 0 {
                    if verbose {
                        println!("{}{} {:?} @ {:?}", " ".repeat((level * 4) as usize), command, args, cwd);
                    } else {
                        println!("{}{}", " ".repeat((level * 4) as usize), command);
                    }
                }
            }
            _ => {}
        }
    }

    if !is_terminal {
        // Traverse children with a deeper level
        for c in n.children() {
            debug_tree(c, level + 1, verbose);
        }
    }
}

/// Replay a build exactly, invoking "shadow" commands to build bitcode where necessary
fn replay_build(bitcode_options : &BitcodeOptions, ft : &mut FileTracker, n : NodeRef<Task>) {
    let mut is_terminal = false;
    for evt in &n.data().task_events {
        match &evt.evt {
            EventType::Exec { command, args, cwd, .. } => {
                is_terminal = is_terminal_command(command) || is_terminal;

                let cmd_path = Path::new(command);
                match cmd_path.file_name() {
                    None => {
                        // Can't exec something with no command...
                    }
                    Some(cmd_file_name) => {
                        // We run the command as long as it is not a recursive make invocation
                        //
                        // We already have the commands that make will invoke,
                        // so there is no need to re-run make.
                        //
                        // FIXME: More generally: we want to skip re-running any build systems
                        if cmd_file_name != "make" && cmd_file_name != "gmake" {
                            let (_, rest_args) = args.split_at(1);
                            println!("{} {:?} @ {:?}", command, rest_args, cwd);
                            match Command::new(command).args(rest_args).current_dir(cwd).spawn() {
                                Err(msg) => { println!("Error while spawning command '{:?}': {}", command, msg) }
                                Ok(mut child) => {
                                    let _rc = child.wait();
                                }
                            }
                            match build_bitcode(bitcode_options, ft, command, rest_args, cwd.as_path()) {
                                Ok(_) => {}
                                Err(msg) => {
                                    println!("Error building bitcode: {:?}", msg);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if !is_terminal {
        for c in n.children() {
            replay_build(bitcode_options, ft, c);
        }
    }
}

/// Given a command, modify it to build bitcode (if possible)
///
/// NOTE: this function expects that argv[0] (the program name in the original
/// exec call) has been stripped off.
///
/// We intercept the following commands:
///
/// - gcc -c (-> clang -emit-llvm -c)
/// - g++ -c (-> clang++ -emit-llvm -c)
/// - ar (-> llvm-ar)
///
/// TODO:
///
/// - ld (-> llvm-link)
/// - gcc (-> llvm-link)
/// - g++ (-> llvm-link)
/// - as (-> llvm-as)
fn build_bitcode(bitcode_options : &BitcodeOptions, ft : &mut FileTracker, command : &str, args : &[String], cwd : &Path) -> anyhow::Result<()> {
    let mut is_compile_only = false;
    for arg in args {
        if arg == "-c" {
            is_compile_only = true;
        }
    }

    let cmd_path = Path::new(command);
    match cmd_path.file_name() {
        None => {
            // This should probably be impossible (or it was a broken exec of a directory)
            //
            // No reason to panic...
            Ok(())
        }
        Some(cmd_file_name) => {
            if (cmd_file_name == "gcc" || cmd_file_name == "g++" || cmd_file_name == "clang" || cmd_file_name == "clang++") && is_compile_only {
                let mut bc_command = OsString::from("clang");
                match &bitcode_options.clang_path {
                    None => {}
                    Some(alt) => {
                        bc_command = OsString::from(alt);
                    }
                }
                if cmd_file_name == "g++" || cmd_file_name == "clang++" {
                    bc_command.push("++")
                }
                build_bitcode_compile_only(ft, &bc_command, args, cwd)?;
            } else if cmd_file_name == "ar" {
                let mut ar_command = OsString::from("llvm-ar");
                match &bitcode_options.llvm_tool_suffix {
                    None => {}
                    Some(suffix) => {
                        ar_command.push(suffix);
                    }
                }
                build_bitcode_archive(ft, &ar_command, args, cwd);
            }
            Ok(())
        }
    }
}

fn build_bitcode_archive(ft : &mut FileTracker, ar_command : &OsStr, args : &[String], cwd : &Path) {
    // /usr/bin/ar ["rc", "libz.a", "adler32.o", "crc32.o",
    let mut modified_args = Vec::new() as Vec<OsString>;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let p = Path::new(arg);
        if is_archive(p) {
            let mut pb = p.to_path_buf();
            pb.set_extension("bca");
            modified_args.push(OsString::from(pb.clone()));
            add_file_mapping(ft, OsString::from(p.clone()), OsString::from(pb.clone()));
        } else if is_object(p) {
            match get_file_mapping(ft, p.as_os_str()) {
                None => {
                    println!("No object mapping for file {:?}", p);
                    modified_args.push(OsString::from(p));
                }
                Some(bc_file) => {
                    modified_args.push(OsString::from(bc_file));
                }
            }
        } else {
            modified_args.push(OsString::from(arg));
        }
    }

    match Command::new(&ar_command).args(&modified_args).current_dir(cwd).spawn() {
        Err(msg) => {
            println!("Error while spawning command '{:?} {:?}' : {}", &ar_command, &modified_args, msg);
            return;
        }
        Ok(mut child) => {
            let _rc = child.wait();
        }
    }
}

fn is_archive(p : &Path) -> bool {
    p.extension().map_or(false, |e| e == "a")
}

fn is_object(p : &Path) -> bool {
    p.extension().map_or(false, |e| e == "o")
}

fn build_bitcode_compile_only(ft : &mut FileTracker, bc_command : &OsStr, args : &[String], cwd : &Path) -> anyhow::Result<()> {
    let mut orig_target = OsString::from("");
    let mut new_target = OsString::from("");
    let mut modified_args = Vec::new() as Vec<OsString>;
    modified_args.push(OsString::from("-emit-llvm"));
    let mut it = args.iter();
    while let Some(arg) = it.next() {
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
            add_file_mapping(ft, orig_target, new_target);
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
    MissingOutputFile(PathBuf, Vec<String>),
    #[error("Error generating bitcode with command {0:?} {1:?} ({2:?})")]
    ErrorGeneratingBitcode(PathBuf, Vec<OsString>, std::io::Error)
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
    let bc_path = Path::new(bc_target);
    let mut archived_name = OsString::new();
    archived_name.push(bc_path.file_stem().unwrap());
    archived_name.push("-");
    archived_name.push(hex::encode(hash));
    archived_name.push(".");
    archived_name.push(bc_path.extension().unwrap());

    tb.append_path_with_name(bc_path, &archived_name)?;
    tb.into_inner()?;


    let mut objcopy_args = Vec::new();
    objcopy_args.push(OsString::from("--add-section"));
    let ok_tar_name = tar_name.into_string().ok().unwrap();
    objcopy_args.push(OsString::from(format!("{}={}", ELF_SECTION_NAME, ok_tar_name)));
    objcopy_args.push(object_path.into_os_string());

    match Command::new("objcopy").args(&objcopy_args).spawn() {
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
    let loaded_trace = load_trace(&bitcode_options.input)?;
    // Handle either raw events (normalize them first) or pre-normalized events (that have to be grouped)
    let (root_task, event_groups) = match loaded_trace {
        SomeLoadedTrace::RawTrace(raw_trace) => {
            let mut normalizations = Vec::new();
            normalizations.push(Normalization::ElideClose);
            normalizations.push(Normalization::ElideFailedOpen);
            normalizations.push(Normalization::ElideFailedExec);
            let events = normalize(&StringNormalizeStrategy::Strict, &normalizations, raw_trace.events.as_slice())?;
            (raw_trace.root_task, events)
        }
        SomeLoadedTrace::NormalizedTrace(loaded_trace) => {
            let groups = group_events(loaded_trace.events);
            (loaded_trace.root_task, groups)
        }
    };

    let t = build_task_tree(root_task, &event_groups)?;
    if bitcode_options.dry_run {
        debug_tree(t.root().unwrap(), 0, bitcode_options.verbose);
    } else {
        let mut ft = new();
        // Iterate over all of the children of the root.  We skip the root
        // because it is the invocation of the build command (which we are
        // emulating and would rather not run again).
        let root = t.root().unwrap();
        for c in root.children() {
            replay_build(bitcode_options, &mut ft, c);
        }
    }

    Ok(())
}

/// A data structure for tracking the bitcode files generated (and the files
/// that they map to in the original build)
struct FileTracker {
    bitcode : HashMap<OsString,OsString>
}

fn new() -> FileTracker {
    let hm = HashMap::new();
    FileTracker { bitcode : hm }
}

fn add_file_mapping(ft : &mut FileTracker, orig_file : OsString, new_file : OsString) {
    ft.bitcode.insert(orig_file, new_file);
}

fn get_file_mapping<'a>(ft : &'a FileTracker, orig_file : &OsStr) -> Option<&'a OsString>{
    ft.bitcode.get(orig_file)
}
