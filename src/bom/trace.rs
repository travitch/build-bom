use log::{error, warn};
use std::collections::{HashMap,BTreeMap};
use std::io::Write;
use std::ffi::OsString;
use std::thread;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json;
use rmp_serde;
use os_pipe::{pipe,PipeReader,PipeWriter};
use core::borrow::Borrow;
use pete::{Ptracer, Restart, Stop, Tracee};

use crate::bom::event::{RawEventType,TraceEvent,EnvID,Environment};
use crate::bom::syscalls::{load_syscalls};
use crate::bom::options::{TraceOptions};
use crate::bom::versioning::{Header,DataFormat,CURRENT_VERSION};
use crate::bom::proc_read::{read_str_from,read_str_list_from,read_cwd,read_environment};

pub fn trace_entrypoint(trace_opts : &TraceOptions) -> anyhow::Result<()> {
    let syscalls = load_syscalls();
    let (reader, mut writer) = pipe().unwrap();
    let thread_opts = trace_opts.output.clone();
    let (cmd, args) = trace_opts.command.split_at(1);
    let cmd_path = which::which(OsString::from(&cmd[0]))?;
    let mut cmd = Command::new(cmd_path);
    cmd.args(args);

    let mut ptracer = Ptracer::new();

    // Tracee is in pre-exec ptrace-stop.
    let _child = ptracer.spawn(cmd);
    match ptracer.wait()? {
        None => {
            error!("Error spawning tracee (command: {})", trace_opts.command.join(" "));
        }
        Some(tracee1) => {
            let root_pid = tracee1.pid;
            let event_reader = thread::spawn(move || { record_events(thread_opts, reader, root_pid.as_raw()) });
            ptracer.restart(tracee1, Restart::Syscall)?;
            let subprocess_writer = writer.try_clone()?;
            trace_events(syscalls, ptracer, subprocess_writer)?;
            // Once we are done processing all of the events from the tracee,
            // that means that it has completed (and so have all of its
            // children).
            //
            // We signal the serializer thread by writing a `None` to the stream
            let bytes = rmp_serde::encode::to_vec::<Option<TraceEvent<RawEventType<EnvID>>>>(&None)?;
            writer.write(bytes.as_slice())?;

            // Wait for the reader thread to finish
            let _res = event_reader.join();
        }
    }
    Ok(())
}

fn trace_events(syscalls : BTreeMap<u64, String>, mut ptracer : Ptracer, mut writer : PipeWriter) -> anyhow::Result<()> {
    while let Ok(Some(mut tracee)) = ptracer.wait() {
        let regs = tracee.registers()?;

        match tracee.stop {
            Stop::Fork { new: new_pid } => {
                let pid = tracee.pid.as_raw();
                write_event(&mut writer, &mut tracee, RawEventType::Fork { old_pid : pid, new_pid : new_pid.as_raw() })?;
            }
            Stop::Vfork { new: new_pid } => {
                let pid = tracee.pid.as_raw();
                write_event(&mut writer, &mut tracee, RawEventType::Fork { old_pid : pid, new_pid : new_pid.as_raw() })?;
            }
            Stop::Exiting { exit_code } => {
                let pid = tracee.pid.as_raw();
                write_event(&mut writer, &mut tracee, RawEventType::Exit { pid : pid, exit_code : exit_code })?;
            }
            Stop::SyscallEnter => {
                let rax = regs.orig_rax;
                let syscall = syscalls.get(&rax).unwrap();
                if syscall == "execve" {
                    let bin = read_str_from(&mut tracee, regs.rdi);
                    let args = read_str_list_from(&mut tracee, regs.rsi);
                    let env = read_environment(&tracee)?;
                    let cwd = read_cwd(&tracee)?;
                    write_event(&mut writer, &mut tracee, RawEventType::Exec { command : bin, args : args, environment : env, cwd : cwd })?;
                } else if syscall == "open" {
                    let path = read_str_from(&mut tracee, regs.rdi);
                    let flags = regs.rsi as u32;
                    let mode = regs.rdx as u32;
                    write_event(&mut writer, &mut tracee, RawEventType::OpenFile { path : path, flags : flags, mode : mode })?;
                } else if syscall == "openat" {
                    let at_fd = regs.rdi as i32;
                    let path = read_str_from(&mut tracee, regs.rsi);
                    let flags = regs.rdx as u32;
                    let mode = regs.r10 as u32;
                    write_event(&mut writer, &mut tracee, RawEventType::OpenFileAt { at_dir : at_fd, path : path, flags : flags, mode : mode })?;
                } else if syscall == "close" {
                    let fd = regs.rdi as i32;
                    write_event(&mut writer, &mut tracee, RawEventType::CloseFile { fd : fd })?;
                } else if syscall == "rename" {
                    let from = read_str_from(&mut tracee, regs.rdi);
                    let to = read_str_from(&mut tracee, regs.rsi);
                    write_event(&mut writer, &mut tracee, RawEventType::Rename { from : from, to : to })?;
                } else if syscall == "renameat" {
                    let from_fd = regs.rdi as i32;
                    let from = read_str_from(&mut tracee, regs.rsi);
                    let to_fd = regs.rdx as i32;
                    let to = read_str_from(&mut tracee, regs.r10);
                    write_event(&mut writer, &mut tracee, RawEventType::RenameAt { from_dir : from_fd, from : from, to_dir : to_fd, to : to })?;
                } else {
                    // debug!("{:>16x}: [{}], {:?}", pc, syscall, tracee.stop);
                };
            },
            Stop::SyscallExit => {
                // While we mostly don't care how system calls return, there
                // will be a few cases where we do:
                //
                // - Some tools try to exec variants of a program until one
                //   succeeds (we would like to know explicitly when exec fails,
                //   though we could figure it out if there are subsequent
                //   syscalls in that process, maybe)
                //
                // - Failures of e.g., chdir need to be noticed
                //
                // - We probably want to know when opens of read-only files fail
                let syscall_num = regs.orig_rax;
                match syscalls.get(&syscall_num) {
                    None => { }
                    Some(syscall) => {
                        let res = regs.rax as i32;
                        if syscall == "execve" && res != 0 {
                            write_event(&mut writer, &mut tracee, RawEventType::FailedExec { result : res })?;
                        } else if syscall == "open" {
                            write_event(&mut writer, &mut tracee, RawEventType::OpenFileReturn { result : res })?;
                        } else if syscall == "openat" {
                            write_event(&mut writer, &mut tracee, RawEventType::OpenFileReturn { result : res })?;
                        }
                    }
                }

            },
            _ => {
                // debug!("{:>16x}: {:?}", pc, tracee.stop);
            },
        }

        ptracer.restart(tracee, Restart::Syscall)?;
    }
    Ok(())
}

fn write_event(writer : &mut PipeWriter, tracee : &mut Tracee, evt : RawEventType<Vec<u8>>) -> anyhow::Result<()> {
    let te = Some(TraceEvent { pid : tracee.pid.as_raw(), evt : evt });
    let bytes = rmp_serde::encode::to_vec(&te)?;
    writer.write(bytes.as_slice())?;
    Ok(())
}


fn record_events(file_path : PathBuf, rdr : PipeReader, root_pid : i32) -> anyhow::Result<()> {
    let mut envs = HashMap::new();
    let mut f = fs::File::create(file_path.as_path())?;
    let header = Header { version : CURRENT_VERSION, data_format : DataFormat::Raw, root_task : root_pid };
    serde_json::to_writer(&f, &header)?;
    f.write("\n".as_bytes())?;

    // This is a plain `loop` instead of a for/iterator loop because we are
    // reading off of a (OS) pipe and have no idea how much data we will
    // receive.
    loop {
        match rmp_serde::decode::from_read::<_, Option<TraceEvent<RawEventType<Vec<u8>>>>>(rdr.borrow()) {
            Err(e) => { warn!("Error recording event: {}", e) }
            Ok(None) => { break; }
            Ok(Some(trace_event)) => {
                // If we get an exec with its full environment inlined, start
                // deduping environments in a local hash map (writing them out
                // as we encounter them for the first time)
                //
                // Write out a more compact Exec that only refers to an EnvID
                match trace_event.evt {
                    RawEventType::Exec { command, args, cwd, environment } => {
                        let env_id = match envs.get(&environment) {
                            Some(env_id) => { *env_id }
                            None => {
                                let env_id = EnvID(envs.len() as u32);
                                envs.insert(environment.clone(), env_id);
                                let env = Environment { id : env_id, bytes : environment };
                                serde_json::to_writer(&f, &env)?;
                                f.write("\n".as_bytes())?;
                                env_id
                            }
                        };

                        let ex = RawEventType::Exec { command : command, args : args, cwd : cwd, environment : env_id };
                        let trace_event1 = TraceEvent { pid : trace_event.pid, evt : ex };
                        serde_json::to_writer(&f, &trace_event1)?;
                        f.write("\n".as_bytes())?;
                    }
                    _ => {
                        serde_json::to_writer(&f, &trace_event)?;
                        f.write("\n".as_bytes())?;
                    }
                }
            }
        }
    }
    Ok(())
}
