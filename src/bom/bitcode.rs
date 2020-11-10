use std::collections::HashMap;
use std::path::{Path,PathBuf};
use std::process::Command;

use crate::bom::options::{BitcodeOptions,StringNormalizeStrategy,Normalization};
use crate::bom::loader::{SomeLoadedTrace,load_trace};
use crate::bom::normalize::normalize;
use crate::bom::event::{EventType,TraceEvent};

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

pub fn bitcode_entrypoint(bitcode_options : &BitcodeOptions) -> anyhow::Result<()> {
    let loaded_trace = load_trace(&bitcode_options.input)?;
    // Handle either raw events (normalize them first) or pre-normalized events (that have to be grouped)
    let (_env, event_groups) = match loaded_trace {
        SomeLoadedTrace::RawTrace(raw_trace) => {
            let mut normalizations = Vec::new();
            normalizations.push(Normalization::ElideClose);
            normalizations.push(Normalization::ElideFailedOpen);
            normalizations.push(Normalization::ElideFailedExec);
            let events = normalize(&StringNormalizeStrategy::Strict, &normalizations, raw_trace.events.as_slice())?;
            (raw_trace.environments, events)
        }
        SomeLoadedTrace::NormalizedTrace(loaded_trace) => {
            let groups = group_events(loaded_trace.events);
            (loaded_trace.environments, groups)
        }
    };

    for (_task_id, events) in event_groups {
        for event in events {
            match event.evt {
                EventType::Exec { command, args, cwd, .. } => {
                    let path = Path::new(&command);
                    let filename = path.file_name().unwrap().to_str().unwrap().to_string();
                    if filename == "gcc" || filename == "g++" {
                        compile_bitcode(&bitcode_options, &filename, args.as_slice(), cwd.as_path());
                        println!("Compile Command: {:?} from {:?}", args, cwd);
                    } else if filename == "ld" {
                        println!("Link Command: {:?} from {:?}", args, cwd);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn compile_bitcode(bitcode_options : &BitcodeOptions, command_filename : &String, args : &[String], cwd : &Path) {
    let mut is_compile_only = false;
    for arg in args {
        if arg == "-c" {
            is_compile_only = true;
            break;
        }
    }
    if !is_compile_only {
        return;
    }

    let mut modified_args = Vec::new();
    let mut it = args.iter();
    // We discard the first argument because it repeats the command name
    let _discard = it.next();

    while let Some(arg) = it.next() {
        if arg == "-o" {
            modified_args.push(arg.clone());
            match it.next() {
                None => {
                    println!("No output file in command '{:?}'", command_filename);
                    return
                }
                Some(target) => {
                    let mut target_path = PathBuf::from(&target);
                    target_path.set_extension("bc");
                    // FIXME: The unwrap could fail, handle it gracefully
                    modified_args.push(target_path.to_str().unwrap().to_string())
                }
            }
        } else {
            modified_args.push(arg.clone());
        }
    }

    modified_args.push("-emit-llvm".to_string());

    let bc_command = if command_filename == "gcc" {
        let default_clang = PathBuf::from("clang");
        bitcode_options.clang_path.as_ref().unwrap_or(&default_clang).to_str().unwrap().to_string()
    } else if command_filename == "g++" {
        // FIXME: This isn't quite right...
        let default_clang = PathBuf::from("clang++");
        bitcode_options.clang_path.as_ref().unwrap_or(&default_clang).to_str().unwrap().to_string()
    } else {
        unreachable!()
    };

    match Command::new(bc_command).args(modified_args).current_dir(cwd).spawn() {
        Err(msg) => { println!("Error while spawning command '{:?}': {}", command_filename, msg) }
        Ok(mut child) => {
            let _rc = child.wait();
        }
    }
}
