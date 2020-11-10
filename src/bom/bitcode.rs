use std::collections::HashMap;
use std::path::{Path,PathBuf};
use std::process::Command;
use std::ffi::OsString;

use slab_tree::{NodeMut,NodeRef};
use slab_tree::tree::{Tree,TreeBuilder};

use crate::bom::options::{BitcodeOptions,StringNormalizeStrategy,Normalization};
use crate::bom::loader::{SomeLoadedTrace,load_trace};
use crate::bom::normalize::normalize;
use crate::bom::event::{EventType,TraceEvent};

#[derive(thiserror::Error,Debug)]
pub enum DependencyAnalysisError {
    #[error("Missing TraceEvent for root task {0:?}")]
    MissingRoot(i32),
    #[error("Missing TraceEvent for non-root task {0:?}")]
    MissingNode(i32)
}

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

#[derive(Debug)]
struct Task {
    task_id : i32,
    task_events : Vec<TraceEvent<EventType>>
}

fn build_task_tree(root_task_id : i32, event_groups : &HashMap<i32,Vec<TraceEvent<EventType>>>) -> anyhow::Result<Tree<Task>> {
    let root_events = event_groups.get(&root_task_id).ok_or(DependencyAnalysisError::MissingRoot(root_task_id))?;
    let root_task = Task { task_id : root_task_id, task_events : root_events.clone() };
    let mut tree = TreeBuilder::new().with_root(root_task).build();
    let root_id = tree.root_id().expect("Missing root");
    let mut root_node = tree.get_mut(root_id).unwrap();
    build_node(&mut root_node, event_groups)?;
    Ok(tree)
}

/// For each fork event for the task, create child nodes and populate them
fn build_node(node : &mut NodeMut<Task>, event_groups : &HashMap<i32,Vec<TraceEvent<EventType>>>) -> anyhow::Result<()> {
    let task_event_trace = &node.data().task_events.clone();
    for evt in task_event_trace {
        match evt.evt {
            EventType::Fork { new_pid, .. } => {
                let events = event_groups.get(&new_pid).ok_or(DependencyAnalysisError::MissingNode(new_pid))?;
                let task = Task { task_id : new_pid, task_events : events.clone() };
                let mut this_node = node.append(task);
                build_node(&mut this_node, event_groups)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn is_terminal_command( command : &str) -> bool {
    command == "/usr/bin/gcc" || command == "/bin/sh"
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
fn replay_build(bitcode_options : &BitcodeOptions, n : NodeRef<Task>) {
    let mut is_terminal = false;
    for evt in &n.data().task_events {
        match &evt.evt {
            EventType::Exec { command, args, cwd, .. } => {
                is_terminal = is_terminal_command(command) || is_terminal;

                let (_, rest_args) = args.split_at(1);
                println!("{} {:?} @ {:?}", command, rest_args, cwd);
                match Command::new(command).args(rest_args).current_dir(cwd).spawn() {
                    Err(msg) => { println!("Error while spawning command '{:?}': {}", command, msg) }
                    Ok(mut child) => {
                        let _rc = child.wait();
                    }
                }
                build_bitcode(bitcode_options, command, rest_args, cwd);
            }
            _ => {}
        }
    }

    if !is_terminal {
        for c in n.children() {
            replay_build(bitcode_options, c);
        }
    }
}

/// Given a command, modify it to build bitcode (if possible)
///
/// We intercept the following commands:
///
/// - gcc -c (-> clang -emit-llvm -c)
///
/// TODO:
///
/// - g++ -c (-> clang++ -emit-llvm -c)
/// - ar (-> llvm-ar)
/// - ld (-> llvm-link)
/// - gcc (-> llvm-link)
/// - g++ (-> llvm-link)
fn build_bitcode(bitcode_options : &BitcodeOptions, command : &str, args : &[String], cwd : &PathBuf) {
    let mut is_compile_only = false;
    for arg in args {
        if arg == "-c" {
            is_compile_only = true;
        }
    }

    let cmd_path = Path::new(command);
    match cmd_path.file_name() {
        None => { return; }
        Some(cmd_file_name) => {
            if !(cmd_file_name == "gcc" && is_compile_only) {
                return;
            }
        }
    }

    let mut modified_args = Vec::new() as Vec<OsString>;
    modified_args.push(OsString::from("-emit-llvm"));
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        modified_args.push(OsString::from(arg.to_owned()));
        if arg == "-o" {
            match it.next() {
                None => {
                    println!("No output file in command '{} {:?}'", command, args);
                    return;
                }
                Some(target) => {
                    let mut target_path = PathBuf::from(&target);
                    target_path.set_extension("bc");
                    modified_args.push(target_path.into_os_string());
                }
            }
        }
    }

    let mut bc_command = OsString::from("clang");
    match &bitcode_options.clang_path {
        None => {}
        Some(alt) => {
            bc_command = OsString::from(alt);
        }
    }

    match Command::new(&bc_command).args(&modified_args).current_dir(cwd).spawn() {
        Err(msg) => { println!("Error while spawning command '{:?} {:?}': {}", &bc_command, &modified_args, msg) }
        Ok(mut child) => {
            let _rc = child.wait();
        }
    }
}

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
        // Iterate over all of the children of the root.  We skip the root
        // because it is the invocation of the build command (which we are
        // emulating and would rather not run again).
        let root = t.root().unwrap();
        for c in root.children() {
            replay_build(bitcode_options, c);
        }
    }

    Ok(())
}

